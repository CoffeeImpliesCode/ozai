//! A client and a server connection wired back to back through a simulated
//! link, so loss recovery can be tested deterministically and without real
//! time passing.
//!
//! The clock lives in this file. Every entry point below takes the instant
//! and the entropy to use, and nothing underneath reads either from anywhere
//! else, so `now` is advanced by hand and the same run happens every time.
//! That is stronger than the global test clock this replaced: one harness can
//! no longer move another one's `now`, and the instant every packet was
//! stamped with is visible here rather than somewhere nobody can read it.

const std = @import("std");
const address = @import("../address.zig");
const testing = std.testing;
const connection = @import("connection.zig");
const connection_manager = @import("connection_manager.zig");
const tls13 = @import("tls13.zig");
const mtu = @import("mtu.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const MAX_DGRAM = 1500;

/// Where virtual time starts. A second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
const test_now: i64 = 1_000 * std.time.ns_per_s;

/// Seeded entropy, so a run draws the same connection IDs and the same reset
/// bytes every time. `std.Random` is an interface over a pointer to its
/// engine, so the engine has to outlive every value handed out from it:
/// keep the `entropy` next to the `random`, never one without the other.
const TestRandom = std.Random.DefaultPrng;

const Datagram = struct {
    arrive: i64,
    len: usize,
    bytes: [MAX_DGRAM]u8,
};

/// One direction of the link: fixed delay, and a drop decision per datagram.
const Link = struct {
    queue: std.ArrayList(Datagram) = .empty,
    head: usize = 0,
    delay_ns: i64,
    sent: u64 = 0,
    dropped: u64 = 0,
    loss: Loss,

    const Loss = union(enum) {
        none,
        /// Drop `burst` consecutive datagrams out of every `period`.
        periodic: struct { period: u64, burst: u64, phase: u64 = 0 },
        /// Gilbert-Elliott: enter a loss burst with `p_enter`, leave with
        /// `p_leave`; every datagram inside a burst is dropped.
        bursty: struct { prng: std.Random.DefaultPrng, p_enter: f64, p_leave: f64, in_burst: bool = false },
    };

    fn deinit(self: *Link) void {
        self.queue.deinit(testing.allocator);
    }

    fn drops(self: *Link) bool {
        const n = self.sent;
        self.sent += 1;
        return switch (self.loss) {
            .none => false,
            .periodic => |p| (n + p.phase) % p.period < p.burst,
            .bursty => |*b| blk: {
                const r = b.prng.random().float(f64);
                if (b.in_burst) {
                    if (r < b.p_leave) b.in_burst = false;
                } else if (r < b.p_enter) b.in_burst = true;
                break :blk b.in_burst;
            },
        };
    }

    fn push(self: *Link, now: i64, bytes: []const u8) !void {
        if (self.drops()) {
            self.dropped += 1;
            return;
        }
        std.debug.assert(self.head <= self.queue.items.len);
        // Compact only after consuming at least as much as the live tail.
        if (self.head > 0 and self.head >= self.queue.items.len - self.head) {
            const live = self.queue.items.len - self.head;
            std.mem.copyForwards(
                Datagram,
                self.queue.items[0..live],
                self.queue.items[self.head..],
            );
            self.queue.items.len = live;
            self.head = 0;
        }
        var d: Datagram = .{ .arrive = now + self.delay_ns, .len = bytes.len, .bytes = undefined };
        @memcpy(d.bytes[0..bytes.len], bytes);
        try self.queue.append(testing.allocator, d);
    }

    /// The borrowed datagram remains valid until the next push on this link.
    fn popDue(self: *Link, now: i64) ?*Datagram {
        std.debug.assert(self.head <= self.queue.items.len);
        if (self.head == self.queue.items.len) return null;
        const datagram = &self.queue.items[self.head];
        if (datagram.arrive > now) return null;
        // Reclaim on push, not here: clearing the list poisons this borrow.
        self.head += 1;
        return datagram;
    }

    fn nextArrival(self: *const Link) ?i64 {
        std.debug.assert(self.head <= self.queue.items.len);
        return if (self.head < self.queue.items.len)
            self.queue.items[self.head].arrive
        else
            null;
    }
};

/// Loopback on `port`. Both ends of the link are reached on it, so the port is
/// the only thing that tells the two apart — which is what makes the port part
/// of a path rather than decoration the harness happens to vary.
fn addr(port: u16) address.Address {
    return address.Address.initIpv4(.{ 127, 0, 0, 1 }, port);
}

/// The server's Ed25519 seed. Fixed, so the node id it owns — and so every
/// handshake — is identical on every run. `generateDeterministic` fails only
/// on a degenerate seed, which a constant byte pattern is not.
const server_seed: [32]u8 = @splat(0x53);

/// The server's TLS configuration. A peer presents a bare 44-byte Ed25519
/// `SubjectPublicKeyInfo` and that is its whole certificate — there is no chain
/// left to walk — so the server hands out the SPKI wrapping its seed's node id
/// and the seed behind it.
///
/// Both live in statics rather than in a local. The config borrows them, and a
/// chain wired over a local points at a frame that is gone before the first
/// flight is built.
fn serverTls() tls13.TlsConfig {
    const S = struct {
        var spki: [tls13.ed25519_spki_len]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
        var alpn: [1][]const u8 = .{"bulk"};

        fn build() void {
            const kp = Ed25519.KeyPair.generateDeterministic(server_seed) catch unreachable;
            const node_id = kp.public_key.toBytes();
            spki = tls13.ed25519Spki(&node_id);
            cert_chain = .{&spki};
        }
    };
    S.build();
    return .{
        .cert_chain_der = &S.cert_chain,
        .private_key_bytes = &server_seed,
        .private_key_algorithm = .ed25519,
        .alpn = &S.alpn,
    };
}

const client_alpn = [_][]const u8{"bulk"};

const Result = struct {
    delivered: u64,
    finished: bool,
    elapsed_ns: i64,
    c2s_dropped: u64,
    c2s_sent: u64,
    s2c_dropped: u64,
    s2c_sent: u64,
    closed: bool,
    /// Longest stretch of virtual time in which the server read nothing new.
    max_stall_ns: i64,
    /// Datagram size each side ended up using.
    client_mtu: u16,
    server_mtu: u16,
};

/// Client uploads `total` bytes on one bidi stream; the server reads as it
/// arrives. Stops when the server has read the FIN, a connection closes, or
/// `limit_ns` of virtual time has passed.
///
/// `now` and `random` are the whole input this function has. It never reads a
/// clock or a source of entropy: the loop below is the clock, and the two
/// generators are seeded, so two runs of the same case transfer the same
/// bytes over the same schedule.
fn runBulk(total: usize, c2s_loss: Link.Loss, s2c_loss: Link.Loss, one_way_ns: i64, limit_ns: i64) !Result {
    const alloc = testing.allocator;
    const start: i64 = test_now;
    var now = start;
    var entropy = TestRandom.init(0);
    const random = entropy.random();

    var mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), .{}, .{1} ** 16, .{2} ** 16, random);
    defer mgr.deinit();

    const client = try alloc.create(connection.Connection);
    defer alloc.destroy(client);
    try connection.connectInto(client, alloc, "localhost", .{}, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client_alpn,
        .server_name = "localhost",
    }, null, now, random);
    defer client.deinit();

    const c_addr = addr(40000);
    const s_addr = addr(4433);
    client.paths[0].peer_addr = s_addr;
    client.paths[0].local_addr = c_addr;

    var c2s: Link = .{ .delay_ns = one_way_ns, .loss = c2s_loss };
    defer c2s.deinit();
    var s2c: Link = .{ .delay_ns = one_way_ns, .loss = s2c_loss };
    defer s2c.deinit();

    const payload = try alloc.alloc(u8, total);
    defer alloc.free(payload);
    for (payload, 0..) |*b, k| b.* = @intCast(k % 251);

    var last_delivered: u64 = 0;
    var last_progress: i64 = start;
    var max_stall: i64 = 0;
    var stream_id: ?u64 = null;
    var delivered: u64 = 0;
    var finished = false;
    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;

    while (now - start < limit_ns and !finished) {
        // Timers due now.
        if (client.nextTimeoutNs(now)) |t| if (t <= now) client.onTimeout(now, random) catch {};
        for (mgr.entries.items) |e| if (e.conn.nextTimeoutNs(now)) |t| if (t <= now) e.conn.onTimeout(now, random) catch {};
        if (client.isClosed()) break;
        if (mgr.entries.items.len > 0 and mgr.entries.items[0].conn.isClosed()) break;

        // Application: open and fill the upload once connected.
        if (stream_id == null and client.isEstablished()) {
            const s = try client.openStream();
            try s.send.writeData(payload);
            s.send.close();
            stream_id = s.stream_id;
        }
        if (mgr.entries.items.len > 0) {
            const sconn = mgr.entries.items[0].conn;
            if (stream_id) |id| if (sconn.streams.getStream(id)) |s| {
                while (s.recv.read()) |d| {
                    for (d, 0..) |v, k| {
                        const expected: u8 = @intCast((delivered + @as(u64, k)) % 251);
                        try testing.expectEqual(expected, v);
                    }
                    delivered += d.len;
                    alloc.free(d);
                }
                if (s.recv.finished) finished = true;
            };
        }
        if (delivered != last_delivered) {
            max_stall = @max(max_stall, now - last_progress);
            last_delivered = delivered;
            last_progress = now;
        }

        // Send everything each side will send now.
        while (true) {
            const n = client.sendAt(&buf, now, random) catch break;
            if (n == 0) break;
            try c2s.push(now, buf[0..n]);
        }
        for (mgr.entries.items) |e| while (true) {
            const n = e.conn.sendAt(&buf, now, random) catch break;
            if (n == 0) break;
            try s2c.push(now, buf[0..n]);
        };

        // Deliver what has arrived.
        var delivered_any = false;
        while (c2s.popDue(now)) |d| {
            delivered_any = true;
            switch (mgr.recvDatagram(d.bytes[0..d.len], c_addr, s_addr, 0, &resp, now, random)) {
                .send_response => |r| try s2c.push(now, r),
                else => {},
            }
        }
        while (s2c.popDue(now)) |d| {
            client.handleDatagram(d.bytes[0..d.len], .{ .to = c_addr, .from = s_addr, .datagram_size = d.len }, now, random);
            delivered_any = true;
        }
        if (delivered_any) continue;

        // Advance to the next event.
        var next: i64 = std.math.maxInt(i64);
        if (c2s.nextArrival()) |t| next = @min(next, t);
        if (s2c.nextArrival()) |t| next = @min(next, t);
        if (client.nextTimeoutNs(now)) |t| next = @min(next, t);
        for (mgr.entries.items) |e| if (e.conn.nextTimeoutNs(now)) |t| {
            next = @min(next, t);
        };
        // A timer already due that fired without effect must not spin. This
        // assignment is the only thing in the file that moves time.
        now = @max(now + std.time.ns_per_us, next);
    }

    const closed = client.isClosed() or (mgr.entries.items.len > 0 and mgr.entries.items[0].conn.isClosed());
    return .{
        .delivered = delivered,
        .finished = finished,
        .elapsed_ns = now - start,
        .c2s_dropped = c2s.dropped,
        .c2s_sent = c2s.sent,
        .s2c_dropped = s2c.dropped,
        .s2c_sent = s2c.sent,
        .closed = closed,
        .max_stall_ns = @max(max_stall, now - last_progress),
        .client_mtu = client.mtu_discoverer.current_mtu,
        .server_mtu = if (mgr.entries.items.len > 0) mgr.entries.items[0].conn.mtu_discoverer.current_mtu else 0,
    };
}

const ms = std.time.ns_per_ms;

test "lossy link: a clean 4 MiB upload finishes within a second" {
    const r = try runBulk(4 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.elapsed_ns < std.time.ns_per_s);
}

test "lossy link: an upload past the stream window gets MAX_STREAM_DATA" {
    // 16 MiB against the 6 MiB initial stream window: without the server
    // re-granting credit as it reads, the upload stalls and never finishes.
    const r = try runBulk(16 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
}

test "lossy link: a busy connection still finds the path MTU" {
    // The probe used to sit below the pacer, where the only way to reach it was
    // a pass with nothing to send and no pacing due — which a connection
    // carrying data back to back never gets. Every datagram stayed at 1200.
    const r = try runBulk(4 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.client_mtu > mtu.BASE_PLPMTU);
    try testing.expect(r.server_mtu > mtu.BASE_PLPMTU);
}

test "lossy link: an upload survives bursty loss on the data path" {
    // ~9.5% loss in bursts averaging 3.3 datagrams.
    const r = try runBulk(2 << 20, .{ .bursty = .{ .prng = .init(2), .p_enter = 0.03, .p_leave = 0.3 } }, .none, 10 * ms, 120 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.c2s_dropped > r.c2s_sent / 20);
}

test "lossy link: an upload survives periodic loss bursts in both directions" {
    const burst: Link.Loss = .{ .periodic = .{ .period = 55, .burst = 5 } };
    const r = try runBulk(2 << 20, burst, burst, 10 * ms, 120 * std.time.ns_per_s);
    try testing.expect(r.finished);
}

const stateless_reset = @import("stateless_reset.zig");

/// A connected client and server, handshake done and CIDs exchanged.
///
/// There is no simulated delay here, so `now` stays at `test_now` for the
/// pair's whole life and no timer ever comes due. The field is kept because
/// `sendAt`, `recvDatagram` and `handleDatagram` all stamp what they build
/// or parse with it: an instant that is threaded in has to come from
/// somewhere, and a fixed one says exactly where.
const Pair = struct {
    mgr: connection_manager.ConnectionManager,
    client: *connection.Connection,
    c_addr: address.Address,
    s_addr: address.Address,
    now: i64,
    entropy: TestRandom,
    random: std.Random,

    fn init(self: *Pair) !void {
        const alloc = testing.allocator;
        // Assigned field by field, not through `self.* = .{...}`: `random`
        // holds a pointer to `entropy`, so the engine has to reach its final
        // address before anything is handed out from it.
        self.c_addr = addr(40000);
        self.s_addr = addr(4433);
        self.now = test_now;
        self.entropy = TestRandom.init(0);
        self.random = self.entropy.random();
        self.mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), .{}, .{1} ** 16, .{2} ** 16, self.random);
        self.client = try alloc.create(connection.Connection);
        errdefer {
            alloc.destroy(self.client);
            self.mgr.deinit();
        }
        try connection.connectInto(self.client, alloc, "localhost", .{}, .{
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .alpn = &client_alpn,
            .server_name = "localhost",
        }, null, self.now, self.random);
        self.client.paths[0].peer_addr = self.s_addr;
        self.client.paths[0].local_addr = self.c_addr;

        var i: usize = 0;
        while (i < 50 and self.exchange()) : (i += 1) {}
        try testing.expect(self.client.handshake_confirmed);
        try testing.expectEqual(@as(usize, 1), self.mgr.entries.items.len);
    }

    fn deinit(self: *Pair) void {
        self.client.deinit();
        testing.allocator.destroy(self.client);
        self.mgr.deinit();
    }

    /// One round of both sides sending what they have; false once quiet.
    fn exchange(self: *Pair) bool {
        var buf: [MAX_DGRAM]u8 = undefined;
        var resp: [MAX_DGRAM]u8 = undefined;
        var any = false;
        while (true) {
            const n = self.client.sendAt(&buf, self.now, self.random) catch break;
            if (n == 0) break;
            any = true;
            _ = self.mgr.recvDatagram(buf[0..n], self.c_addr, self.s_addr, 0, &resp, self.now, self.random);
        }
        for (self.mgr.entries.items) |e| while (true) {
            const n = e.conn.sendAt(&buf, self.now, self.random) catch break;
            if (n == 0) break;
            any = true;
            self.client.handleDatagram(buf[0..n], .{ .to = self.c_addr, .from = self.s_addr, .datagram_size = n }, self.now, self.random);
        };
        return any;
    }
};

test "stateless reset: a client whose server lost the connection drains" {
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();

    p.mgr.removeConnection(p.mgr.entries.items[0]);

    const s = try p.client.openStream();
    try s.send.writeData("x" ** 64);
    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    const n = try p.client.sendAt(&buf, p.now, p.random);
    const reset = switch (p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp, p.now, p.random)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    p.client.handleDatagram(@constCast(reset), .{ .to = p.c_addr, .from = p.s_addr, .datagram_size = reset.len }, p.now, p.random);
    try testing.expect(p.client.isDraining());
    try testing.expect(p.client.received_stateless_reset);
    try testing.expectEqual(@as(usize, 0), try p.client.sendAt(&buf, p.now, p.random));
}

test "stateless reset: the server drains a connection its client reset" {
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();

    // A token the client issued in NEW_CONNECTION_ID; the reset's DCID is random.
    const token = for (&p.client.local_cid_pool.entries) |*e| {
        if (e.occupied and e.seq_num > 0) break e.stateless_reset_token;
    } else return error.TestUnexpectedResult;
    var reset: [48]u8 = undefined;
    p.random.bytes(&reset);
    reset[0] = 0x40 | (reset[0] & 0x3f);
    @memcpy(reset[reset.len - stateless_reset.TOKEN_LEN ..], &token);

    var resp: [MAX_DGRAM]u8 = undefined;
    const sconn = p.mgr.entries.items[0].conn;
    try testing.expect(p.mgr.recvDatagram(&reset, p.c_addr, p.s_addr, 0, &resp, p.now, p.random) == .processed);
    try testing.expect(sconn.isDraining());
    try testing.expect(sconn.received_stateless_reset);
}
