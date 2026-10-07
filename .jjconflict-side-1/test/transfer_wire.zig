//! One endpoint's transport, and the virtual clock every endpoint is driven
//! at.
//!
//! `Wire` owns a socket on an ephemeral loopback port, the `Bridge` that runs
//! its connections, a `Dialer`, an address map and the buffers both seams need.
//! It carries no protocol state, because the getter and the provider want
//! different state on top of exactly this — which is why both reach down to it
//! rather than either owning it.
//!
//! `Counters` is here rather than in the link because the numbers it keeps are
//! the send seam's: a transfer this size has to go out as segmented sends and
//! only the seam knows how many datagrams there were.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const batch = ozai.transport_batch;
const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;

const Bridge = bridge_mod.Bridge;
pub const Conn = bridge_mod.Conn;
const Egress = bridge_mod.Egress;
pub const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine
/// has to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

/// Where every socket binds, with port zero: the kernel picks, so a socket
/// left over from the last run cannot collide with this one.
pub const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. See the module doc: it only moves by `quantum`.
pub const start_ns: u64 = 1000 * std.time.ns_per_s;

/// How far the clock moves per round. A round is a handful of syscalls, so
/// this is a clock and not a delay: nothing in this file waits for it.
pub const quantum: u64 = std.time.ns_per_ms;

/// How many rounds a phase may take before it is called stalled.
///
/// Generous, because a round is a few syscalls and nothing here can block: the
/// bound is a backstop against a run that never finishes, not a timer.
pub const max_rounds = 512;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small, and the room for them.
///
/// A burst of this blob's answer is bounded by the sender's congestion window
/// rather than by a fixed count, so the room is sized for the whole answer and
/// not for a guess about how many packets a burst holds.
const max_egress = 512;
const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: the datagram is copied into its front and a
/// stateless reply is written behind it.
const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One endpoint's transport: an identity, a socket on an ephemeral loopback
/// port, the bridge that runs its connections, and the buffers both seams need.
///
/// It carries no protocol state, because the two halves of this test want
/// different state on top of exactly this.
pub const Wire = struct {
    name: []const u8,
    id: NodeId,
    secret: SecretKey,
    socket: Socket,
    bridge: *Bridge,
    dialer: *Dialer,
    map: addr_map.MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,
    stats: Counters = .{},

    /// Stand the wire up: its socket, its bridge, its dialer and its scratch.
    ///
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn init(
        self: *Wire,
        name: []const u8,
        secret: SecretKey,
        expect_peer: ?NodeId,
        alpn: []const u8,
        seed: u64,
    ) !void {
        self.* = .{
            .name = name,
            .id = secret.nodeId(),
            .secret = secret,
            .socket = undefined,
            .bridge = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.map.deinit(t.allocator);
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a
        // test whose Retry key differs on every run has failures that move.
        self.bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = secret,
            .expect_peer = expect_peer,
            .alpn = alpn,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.dialer = try Dialer.create(t.allocator, self.bridge, .{
            .secret = secret,
            .alpn = alpn,
        });
        errdefer self.dialer.destroy() catch @panic("new dialer has no live connections");
        // A bridge created a moment ago has no entry for `destroy` to refuse,
        // so this fires only on an allocation that followed it.
        self.egress = try t.allocator.alloc(Egress, max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, send_room);
        errdefer t.allocator.free(self.out);
        self.scratch = try t.allocator.alloc(u8, scratch_room);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, receive_room);
    }

    /// Unwind order matters, and it is `Dialer.destroy`'s: a dialled
    /// connection's handshake points at the dialer's own seed, so every
    /// connection this dialer opened has to leave the manager before the
    /// dialer goes, and the manager has to outlive both.
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn deinit(self: *Wire) void {
        // Backwards, because `removeConnection` swap-removes and a forward
        // walk would skip an entry and leave a freed one behind.
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        // Only server entries can survive: the bridge never dials, and no code
        // between the removal walk and destroy can add another connection.
        self.dialer.destroy() catch @panic("dialer retained a connection after removal");
        self.bridge.destroy();
        t.allocator.free(self.egress);
        t.allocator.free(self.out);
        t.allocator.free(self.scratch);
        t.allocator.free(self.buf);
        self.map.deinit(t.allocator);
        self.socket.close();
        self.secret.deinit();
        self.* = undefined;
    }

    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn random(self: *Wire) std.Random {
        return self.engine.random();
    }

    /// Take everything queued on this socket and hand it to the bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into
    /// one buffer, so the stride is what says how many packets there are and
    /// the bridge is handed them one at a time.
    fn take(self: *Wire, at: Instant) !bool {
        var moved = false;
        while (true) {
            const sock = &self.socket;
            const got = sock.tryReceive(t.io, self.buf, &self.control) catch |err| switch (err) {
                // The socket is non-blocking from the moment it was created,
                // and an empty queue is a fact the loop acts on.
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            self.stats.in += recv.datagramCount();
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try self.bridge.recv(&self.map, .{
                    // The loop's bound is `recv.datagramCount()`, and
                    // `Recv.datagram` answers null only past that count.
                    // zwanzig-disable-next-line: optional-unwrap
                    .bytes = recv.datagram(position).?,
                    .from = got.from,
                    .local = self.socket.address,
                    .ecn = recv.ecn,
                }, self.scratch, at, self.random());
                moved = true;
                switch (ingress.outcome) {
                    // Nothing to do here: this connection is drained by the
                    // next `flush`, which finds it by index.
                    .processed => {},
                    // A stateless reply is a send, back out of the same socket
                    // to the address the datagram came from.
                    .reply => |reply| {
                        self.stats.out += 1;
                        self.stats.note(reply, sock.caps);
                        _ = try sock.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// Drain every connection and write each datagram out, then run the timers.
    fn flush(self: *Wire, at: Instant) !bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                self.stats.out += 1;
                // Counted before the write, because the accounting is about
                // what the bridge handed over and not about whether the kernel
                // took it.
                self.stats.note(egress.send, self.socket.caps);
                const report = try self.socket.send(t.io, egress.to, egress.send);
                if (!report.ecnSurvived()) self.stats.dropped_ecn += 1;
                moved = true;
            }
        }
        var scan: usize = 0;
        while (self.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) self.stats.finished += 1;
        }
        return moved;
    }

    /// One pass of the whole link: everything this side has, then everything
    /// its peer has.
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn exchange(self: *Wire, at: Instant) !bool {
        const mine = try self.take(at);
        return (try self.flush(at)) or mine;
    }
};

/// What one side moved, and how the send seam cut it up.
///
/// The datagram counts are not a claim about the protocol; they are the
/// measurement the plan asks for, because a transfer this size has to go out
/// as segmented sends and only the seam knows how many datagrams there were.
pub const Counters = struct {
    out: usize = 0,
    in: usize = 0,
    finished: usize = 0,
    /// `batch.Send` values handed to the socket.
    sends: usize = 0,
    /// `sendmsg` calls those sends were cut into, at the socket's own
    /// capability: a batch of more than `max_segments_linux` datagrams is more
    /// than one `sendmsg` may carry.
    runs: usize = 0,
    /// Datagrams inside those sends.
    datagrams: usize = 0,
    /// The most datagrams in one send, which is what says whether the batch
    /// boundary was crossed inside a single batch.
    widest: usize = 0,
    /// Sends the batcher segmented rather than passing as one datagram.
    segmented: usize = 0,
    /// Sends whose traffic class the kernel did not carry.
    dropped_ecn: usize = 0,

    /// Account for one `batch.Send`, cut with the capability the socket will
    /// use.
    fn note(counter: *Counters, send: batch.Send, caps: batch.Capability) void {
        counter.sends += 1;
        const datagrams = send.datagramCount();
        counter.datagrams += datagrams;
        counter.widest = @max(counter.widest, datagrams);
        if (send.isSegmented()) counter.segmented += 1;
        var runs = batch.Runs.init(send, caps) catch return;
        while (runs.next()) |_| counter.runs += 1;
    }
};
