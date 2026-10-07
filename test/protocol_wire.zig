//! One endpoint's transport, and the virtual clock every endpoint is driven at.
//!
//! `Wire` owns a socket on an ephemeral loopback port, the `Bridge` that runs
//! its connections, a `Dialer`, an address map and the buffers both seams need.
//! It carries no protocol state, because the gossip swarm and the blobs pair
//! want different state on top of exactly this — which is why both of them
//! reach down to it rather than either owning it.
//!
//! The clock lives here because every caller of it is a transport driver and
//! because it is the transport's one external input: no call below reads a
//! real clock, so a run that never converges ends on the round bound with a
//! report rather than by hanging.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;

const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;
const batch = ozai.transport_batch;

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

/// Where virtual time starts. See the module doc: it only ever moves by
/// `time_quantum`.
pub const start_ns: gossip.Nanos = 1_000 * std.time.ns_per_s;

/// How far the clock moves per round. A round is a handful of syscalls, so this
/// is a clock and not a delay: nothing in this file waits for it to elapse.
pub const time_quantum: gossip.Nanos = gossip.nanos_per_milli;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
pub const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small.
pub const max_egress = 8;

/// Room for every datagram one drain may produce.
pub const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: the datagram is copied into its front and a
/// stateless reply is written behind it.
pub const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How many rounds a phase may take before it is called stalled.
///
/// Generous, because a round is a few syscalls and nothing here can block: the
/// bound is a backstop against a run that never converges, not a timer.
pub const max_rounds = 512;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One endpoint's transport: an identity, a socket on an ephemeral loopback
/// port, the bridge that runs its connections, and the buffers both seams need.
///
/// It carries no protocol state, because the gossip mesh and the blobs pair
/// want different state on top of exactly this.
pub const Wire = struct {
    name: []const u8,
    index: usize,
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

    /// Stand the wire up: its socket, its bridge, its dialer and its scratch.
    ///
    /// `pub` because `protocol_blobs_link.zig` and `protocol_node.zig` call
    /// it across the file boundary the split gave this module its own name.
    pub fn init(
        self: *Wire,
        name: []const u8,
        index: usize,
        secret: ozai.SecretKey,
        expect_peer: ?ozai.NodeId,
        alpn: []const u8,
        seed: u64,
    ) !void {
        self.* = .{
            .name = name,
            .index = index,
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
        // A bridge that was created a moment ago has no entry for `destroy` to
        // refuse, so this fires only on an allocation that followed it.
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
    ///
    /// `pub` because `protocol_blobs_link.zig` and `protocol_node.zig` call it
    /// across the file boundary the split gave this module its own name.
    pub fn deinit(self: *Wire) void {
        // Backwards, because `removeConnection` swap-removes and a forward walk
        // would skip an entry and leave a freed one behind.
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

    /// A generator over this wire's own engine, good until the next call.
    ///
    /// `pub` because `protocol_swarm.zig` and `protocol_blobs_link.zig` call
    /// it across the file boundary the split gave this module its own name.
    pub fn random(self: *Wire) std.Random {
        return self.engine.random();
    }

    /// Take everything queued on this socket and hand it to the bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into one
    /// buffer, so the stride is what says how many packets there are and the
    /// bridge is handed them one at a time.
    fn take(self: *Wire, at: Instant, stats: *Counters) !bool {
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
            stats.in += recv.datagramCount();
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
                        stats.out += 1;
                        _ = try sock.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// Drain every connection and write each datagram out, then run the timers.
    fn flush(self: *Wire, at: Instant, stats: *Counters) !bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                stats.out += 1;
                _ = try self.socket.send(t.io, egress.to, egress.send);
                moved = true;
            }
        }
        var scan: usize = 0;
        while (self.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) stats.finished += 1;
        }
        return moved;
    }

    /// One pass of the whole link: everything this side has, then everything
    /// its peer has.
    /// `pub` because `protocol_blobs_link.zig` and `protocol_swarm.zig` call it
    /// across the file boundary the split that gave this module its own name
    /// introduced.
    pub fn exchange(self: *Wire, at: Instant, stats: *Counters) !bool {
        const mine = try self.take(at, stats);
        return (try self.flush(at, stats)) or mine;
    }
};

/// What one side moved, for the stall report. Counters and nothing else: the
/// assertions are about membership, and these are what say what the
/// transport underneath was doing.
pub const Counters = struct {
    out: usize = 0,
    in: usize = 0,
    finished: usize = 0,
};
