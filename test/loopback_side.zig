//! One endpoint: an identity, a socket on an ephemeral loopback port, the
//! bridge that runs its connections, and the buffers the send and receive seams
//! need.
//!
//! The buffers are on the heap because the receive one is 96 KB. A test that
//! overflows the stack fails for a reason that has nothing to do with QUIC, and
//! every buffer here is the caller's by the seam's own contract. The clock lives
//! here too, because `Side` is what every instant in this file is an argument to.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const batch = ozai.transport_batch;
const bridge_mod = ozai.transport_quic_bridge;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;

const Bridge = bridge_mod.Bridge;
const Instant = bridge_mod.Instant;
const Egress = bridge_mod.Egress;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;
const SocketAddr = ozai.SocketAddr;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine
/// has to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

/// The one ALPN both ends speak, and the only thing they agree on besides the
/// handshake itself.
pub const alpn = "ozai";

/// Where both sockets bind, with port zero: the kernel picks, so two runs at
/// once and a socket left over from the last one cannot collide, and nothing
/// in the test needs to be reconfigured when one of them does.
pub const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. It never moves: see the module doc.
pub const start: Instant = 1_000 * std.time.ns_per_s;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small. A whole flight fits; a caller that wants less learns it from
/// `error.NoRoom`.
const max_egress = 8;

/// Room for every datagram one drain may produce.
const send_room: usize = max_egress * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
/// `batch.max_gro_segments_linux` is the count a socket installs when it
/// accepts `UDP_GRO`, and its own doc says a receive buffer too small for the
/// largest list truncates a coalesced read — which arrives at this seam as
/// `error.MessageTooLarge` rather than as a short datagram.
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How many flights each direction a phase may take before it is called
/// stalled. Generous, because a round is a few syscalls and nothing here can
/// block: the bound is a backstop against a run that never converges, not a
/// timer.
pub const max_rounds = 32;

/// One endpoint: an identity, a socket on an ephemeral loopback port, the
/// bridge that runs its connections, and the buffers the send and receive
/// seams need.
///
/// The buffers are on the heap because the receive one is 96 KB. A test that
/// overflows the stack fails for a reason that has nothing to do with QUIC,
/// and every buffer here is the caller's by the seam's own contract.
pub const Side = struct {
    name: []const u8,
    socket: Socket,
    bridge: *Bridge,
    map: addr_map.MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,

    /// Stand one end up: its socket, its bridge and the buffers it shares.
    ///
    /// `pub` because `loopback_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn init(
        self: *Side,
        name: []const u8,
        secret: ozai.SecretKey,
        expect: ?ozai.NodeId,
        engine_seed: u64,
    ) !void {
        self.* = .{
            .name = name,
            .socket = undefined,
            .bridge = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(engine_seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.map.deinit(t.allocator);
        // The bind happens inside `create`, so the address this side is
        // reachable at is only known once the socket exists. That is why the
        // dialling side is dialled at this side's address rather than at one
        // the test made up.
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a
        // test whose Retry key differs on every run has failures that move.
        self.bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = secret,
            .expect_peer = expect,
            .alpn = alpn,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.egress = try t.allocator.alloc(Egress, max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, send_room);
        errdefer t.allocator.free(self.out);
        // The core's own buffer: the datagram is copied into its front and a
        // stateless reply is written behind it, which is `Bridge.recv`'s
        // contract and the reason it is twice a datagram.
        self.scratch = try t.allocator.alloc(u8, 2 * max_datagram);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, receive_room);
        errdefer t.allocator.free(self.buf);
    }

    /// Take the side down: the bridge, the buffers, the address map and the
    /// socket, in the order each of them was set up.
    ///
    /// `pub` because `loopback_link.zig` and `loopback_test.zig` call it across
    /// the file boundary the split that gave this module its own name
    /// introduced.
    pub fn deinit(self: *Side) void {
        self.bridge.destroy();
        t.allocator.free(self.egress);
        t.allocator.free(self.out);
        t.allocator.free(self.scratch);
        t.allocator.free(self.buf);
        self.map.deinit(t.allocator);
        self.socket.close();
        self.* = undefined;
    }

    /// A generator over this side's own engine, good until the next call.
    ///
    /// `pub` because `loopback_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn random(self: *Side) std.Random {
        return self.engine.random();
    }

    /// Copy whatever a stream the peer opened has delivered into `out`, and
    /// say how many bytes came.
    ///
    /// Two things about the read, both of them the application's problem
    /// rather than the core's. There is no accept-side accessor — a stream
    /// arrives by being written to on the wire, and the connection's own
    /// stream map is then the only place it is readable, so `getStream` is
    /// that map's accessor. And `recv.read` hands the caller ownership of a
    /// whole allocation (`FrameSorter.pop` pops one chunk and the application
    /// frees it), which is why the copy is made here and the core's bytes are
    /// released before this returns.
    ///
    /// `pub` because `loopback_test.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn takeStream(self: *Side, stream_id: u64, out: []u8) usize {
        const conn = self.bridge.connectionAt(0) orelse return 0;
        const opened = conn.entry.conn.streams.getStream(stream_id) orelse return 0;
        const chunk = opened.recv.read() orelse return 0;
        defer t.allocator.free(chunk);
        const taken = @min(chunk.len, out.len);
        @memcpy(out[0..taken], chunk[0..taken]);
        return taken;
    }
};
