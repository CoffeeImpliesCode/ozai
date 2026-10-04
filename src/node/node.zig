//! Heap-stable data: router leases, lanes, and relay registries borrow this address.
//! Lifecycle owns allocation; processor modules operate on this data through free functions.
//!
//! Gossip: a `send_message` names a node id, so this struct holds the two
//! tables that answer for one. `connections` maps every peer id to the
//! connection carrying it, and `topics` holds each swarm's state machine, its
//! timers, the contact data it keeps and the stream it writes that peer on.
//! `node_gossip` is what reads both and puts a frame on a stream.
const std = @import("std");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const shutdown_mod = @import("../router/shutdown.zig");
const lifetime_mod = @import("../router/lifetime.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const topic_table = @import("topic_table.zig");
const conn_index = @import("conn_index.zig");
const relay_state = @import("relay_state.zig");
const config = @import("node_config.zig");
const protocol = @import("node_protocol.zig");
const stats = @import("node_stats.zig");
const Csprng = std.Random.DefaultCsprng;
const relay_storage = relay_state.State(config.relay_table_slots, config.relay_displaced);

pub const Stop = struct {
    flag: std.atomic.Value(bool) = .init(false),
    due: ?quic_conn.Instant = null,
    pub fn init() Stop {
        return .{};
    }
    pub fn request(self: *Stop) void {
        self.flag.store(true, .release);
    }
    pub fn requested(self: *const Stop) bool {
        return self.flag.load(.acquire);
    }
    pub fn expireAt(self: *Stop, at: quic_conn.Instant) void {
        self.due = at;
    }
    pub fn expired(self: *const Stop, at: quic_conn.Instant) bool {
        if (self.requested()) return true;
        const due = self.due orelse return false;
        return at >= due;
    }
};

pub const Answer = struct {
    event: endpoint.Event,
    count: usize = 1,
};

pub const Lane = struct {
    owner: *Node,
    alpn: []const u8,
    standard: ?protocol.Standard,
    caller: ?protocol.Handler,
    turns: u64 = 0,
    finished: u64 = 0,
    shutdowns: u64 = 0,
    shut: bool = false,
    answered: protocol.Turn = .finished,
    pub fn turn(self: *Lane, connection: *const protocol.Connection) router.AcceptError!protocol.Turn {
        if (self.caller) |handler| return handler.accept(handler.ptr, connection.*);
        return .finished;
    }
};

pub const Node = struct {
    gpa: std.mem.Allocator,
    /// ALPN bytes, handlers, and peer address payloads outlive this heap owner.
    /// The protocol list is consumed once; relay role/client/queue sizes are fixed.
    /// Only drain_room may change; peers may change before the first start.
    config: config.Config,
    socket: socket_mod.Socket,
    bridge: *bridge_mod.Bridge,
    dialer: *dial_mod.Dialer,
    map: addr_map.MappedAddrs,
    socket_open: bool,
    endpoint_closed: bool,
    entries: [protocol.max_alpns]router.Entry,
    table: router.Router,
    lanes: [protocol.max_alpns]Lane,
    lane_lifetimes: [protocol.max_alpns]lifetime_mod.Lifetime,
    lane_lanes: lifetime_mod.Lanes,
    /// The ALPN names, in registration order, written once by `Router.offers`
    /// inside `node_lifecycle.create` before `Bridge.create` and `Dialer.create`
    /// are handed a slice of it; each copies the names into its own storage.
    ///
    /// **Narrowing reaches `Bridge.alpn_list` and nothing else.** `retire`
    /// calls `Bridge.withdrawAlpn`, which rewrites that array in place and
    /// re-points the core's `TlsConfig.alpn` at the survivors
    /// (`quic_bridge.zig:334-353`). This field, `router.Router` and
    /// `Dialer.alpn_list` are all left whole, so a name a reader expects to be
    /// gone is still on the dialling side: a retired protocol stays in the
    /// offer on every outgoing dial, and a peer that selects it gets a
    /// connection this node dialled, which `admit` skips — it walks
    /// server-side connections only (`node_accept.zig:25`) — so no lane claims
    /// it and no counter moves. Two fields of the same type beside each other,
    /// one narrowed and one not, is the asymmetry worth naming here.
    ///
    /// `Dialer` has no withdrawal for its list, and whether it should be given
    /// one is a behaviour decision recorded elsewhere; this comment does not
    /// settle it, and nothing here implements it.
    offer_list: [protocol.max_alpns][]const u8,
    tasks: [config.max_accepts]endpoint.Task,
    accept: endpoint.Loop,
    lease: shutdown_mod.Lease,
    /// Every swarm this node is in, and the stream each peer is written on for
    /// each. `node_gossip` drives them; nothing else reaches inside.
    topics: topic_table.Table,
    /// Every connection this node can name by the peer's id — the only way a
    /// request naming a node reaches a socket.
    connections: conn_index.Index,
    /// Seeded securely by lifecycle; passes may still take an injected generator.
    engine: Csprng,
    egress: []quic_conn.Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: socket_mod.ControlBuffer,
    held: ?socket_mod.Received,
    offered: std.AutoHashMapUnmanaged(u64, void),
    dialled: std.AutoArrayHashMapUnmanaged(base_key.NodeId, void),
    joined: bool,
    /// Registry and client slots exist only for .serve; frame buffers exist for every role.
    relay_state: relay_storage,
    stats: stats.Stats,
};

pub fn nodeId(self: *const Node) base_key.NodeId {
    return self.bridge.nodeId();
}

pub fn address(self: *const Node) base_addr.SocketAddr {
    return self.socket.address;
}

pub fn generator(self: *Node) std.Random {
    return self.engine.random();
}

pub fn establishedCount(self: *const Node) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.established()) count += 1;
    }
    return count;
}

/// The peers the first topic's most recent actions named, or an empty slice
/// for a node in no topic. The report reads this to decide whether it has a
/// line to print at all.
pub fn namedPeers(self: *const Node) []const base_key.NodeId {
    const topic = self.topics.peek(0) orelse return &.{};
    return topic.state.namedPeers();
}

pub fn connFor(self: *Node, id: u64) ?quic_conn.Conn {
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.id() == id) return conn;
    }
    return null;
}
