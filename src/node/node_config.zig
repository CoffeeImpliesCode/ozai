const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_transport_addr = @import("../base/transport_addr.zig");
const batch = @import("../transport/batch.zig");
const hyparview = @import("../gossip/hyparview.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_state = @import("relay_state.zig");
const protocol = @import("node_protocol.zig");

pub const max_datagram = 1500;
pub const max_egress = 8;
pub const send_room: usize = max_egress * max_datagram;
pub const scratch_room: usize = 2 * max_datagram;
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;
pub const max_accepts = 64;
pub const poll_interval_ms = 250;
pub const named_ring = 8;
pub const max_close_steps = 8;
pub const max_relay_clients = 4;
pub const relay_table_slots = 2 * max_relay_clients;
pub const relay_displaced = 4;
pub const default_relay_queue_depth = 64;
pub const relay_frame_room = relay_frame.DatagramFrame.header_length + max_datagram + 8;

/// Peers a node names at once, which is the peer-id connection index's width.
/// The accept window doubled: an index that could not name every connection a
/// node is holding would refuse a peer that is really there.
pub const max_connections = 64;
/// Swarms one node is in at once. Upstream runs one topic actor per swarm and
/// a node joins at most one here, so this is headroom rather than a promise.
pub const max_topics = 8;
/// Contact-data slots per topic, which is membership's own table size.
pub const topic_peer_slots = hyparview.max_known_peers;
/// Unidirectional streams open to one peer on one topic: one live, and one
/// more opened when the first has spent the peer's flow-control credit.
pub const streams_per_peer = 2;
/// Route slots a topic holds, because every peer in it may hold this many.
pub const topic_route_slots = topic_peer_slots * streams_per_peer;

comptime {
    if (relay_frame.ServerDeniesAuth.max_frame_length > relay_frame_room) {
        @compileError("the relay's frame room is narrower than the denial it may send");
    }
}

pub const Relay = struct {
    role: Role = .off,
};

pub const Role = union(enum) {
    off,
    serve: Serve,
    client: Peer,
};

pub const Serve = struct {
    /// Construction-fixed: storage is allocated for this many clients.
    clients: usize = max_relay_clients,
    /// Construction-fixed: live queue slices are cut with this depth on every pass.
    queue_depth: usize = default_relay_queue_depth,
    /// May change after construction; bounds writes without resizing storage.
    drain_room: usize = 4,
};

pub const Peer = struct {
    id: base_key.NodeId,
    addr: base_transport_addr.TransportAddr,
};

pub const Config = struct {
    secret: base_key.SecretKey,
    listen: base_addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    },
    /// Each peer is attempted before start refuses an oversized bootstrap list.
    peers: []const Peer = &.{},
    /// Preference order. The slice and all ALPN bytes must outlive the node.
    protocols: []const protocol.Protocol = &.{.{ .alpn = protocol.gossip_alpn }},
    topic: hyparview.TopicConfig = .{},
    relay: Relay = .{},
    /// The swarm this node is in. Every unidirectional stream it opens names
    /// this, and two nodes only hear each other when they agree on it — so it
    /// is configuration, never derived. All zeroes is the default because a
    /// single-swarm node has no other answer to give; an application running
    /// several must choose an id per swarm.
    topic_id: hyparview.TopicId = .fromBytes([_]u8{0} ** hyparview.topic_id_length),
};

/// The storage owner determines the borrowed payload's lifetime.
pub const Delivered = relay_state.Delivered;
