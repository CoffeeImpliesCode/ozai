//! The relay's storage, and the slots a client occupies in it.
//!
//! A relay is sized once, by the operator's `Serve.clients` and
//! `Serve.queue_depth`, and this is where that sizing is cut: one registry
//! over a fixed slot table, one `Served` per client, and the two queues and
//! the datagram ring laid out back to back behind them. Every later read of
//! that storage goes through a cut re-made from the live configuration, which
//! is why `Serve.queue_depth` must not be written after `Node.create`.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_relay_release = @import("node_relay_release.zig");
const node_relay_frame = @import("node_relay_frame.zig");
const node_transport = @import("node_transport.zig");

const base_key = @import("../base/key.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const relay_server = @import("../relay/server.zig");
const quic_varint = @import("../wire/quic_varint.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const NodeId = base_key.NodeId;
const max_datagram = node_transport.max_datagram;
const relay_frame_room = node_relay_frame.relay_frame_room;
const varint_max = quic_varint.max_length;

/// How many clients a relay admits.
///
/// Small, and deliberately: every one of them costs `queue_depth *
/// max_datagram` of fixed storage for the datagrams queued to it, so this is
/// the number an operator picks and `Relay.clients` is the way to pick it.
pub const max_relay_clients = 4;

/// Registry slots for those clients. Open addressing, so twice the clients is
/// never more than half full.
pub const relay_table_slots = 2 * max_relay_clients;

/// How many connections one node id's later connections may displace.
///
/// Enough for `Registry.Admit.replaced` and `Unregister.promoted` to be
/// reachable, and a comptime parameter of `Registry` because the entry's
/// inactive list is a fixed array rather than something that grows.
pub const relay_displaced = 4;

/// Upstream's `PER_CLIENT_SEND_QUEUE_DEPTH` (`relay.rs:40`) is 512 and both of
/// its channels get it, and 512 is the number invariant 9 is about: merged, a
/// `Status` sits behind 512 datagrams for a client that has stopped reading.
///
/// This node makes it the operator's number, because the queue is backed by
/// fixed storage this file allocates and 512 datagrams a client is 512 ×
/// `max_datagram` of bytes a client. The test at the bottom of `node.zig` sets
/// `Relay.queue_depth` to upstream's number so the property is exercised
/// rather than assumed.
pub const default_relay_queue_depth = 64;

/// One client this node serves.
///
/// The registry holds connection ids and not these, because a registry that
/// held queues would allocate and `relay/server.zig`'s does not — it is a table
/// over storage the caller owns, and this is where the caller put the rest.
pub const Served = struct {
    /// Whether this slot holds a client.
    live: bool = false,
    /// The core connection this client is spoken on, which is the id the
    /// registry holds for it.
    conn: u64 = 0,
    /// The relay half of the handshake, from the moment the connection is
    /// established. `.admitted` is where a client stops being a handshake and
    /// starts being a client.
    handshake: relay_server.State = .opened,
    /// The handle that ends this client, and the only way out of the registry.
    /// Null is a client that has not been admitted, and must not be reported
    /// as gone: `Registry.unregister` is not public, so a client with no
    /// handle has no exit at all.
    guard: ?relay_server.Registry(relay_displaced).OnDisconnectGuard = null,
    /// The node id the handshake proved, or null until it has.
    node_id: ?NodeId = null,
    /// The two queues, over storage this node owns.
    queues: relay_server.Connection = undefined,
    /// The bytes a queued datagram borrows: one fixed slot per queue position,
    /// so a `Packet` points at the slot its own ring position names and the
    /// slot is free the moment it is popped.
    ///
    /// Fixed rather than an arena that grows, because a growing arena moves
    /// the bytes every queued `Packet` points at.
    ring: []u8 = &.{},
    /// The stream this relay writes to the client on: one it opened itself.
    ///
    /// **Two streams per client, and they are not interchangeable.** A QUIC
    /// stream is read by whichever end opened it, so the client's half of the
    /// protocol can only be read from the stream the *client* opened — which
    /// this connection does not hold until the client has written something.
    /// That is why the relay opens one of its own to speak on: a relay that
    /// waited for the client's stream could not send the challenge that makes
    /// the client write on it. `serveRead` finds the other half each pass.
    out: bridge_mod.Stream = undefined,
    /// What has been read off that stream and is not yet a whole message.
    inbox: std.ArrayList(u8) = .empty,
    /// Whether the client has been told there is nothing more.
    ended: bool = false,
};

/// Build the relay's storage, once, from the role `create` was given.
///
/// **Two of these allocations belong to every role and four to `.serve`.**
/// `relay_out` and `relay_scratch` are taken before the role is read at
/// all, so a `.off` node holds them and `freeRelay` returns them without a
/// byte of either ever having been written: `serve`, `converse` and
/// `sendThrough` reach `writeRelay`; `serve` and `converse` reach `peekFrame`.
/// The registry, client slots and three queue allocations follow the `.serve` return; they
/// are the storage `Serve.clients` and `Serve.queue_depth` size, once,
/// here. That is why those two fields must not be written after `create`
/// (`Node.config`), and why `queueDepth` reads the same live field the
/// cuts are made from.
pub fn initRelay(self: *Node) Error!void {
    const gpa = self.gpa;
    self.relay_out = try gpa.alloc(u8, relay_frame_room + varint_max);
    errdefer gpa.free(self.relay_out);
    self.relay_scratch = try gpa.alloc(u8, relay_frame_room);
    errdefer gpa.free(self.relay_scratch);
    const role = switch (self.config.relay.role) {
        .serve => |role| role,
        // A client needs no registry and no queues. It needs the two
        // buffers and one stream, and the buffers are all it allocates.
        else => return,
    };
    // The tables here are sized by `max_relay_clients` and are built not to
    // grow, so a relay that admitted more would probe a table the registry
    // would answer `NoFreeSlot` to long before it was actually full.
    if (role.clients > max_relay_clients) return error.TooManyRelayClients;
    // A queue with no room can never take anything, and a relay with one
    // drops every datagram while reporting that it forwarded none.
    if (role.queue_depth == 0) return error.RelayQueueDepthZero;
    const per_client = role.clients * role.queue_depth;
    self.registry = relay_server.Registry(relay_displaced).init(&self.slots);
    self.clients = try gpa.alloc(Served, role.clients);
    errdefer gpa.free(self.clients);
    self.packets = try gpa.alloc(relay_server.Packet, per_client);
    errdefer gpa.free(self.packets);
    self.messages = try gpa.alloc(relay_server.Control, per_client);
    errdefer gpa.free(self.messages);
    self.ring = try gpa.alloc(u8, per_client * max_datagram);
    errdefer gpa.free(self.ring);
    for (self.clients, 0..) |*client, index| {
        client.* = .{ .queues = queuesOf(self, index), .ring = ringOf(self, index) };
    }
}

/// One client's two queues, cut out of this node's storage.
///
/// **The cut is redone from `config` on every call rather than kept beside
/// the storage it describes**, so `depth` is the value the field holds now
/// and not the one `initRelay` sized these allocations from. That is the
/// whole of the rule `Node.config` states: the relay's sizing is fixed at
/// construction because this call re-reads it, not because anything here
/// copied it.
pub fn queuesOf(self: *const Node, index: usize) relay_server.Connection {
    const depth = queueDepth(self);
    const base = index * depth;
    return relay_server.Connection.init(
        self.packets[base..][0..depth],
        self.messages[base..][0..depth],
    );
}

/// One client's datagram ring: a fixed slot per queue position.
pub fn ringOf(self: *const Node, index: usize) []u8 {
    const depth = queueDepth(self);
    return self.ring[index * depth * max_datagram ..][0 .. depth * max_datagram];
}

/// One client's depth, read from the live configuration rather than kept
/// beside it. See `queuesOf` for why that is the same number on every pass
/// and what a write to it costs.
pub fn queueDepth(self: *const Node) usize {
    return switch (self.config.relay.role) {
        .serve => |role| role.queue_depth,
        else => 0,
    };
}

/// The client on connection `conn`, or null when there is none.
pub fn servedFor(self: *const Node, conn: u64) ?*Served {
    for (self.clients) |*slot| {
        if (slot.live and slot.conn == conn) return slot;
    }
    return null;
}

/// A free client slot, or null when every one holds a client.
pub fn freeClient(self: *Node) ?*Served {
    for (self.clients) |*slot| {
        if (!slot.live) return slot;
    }
    return null;
}

/// Which slot this is, for the storage cuts `queuesOf` and `ringOf` make.
pub fn indexOf(self: *const Node, slot: *const Served) usize {
    const at = @intFromPtr(slot) - @intFromPtr(self.clients.ptr);
    return at / @sizeOf(Served);
}

/// How many node ids this relay holds, which is the registry's own answer
/// and not a count kept beside it.
///
/// **Zero for a node that does not serve, and the role is what says so.**
/// `initRelay` builds a registry for a `.serve` and for nothing else, so
/// the table under a `.off` or `.client` node is never initialised at all —
/// reading it would answer from bytes `create` never wrote, which is a
/// different number on every run and under every allocator. Such a node
/// admits nobody, so zero is its count; the switch is the same rule
/// `queueDepth` applies, and like it costs nothing but a read of the role.
pub fn clientCount(self: *const Node) usize {
    return switch (self.config.relay.role) {
        .serve => self.registry.nodeCount(),
        else => 0,
    };
}

/// Give back everything the relay took, for whatever role it took it for.
///
/// Before the bridge goes: a guard reaches into this struct's own registry,
/// and a client slot points at a connection the core frees. The two frame
/// buffers are the other half of `initRelay`'s unconditional pair and are
/// freed whatever the role was, which is what leaves a `.off` node holding
/// no relay storage after this returns.
pub fn freeRelay(self: *Node) void {
    node_relay_release.relayClose(self);
    if (self.spoke) |*spoke| {
        spoke.inbox.deinit(self.gpa);
        for (spoke.delivered.items) |item| self.gpa.free(item.data);
        spoke.delivered.deinit(self.gpa);
    }
    self.spoke = null;
    self.gpa.free(self.relay_out);
    self.gpa.free(self.relay_scratch);
    self.gpa.free(self.ring);
    self.gpa.free(self.messages);
    self.gpa.free(self.packets);
    self.gpa.free(self.clients);
}
