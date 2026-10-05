//! A swarm of endpoints, each one dialling every peer with a higher index, and
//! the round that drives it.
//!
//! Six connections for four nodes, and every pair has exactly one connection
//! with the lower index as the client. One round is the clock, the kernel on
//! every socket, the protocol on every stream, and the timers that came due —
//! and everything this module does with what those produced is handing it to a
//! node's state machine and dispatching what the state machine asked for.
//!
//! The two things it deliberately does not do are the two halves that were
//! never its: what a link's bytes are (`readStream`, `flushStream`,
//! `drainFrames`, in `protocol_node.zig`, because they move one node's queues)
//! and how the run's outcome is read (`asymmetricLinks`, `report`, in
//! `protocol_properties.zig`, because they are what the assertions are about).

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;

const codec = @import("protocol_codec.zig");
const node_ns = @import("protocol_node.zig");
const props = @import("protocol_properties.zig");
const wire = @import("protocol_wire.zig");

const NodeId = ozai.NodeId;

/// The ALPN both ends of a gossip link speak. Upstream's is
/// `b"/iroh-gossip/1"`; the gossip module carries no ALPN of its own, and this
/// is the one `docs/PLAN.md` names at M9.
pub const gossip_alpn = "/iroh-gossip/1";

/// A swarm of endpoints, each one dialling every peer with a higher index.
///
/// Six connections for four nodes, and every pair has exactly one connection
/// with the lower index as the client.
pub const Mesh = struct {
    nodes: [node_ns.max_nodes]node_ns.Node,
    ports: [node_ns.max_nodes]u16,
    now: gossip.Nanos = wire.start_ns,
    /// The codec's scratch, and the one decoded frame at a time.
    codec: []u8,
    frame: []u8,
    wire_out: []u8,
    /// Peers a `disconnect_peer` named, delivered at the end of the round that
    /// produced them.
    disconnects: [node_ns.max_nodes]std.ArrayList(NodeId),
    teardowns: usize = 0,
    peer_data_mismatch: usize = 0,
    /// The first contact-data mismatch, copied out so the report can print it
    /// long after the frame it arrived in is gone. `null` until one happens.
    mismatch: ?props.Mismatch = null,

    /// Build the mesh: `n` nodes, the codec and the wire scratch they share.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn init(mesh: *Mesh, seed: u64) !void {
        mesh.* = .{
            .nodes = undefined,
            .ports = [_]u16{0} ** node_ns.max_nodes,
            .codec = undefined,
            .frame = undefined,
            .wire_out = undefined,
            .disconnects = [_]std.ArrayList(NodeId){.empty} ** node_ns.max_nodes,
        };
        errdefer for (&mesh.disconnects) |*queue| queue.deinit(t.allocator);
        // Short intervals, so the `shuffle` and `pending_neighbor_request`
        // paths are on the wire inside the round bound rather than sitting on
        // a timer the run never reaches. Nothing else about the config moves:
        // the capacity is the upstream default and the walk lengths are the
        // paper's.
        const config: gossip.TopicConfig = .{
            .membership = .{
                .shuffle_interval = 12 * gossip.nanos_per_milli,
                .neighbor_request_timeout = 4 * gossip.nanos_per_milli,
            },
        };
        var rng = gossip.Rng.init(seed);
        var live: usize = 0;
        errdefer for (mesh.nodes[0..live]) |*node| node.deinit();
        for (0..node_ns.max_nodes) |index| {
            // `live` after the `try`, not before it: a node whose `init`
            // refused has already unwound itself, and counting it here would
            // tear down a struct it never finished building.
            try mesh.nodes[index].init(index, gossip_alpn, rng.child(), config, seed + index);
            live = index + 1;
            mesh.ports[index] = mesh.nodes[index].wire.socket.address.port;
        }
        mesh.codec = try t.allocator.alloc(u8, codec.codec_room);
        errdefer t.allocator.free(mesh.codec);
        mesh.frame = try t.allocator.alloc(u8, codec.max_frame);
        errdefer t.allocator.free(mesh.frame);
        mesh.wire_out = try t.allocator.alloc(u8, codec.codec_room);
    }

    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn deinit(mesh: *Mesh) void {
        for (&mesh.disconnects) |*queue| queue.deinit(t.allocator);
        for (&mesh.nodes) |*node| node.deinit();
        // Allocation order, then unwind order: `codec`, `frame`, `wire_out`.
        t.allocator.free(mesh.codec);
        t.allocator.free(mesh.frame);
        t.allocator.free(mesh.wire_out);
        mesh.* = undefined;
    }

    /// Dial every peer with a higher index, each with its own pin.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn dialAll(mesh: *Mesh) !void {
        for (0..node_ns.max_nodes) |index| {
            const node = &mesh.nodes[index];
            for (index + 1..node_ns.max_nodes) |peer| {
                const target = &mesh.nodes[peer];
                const dialed = (try node.wire.dialer.dial(
                    .{ .ip = target.wire.socket.address },
                    target.wire.id,
                    node.wire.socket.address,
                    &node.wire.map,
                    @intCast(mesh.now),
                    node.wire.random(),
                )).conn;
                node.dialled[peer] = dialed;
            }
        }
    }

    /// One round: the clock, the kernel on every socket, the protocol on every
    /// stream, and the timers that came due.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn round(mesh: *Mesh) !bool {
        mesh.now += wire.time_quantum;
        const at: wire.Instant = @intCast(mesh.now);
        var moved = false;
        for (&mesh.nodes) |*node| {
            if (try node.wire.exchange(at, &node.stats)) moved = true;
        }
        if (try mesh.protocol()) moved = true;
        if (try mesh.fireTimers()) moved = true;
        return moved;
    }

    /// Move gossip: frame what arrived on each stream, hand it to the state
    /// machine, and put what the state machine asked for on the wire.
    fn protocol(mesh: *Mesh) !bool {
        var moved = false;
        for (0..node_ns.max_nodes) |index| {
            const node = &mesh.nodes[index];
            for (0..node_ns.max_nodes) |peer| {
                if (peer == index) continue;
                if (try node_ns.readStream(mesh, node, peer)) moved = true;
                if (try node_ns.flushStream(mesh, node, peer)) moved = true;
            }
        }
        // The `peer_disconnected` events membership asked for. See the module
        // doc: the reference's message path ignores its link table, so keeping
        // the descriptor and delivering the event is the faithful port.
        for (0..node_ns.max_nodes) |index| {
            for (mesh.disconnects[index].items) |peer| {
                moved = true;
                try feed(mesh, &mesh.nodes[index], .{
                    .peer_disconnected = peer,
                }, index);
            }
            mesh.disconnects[index].clearRetainingCapacity();
        }
        return moved;
    }

    /// Fire every timer that has come due, in the order it was asked for.
    fn fireTimers(mesh: *Mesh) !bool {
        var moved = false;
        for (0..node_ns.max_nodes) |index| {
            const node = &mesh.nodes[index];
            var position: usize = 0;
            while (position < node.timers.items.len) {
                if (node.timers.items[position].due > mesh.now) {
                    position += 1;
                    continue;
                }
                const due = node.timers.orderedRemove(position);
                moved = true;
                feed(mesh, node, .{ .timer_expired = due.timer }, index) catch |err| {
                    std.debug.print(
                        "\n  {s} refused a timer it had asked for: {t}\n",
                        .{ node.wire.name, err },
                    );
                    return err;
                };
            }
        }
        return moved;
    }
};

/// Hand one event to a node's state machine and dispatch what it asks for.
pub fn feed(mesh: *Mesh, node: *node_ns.Node, event: gossip.InEvent, self_index: usize) !void {
    var out: gossip.Actions(gossip.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try node.topic.handle(event, mesh.now, &out);
    try dispatch(mesh, node, out.slice(), self_index);
}

pub fn dispatch(
    mesh: *Mesh,
    node: *node_ns.Node,
    events: []const gossip.OutEvent,
    self_index: usize,
) !void {
    for (events) |produced| switch (produced) {
        .send_message => |send| {
            const peer = indexOf(mesh, send.to) orelse continue;
            if (peer == self_index) continue;
            // Framed through one shared buffer and then copied into the
            // link's queue: the queue's spare capacity is zero on the
            // first send, and a frame that outlives its encode buffer
            // would be a frame pointing at the next message's bytes.
            const frame = try codec.encodeFrame(send.message, mesh.codec, mesh.wire_out);
            try node.outbound[peer].appendSlice(t.allocator, frame);
        },
        .schedule_timer => |schedule| try node.timers.append(t.allocator, .{
            .due = mesh.now + schedule.after,
            .timer = schedule.timer,
        }),
        .disconnect_peer => |peer| {
            mesh.teardowns += 1;
            try mesh.disconnects[self_index].append(t.allocator, peer);
        },
        .emit_event => |reported| switch (reported) {
            .neighbor_up => node.neighbor_up += 1,
            .neighbor_down => node.neighbor_down += 1,
            .received => |got| noteDelivery(node, got.content),
        },
        .peer_data => |data| {
            node.peer_data_seen += 1;
            const peer = indexOf(mesh, data.peer) orelse continue;
            // Compared against what the peer advertised, not against what
            // this node already held: a codec that dropped or reordered
            // the contact data is a finding, and this is where it shows.
            if (std.mem.eql(u8, data.data, mesh.nodes[peer].advert)) continue;
            mesh.peer_data_mismatch += 1;
            props.noteMismatch(mesh, data.data, mesh.nodes[peer].advert, peer, self_index);
        },
    };
}

/// Record one delivery, and whether it is the second of the same payload.
///
/// The content is copied out of the frame it arrived in, because the borrow
/// dies with the frame and the duplicate check has to outlive it.
fn noteDelivery(node: *node_ns.Node, content: []const u8) void {
    if (node.delivered_len == 0) {
        const held = @min(content.len, node.delivered_content.len);
        @memcpy(node.delivered_content[0..held], content[0..held]);
        node.delivered_len = content.len;
        node.delivered = 1;
        return;
    }
    const held = @min(content.len, node.delivered_len);
    if (std.mem.eql(u8, content[0..held], node.delivered_content[0..held])) {
        node.duplicated += 1;
        return;
    }
    // A second, different payload: the deduplication table let it through,
    // which is the one thing it exists to prevent.
    node.duplicated += 1;
}

/// Which node this `NodeId` is, by the identity each one presents.
pub fn indexOf(mesh: *const Mesh, id: NodeId) ?usize {
    for (0..node_ns.max_nodes) |index| {
        if (mesh.nodes[index].wire.id.order(id) == .eq) return index;
    }
    return null;
}
