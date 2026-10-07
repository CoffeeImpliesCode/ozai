//! What a converged swarm is, and what a stalled one looked like from inside.
//!
//! These are the questions the assertions are asked and the answers the stall
//! report prints, so they are here rather than in the swarm that produced the
//! state: nothing here moves the mesh a byte, and nothing the swarm does calls
//! any of it except `noteMismatch`, which exists so `report` can name the first
//! contact-data mismatch long after the frame it arrived in is gone.

const std = @import("std");
const ozai = @import("ozai");

const gossip = ozai.gossip_hyparview;

const node_ns = @import("protocol_node.zig");
const swarm = @import("protocol_swarm.zig");
const wire = @import("protocol_wire.zig");

/// One peer's contact data as this node received it, and as that peer
/// advertised it.
pub const Mismatch = struct {
    peer: usize,
    holder: usize,
    got: [gossip.peer_data_max]u8,
    got_len: usize,
    want: [gossip.peer_data_max]u8,
    want_len: usize,
};

pub fn noteMismatch(
    mesh: *swarm.Mesh,
    got: []const u8,
    want: []const u8,
    peer: usize,
    holder: usize,
) void {
    if (mesh.mismatch != null) return;
    var recorded: Mismatch = .{
        .peer = peer,
        .holder = holder,
        .got = [_]u8{0} ** gossip.peer_data_max,
        .got_len = @min(got.len, gossip.peer_data_max),
        .want = [_]u8{0} ** gossip.peer_data_max,
        .want_len = @min(want.len, gossip.peer_data_max),
    };
    @memcpy(recorded.got[0..recorded.got_len], got[0..recorded.got_len]);
    @memcpy(recorded.want[0..recorded.want_len], want[0..recorded.want_len]);
    mesh.mismatch = recorded;
}

// -- the properties the assertions are about -------------------------

/// How many nodes have no neighbour at all. A converged swarm has none,
/// and upstream's bootstrap asserts exactly this.
pub fn peersWithoutNeighbors(mesh: *const swarm.Mesh) usize {
    var count: usize = 0;
    for (&mesh.nodes) |*node| {
        if (node.topic.swarm.activeView().len == 0) count += 1;
    }
    return count;
}

/// Links one end still believes in and the other end does not.
///
/// A healthy converged swarm has none, and this is the number that says so
/// more honestly than "no node is alone". It is not always zero, and
/// `sim.Network.asymmetricLinks` says why: `on_neighbor` takes a `Neighbor`
/// for a reply whenever the sender is in `pending_neighbor_requests`, and a
/// reply is not answered, so an evicted peer can be put back silently.
/// Upstream has the identical code path. What must hold — and what this is
/// for — is that the count does not grow: a swarm that has stopped joining
/// stops disagreeing.
pub fn asymmetricLinks(mesh: *const swarm.Mesh) usize {
    var count: usize = 0;
    for (0..node_ns.max_nodes) |index| {
        for (mesh.nodes[index].topic.swarm.activeView()) |peer| {
            const other = swarm.indexOf(mesh, peer) orelse continue;
            if (holdsNeighbor(mesh, other, mesh.nodes[index].wire.id)) continue;
            count += 1;
        }
    }
    return count;
}

/// Whether the node at `index` lists `id` in its active view.
pub fn holdsNeighbor(mesh: *const swarm.Mesh, index: usize, id: ozai.NodeId) bool {
    for (mesh.nodes[index].topic.swarm.activeView()) |held| {
        if (held.order(id) == .eq) return true;
    }
    return false;
}

/// This node's neighbours as indices, for the report.
pub fn neighbours(mesh: *const swarm.Mesh, index: usize, out: *[node_ns.max_nodes]usize) usize {
    var count: usize = 0;
    for (mesh.nodes[index].topic.swarm.activeView()) |peer| {
        const other = swarm.indexOf(mesh, peer) orelse continue;
        out[count] = other;
        count += 1;
    }
    return count;
}

/// Print what a stall looks like from the inside.
///
/// "Convergence failed" on four nodes that exchanged bytes is not a
/// diagnosis. This is: the node that is alone, the three it *is* adjacent
/// to, every connection's state, the frames each direction moved, and how
/// many teardowns the protocol asked for on the way.
pub fn report(mesh: *swarm.Mesh, reason: []const u8) void {
    std.debug.print("\ngossip wire stalled: {s}\n", .{reason});
    for (0..node_ns.max_nodes) |index| {
        const node = &mesh.nodes[index];
        var found: [node_ns.max_nodes]usize = undefined;
        const count = neighbours(mesh, index, &found);
        std.debug.print(
            "  {s} ({f}) at {f}: {d} datagrams out, {d} in, {d} finished\n",
            .{
                node.wire.name,
                node.wire.id,
                node.wire.socket.address,
                node.stats.out,
                node.stats.in,
                node.stats.finished,
            },
        );
        std.debug.print(
            "    frames {d} written, {d} read; active view {d}/{d}, passive {d}\n",
            .{
                node.frames_written,
                node.frames_read,
                node.topic.swarm.activeView().len,
                node.topic.swarm.config.active_view_capacity,
                node.topic.swarm.passiveView().len,
            },
        );
        std.debug.print(
            "    neighbor up {d}, down {d}; contact data {d}; delivered {d}, duplicate {d}\n",
            .{
                node.neighbor_up,
                node.neighbor_down,
                node.peer_data_seen,
                node.delivered,
                node.duplicated,
            },
        );
        std.debug.print("    adjacent to:", .{});
        for (found[0..count]) |peer| {
            std.debug.print(" {s}", .{mesh.nodes[peer].wire.name});
        }
        if (count == 0) std.debug.print(" nobody — this node is the one left out", .{});
        std.debug.print("\n", .{});
        for (0..node_ns.max_nodes) |peer| {
            const conn = node.connTo(peer, mesh.ports) orelse continue;
            std.debug.print(
                "    conn to {s}: id {d}, state {t}, established {}\n",
                .{
                    mesh.nodes[peer].wire.name,
                    conn.id(),
                    conn.entry.conn.state,
                    conn.established(),
                },
            );
        }
        for (0..node_ns.max_nodes) |peer| {
            if (peer == index) continue;
            std.debug.print(
                "    link to {s}: {d} bytes waiting out, {d} bytes waiting in\n",
                .{
                    mesh.nodes[peer].wire.name,
                    node.outbound[peer].items.len,
                    node.inbound[peer].items.len,
                },
            );
        }
    }
    std.debug.print(
        "  asymmetric links {d}; teardowns asked for {d}; contact-data mismatches {d}; " ++
            "virtual time {d} ms; round bound {d}\n",
        .{
            asymmetricLinks(mesh),
            mesh.teardowns,
            mesh.peer_data_mismatch,
            mesh.now / gossip.nanos_per_milli,
            wire.max_rounds,
        },
    );
    if (mesh.mismatch) |found| {
        var got_hex: [2 * gossip.peer_data_max]u8 = undefined;
        var want_hex: [2 * gossip.peer_data_max]u8 = undefined;
        std.debug.print(
            "  first contact-data mismatch: {s} holds {s} as '{s}', " ++
                "and {s} advertised '{s}'\n",
            .{
                mesh.nodes[found.holder].wire.name,
                mesh.nodes[found.peer].wire.name,
                writeHex(&got_hex, found.got[0..found.got_len]),
                mesh.nodes[found.peer].wire.name,
                writeHex(&want_hex, found.want[0..found.want_len]),
            },
        );
    }
}

/// `bytes` as lower-case hex written into `out`, and the digits it wrote.
///
/// `std.fmt.bytesToHex` takes its width from the type, and this printout's
/// width is a run's answer — how many contact bytes crossed the socket — so
/// it needs the form the format string can bound. `out` must be twice
/// `bytes.len`.
fn writeHex(out: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, at| {
        out[2 * at] = digits[byte >> 4];
        out[2 * at + 1] = digits[byte & 15];
    }
    return out[0 .. 2 * bytes.len];
}
