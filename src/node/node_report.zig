//! Run reports over node data and retained relay deliveries.
const std = @import("std");
const node_mod = @import("node.zig");
const Node = node_mod.Node;
const config = @import("node_config.zig");
const relay_client = @import("node_relay_client.zig");

const inbox_datagrams_printed: usize = 4;
const inbox_bytes_printed: usize = 24;
const closes_acknowledged: u64 = 0;

pub const Holding = struct {
    node_ids: usize,
    connections: usize,
};

pub const Close = struct {
    connections: usize,
    datagrams: u64,
};

pub fn report(
    text: *std.Io.Writer,
    node: *const Node,
    holding: Holding,
    close: Close,
) !void {
    const stats = node.stats;
    try reportRelay(text, node, holding);
    try text.print(
        \\
        \\stopped: {d} passes, {d} datagrams in, {d} out ({d} degraded, {d} codepoints lost)
        \\accept loop: {d} attempts, {d} spawned, {d} routed, {d} handler connections
        \\  {d} refusals, {d} ignores, {d} protocols refused
        \\dials: {d} of {d} refused; {d} connections finished
        \\gossip: {d} events, {d} timers scheduled, {d} fired
        \\  {d} membership and {d} broadcast messages asked for: {d} sent, {d} dropped
        \\  {d} disconnects asked for, {d} acted on; {d} routes dropped
        \\  neighbour up {d}, down {d}; broadcasts received {d}; peer data {d}
        \\shutdown: {t}, {d} handler shutdowns, {d} accepts cancelled, socket {s}
        \\
    , .{
        stats.steps,
        stats.datagrams_in,
        stats.datagrams_out,
        stats.sends_degraded,
        stats.ecn_lost,
        stats.attempts,
        stats.spawned,
        stats.tasks_routed,
        stats.handler_connections,
        stats.refusals,
        stats.ignores,
        stats.protocols_refused,
        stats.dials,
        stats.dials_refused,
        stats.connections_finished,
        stats.gossip_events,
        stats.gossip_timers_scheduled,
        stats.gossip_timers_fired,
        stats.gossip_membership_asked,
        stats.gossip_broadcast_asked,
        stats.gossip_sends_written,
        stats.gossip_sends_dropped,
        stats.gossip_disconnects_asked,
        stats.gossip_disconnects_acted,
        stats.gossip_routes_dropped,
        stats.neighbor_up,
        stats.neighbor_down,
        stats.broadcasts_received,
        stats.peer_data_seen,
        node.accept.shutdown.phase,
        stats.handler_shutdowns,
        stats.accepts_cancelled,
        if (node.socket_open) "still open" else "closed",
    });
    try reportClose(text, close);

    if (node_mod.namedPeers(node).len == 0) return;
    try text.writeAll("gossip named: ");
    for (node_mod.namedPeers(node), 0..) |peer, index| {
        if (index > 0) try text.writeAll(", ");
        try text.print("{f}", .{peer});
    }
    try text.writeAll("\n");
}

fn reportClose(text: *std.Io.Writer, close: Close) !void {
    try text.print(
        "close: {d} connections owed, {d} close datagrams written, " ++
            "{d} acknowledged by any peer\n",
        .{ close.connections, close.datagrams, closes_acknowledged },
    );
}

fn reportRelay(text: *std.Io.Writer, node: *const Node, holding: Holding) !void {
    const stats = node.stats;
    switch (node.config.relay.role) {
        .off => try text.writeAll(
            "relay: none — this node is dialled at its own address\n",
        ),
        .serve => {
            try text.print(
                "relay: serving {d} clients, {d} datagrams deep\n",
                .{ config.max_relay_clients, config.default_relay_queue_depth },
            );
            try text.print(
                "relay in: admitted {d}, replaced {d}, promoted {d}, refused {d}, " ++
                    "deferred {d}, truncated {d}\n",
                .{
                    stats.relay_admitted,
                    stats.relay_replaced,
                    stats.relay_promoted,
                    stats.relay_refused,
                    stats.relay_stream_deferred,
                    stats.relay_stream_truncated,
                },
            );
            try text.print(
                "relay held: node ids {d}, connections up {d}, at the stop\n",
                .{ holding.node_ids, holding.connections },
            );
            try text.print(
                "relay out: read {d}, forwarded {d}, unknown target {d}, " ++
                    "full queue {d}, oversized {d}\n",
                .{
                    stats.relay_datagrams_in,
                    stats.relay_forwarded,
                    stats.relay_unknown_target,
                    stats.relay_queue_full,
                    stats.relay_oversized,
                },
            );
            try text.print(
                "relay away: disconnects {d}, {d} of them displaced earlier, " ++
                    "already gone {d}, told displaced {d}, promoted {d}\n",
                .{
                    stats.relay_disconnects,
                    stats.relay_duplicates,
                    stats.relay_double_reports,
                    stats.relay_told_displaced,
                    stats.relay_promoted,
                },
            );
        },
        .client => |peer| {
            try text.print(
                "relay: client of {f} at {f}\n",
                .{ peer.id, peer.addr },
            );
            try text.print(
                "relay in: dialled {d}, refused {d}, auth sent {d}, established {d}, " ++
                    "displaced {d}, peer gone {d}, truncated {d}\n",
                .{
                    stats.relay_dials,
                    stats.relay_dials_refused,
                    stats.relay_auth_sent,
                    stats.relay_established,
                    stats.relay_displaced,
                    stats.relay_peer_gone,
                    stats.relay_stream_truncated,
                },
            );
            try text.print(
                "relay held: connections up {d}, at the stop\n",
                .{holding.connections},
            );
            try text.print(
                "relay out: sent {d}, handed to this node {d}\n",
                .{ stats.relay_sent, stats.relay_datagrams_out },
            );
            try text.print(
                "relay away: closed by the relay {d}, duplicate reports {d}\n",
                .{ stats.relay_closed, stats.relay_double_reports },
            );
        },
    }
    try reportInbox(text, node);
}

fn reportInbox(text: *std.Io.Writer, node: *const Node) !void {
    const handed = relay_client.delivered(node);
    if (handed.len == 0) return;
    var bytes: usize = 0;
    var cut: usize = 0;
    for (handed) |item| {
        bytes += item.data.len;
        if (item.data.len > inbox_bytes_printed) cut += 1;
    }
    try text.print(
        "relay inbox: datagrams {d}, bytes in all {d}",
        .{ handed.len, bytes },
    );
    if (cut != 0) {
        try text.print(", hex cut to {d} bytes on {d} of them", .{
            inbox_bytes_printed,
            cut,
        });
    }
    try text.writeAll("\n");
    for (handed, 0..) |item, index| {
        if (index == inbox_datagrams_printed) {
            try text.print(
                "relay inbox: {d} more datagrams, not printed\n",
                .{handed.len - index},
            );
            return;
        }
        try text.print(
            "relay inbox[{d}]: bytes {d} from {f} {x}\n",
            .{
                index,
                item.data.len,
                item.src,
                item.data[0..@min(item.data.len, inbox_bytes_printed)],
            },
        );
    }
}
