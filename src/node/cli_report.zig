//! What the run did, and how it ended.
//!
//! Every line is a number a caller of `Node` could not get any other way, or a
//! statement about a limit this program will not cross: the gossip codec that
//! does not exist, and the closes no peer acknowledges. The counters that stop
//! at a count are printed next to what they would have been, so the gap is
//! visible rather than inferred from an absence of traffic.

const std = @import("std");

const ozai = @import("ozai");

const node_mod = ozai.node;
const Node = node_mod.Node;

/// How many datagrams a report prints, and how many bytes of each.
///
/// A datagram is up to `Node.max_datagram` bytes and a report is read by a
/// person and by a test, so the bytes are hexed and cut: enough to see that
/// the payload arrived, and a count of what was not shown.
const inbox_datagrams_printed: usize = 4;
const inbox_bytes_printed: usize = 24;

/// How many of this node's closes a peer acknowledged: none, ever.
///
/// **A constant, and printed rather than assumed**, because it is the finding
/// and not a counter — CONNECTION_CLOSE is not ack-eliciting (RFC 9000 §19.3),
/// so a peer never ACKs one and the best it can do is go quiet. A report that
/// counted acknowledgements without saying there are none would read as though
/// the number could move. See `reportClose`.
const closes_acknowledged: u64 = 0;

/// What the relay was still holding when this node was asked to stop.
///
/// Read before the close and printed after it, because the two ends of a run
/// answer different questions. By the time a report is written this node's own
/// shutdown has given every client and every connection away, so a count read
/// then is the same for a peer that left while this node was running and for
/// one that was still there. Read here they differ, and that difference is the
/// only thing a caller on the other side of a pipe can use to say that a
/// survivor noticed.
pub const Holding = struct {
    /// Node ids in this relay's registry: its clients, or none for a node that
    /// is not one.
    node_ids: usize,
    /// Connections the core still held, whoever opened them.
    connections: usize,
};

/// What the shutdown owed a peer, and what it wrote for it.
///
/// Measured either side of `Node.close` rather than asked of the node
/// afterwards, because a close is the one thing the node does that leaves no
/// counter of its own: it is a drain on the way out and not a pass, so the
/// difference in the report's own `datagrams out` is the whole of what it put
/// on the wire.
pub const Close = struct {
    /// Connections the shutdown still owed a CONNECTION_CLOSE, read with
    /// `Node.establishedCount` before the close. **Zero here does not mean
    /// the core held nothing**: a connection the core has already given up is
    /// one with nothing left to say, so it is not counted and its close wrote
    /// no datagram either. That is why these two numbers read zero together.
    connections: usize,
    /// Datagrams written for them. At least one apiece, and more for a
    /// connection still handshaking, which the core tells at every encryption
    /// level it holds rather than only the one it would prefer.
    datagrams: u64,
};

/// What the run did, and how it ended.
///
/// Every line here is a number a caller of `Node` could not get any other way,
/// and the two counters that stop at a count are printed next to what they
/// would have been had the codec existed — so the gap is visible rather than
/// inferred from the absence of traffic.
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
        \\accept loop: {d} attempts, {d} spawned, {d} handler connections
        \\  {d} refusals, {d} ignores
        \\dials: {d} of {d} refused; {d} connections finished
        \\gossip: {d} events, {d} timers scheduled, {d} fired
        \\  {d} membership and {d} broadcast messages asked for and not sent
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
        stats.handler_connections,
        stats.refusals,
        stats.ignores,
        stats.dials,
        stats.dials_refused,
        stats.connections_finished,
        stats.gossip_events,
        stats.gossip_timers_scheduled,
        stats.gossip_timers_fired,
        stats.gossip_membership_asked,
        stats.gossip_broadcast_asked,
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

    if (node.namedPeers().len == 0) return;
    try text.writeAll("gossip named: ");
    for (node.namedPeers(), 0..) |peer, index| {
        if (index > 0) try text.writeAll(", ");
        try text.print("{f}", .{peer});
    }
    try text.writeAll("\n");
}

/// What the shutdown wrote, and the answer it will never be given.
///
/// The three numbers are the loss's whole extent and the only truth available
/// about it: what was owed a close, what was written for it, and what came
/// back — which is nothing, because nothing comes back. All three are printed
/// at zero as well, because a node with nothing to tell and a node whose close
/// may never have landed are different reports, and the one that printed
/// nothing at all is how a reader would have to guess which it was.
fn reportClose(text: *std.Io.Writer, close: Close) !void {
    try text.print(
        "close: {d} connections owed, {d} close datagrams written, " ++
            "{d} acknowledged by any peer\n",
        .{ close.connections, close.datagrams, closes_acknowledged },
    );
}

/// What the relay did, and what of it was still standing at the stop.
///
/// The role is the first line and it is printed for every node, because a node
/// that cannot relay and a node that relayed nothing are told apart by that
/// line and not by the absence of traffic under it. The rest is the role's own
/// counters, and a node that is not a relay has none of them to print.
///
/// **Every count carries its own name before it**, which is what the rest of
/// this report does and what a reader of one expects: "refused 0" is a refusal
/// that did not happen, and "0 refused" is the same fact with the words on the
/// wrong side of the number. It is also what lets a caller that is not a person
/// — `test/two_process_test.zig` reads these lines by label — ask for one
/// counter without counting the ones in front of it.
///
/// A client's line says the socket its URL resolved to, and the banner said
/// the URL: the two are printed from the two places that own them because a
/// report showing only one of them would be half an address.
fn reportRelay(text: *std.Io.Writer, node: *const Node, holding: Holding) !void {
    const stats = node.stats;
    switch (node.config.relay.role) {
        .off => try text.writeAll(
            "relay: none — this node is dialled at its own address\n",
        ),
        .serve => {
            try text.print(
                "relay: serving {d} clients, {d} datagrams deep\n",
                .{ node_mod.max_relay_clients, node_mod.default_relay_queue_depth },
            );
            try text.print(
                "relay in: admitted {d}, replaced {d}, promoted {d}, refused {d}, " ++
                    "deferred {d}\n",
                .{
                    stats.relay_admitted,
                    stats.relay_replaced,
                    stats.relay_promoted,
                    stats.relay_refused,
                    stats.relay_stream_deferred,
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
                "relay away: disconnects {d}, already gone {d}, told displaced {d}, " ++
                    "promoted {d}\n",
                .{
                    stats.relay_disconnects,
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
                    "displaced {d}, peer gone {d}\n",
                .{
                    stats.relay_dials,
                    stats.relay_dials_refused,
                    stats.relay_auth_sent,
                    stats.relay_established,
                    stats.relay_displaced,
                    stats.relay_peer_gone,
                },
            );
            // The connections, and not a registry: a client has none, so
            // `Holding` carries a zero for it that this line does not print.
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

/// What this node's relay handed back, oldest first.
///
/// The payloads are hexed and cut: a datagram is up to `Node.max_datagram`
/// bytes, and a report is read by a person and by a test, and both want the
/// first bytes and the length rather than the whole thing. A node that was
/// handed nothing prints nothing here — the count above already says zero —
/// and a node that was handed more than `inbox_datagrams_printed` says how
/// many it did not print, because a count that stops is a lie about the rest.
fn reportInbox(text: *std.Io.Writer, node: *const Node) !void {
    const handed = node.delivered();
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
