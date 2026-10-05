//! The serving half of the relay: which role this node runs, and the admission
//! of a client into it.
//!
//! `relay` is the one switch on the role a node was built with, and `serve` is
//! a serving relay's pass in the order its own work is ordered. The rest of
//! this file is getting a client *in*: take a slot, open the stream the relay
//! speaks on, run the handshake, and put the proved node id in the registry.
//! What the relay then does for that client is `node_relay_forward.zig`, and
//! ending it is `node_relay_release.zig`.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_relay_client = @import("node_relay_client.zig");
const node_relay_frame = @import("node_relay_frame.zig");
const node_relay_forward = @import("node_relay_forward.zig");
const node_relay_release = @import("node_relay_release.zig");
const node_relay_table = @import("node_relay_table.zig");
const node_transport = @import("node_transport.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_server = @import("../relay/server.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const Instant = bridge_mod.Instant;
const Served = node_relay_table.Served;

/// One turn of the relay.
///
/// Two roles and nothing else. Upstream's relay is a process and its client
/// is a library call, and the difference between them is which half of one
/// handshake a node runs. `.off` is every other node and touches nothing.
///
/// Where this sits in `step` is `node.zig`'s module doc's subject and the reason
/// for every ordering inside it: the accept path a relay uses is the one
/// `node.zig` already had, and none of it comes from a dial.
pub fn relay(self: *Node, at: Instant, random: std.Random) Error!bool {
    return switch (self.config.relay.role) {
        .off => false,
        .serve => try serve(self, at, random),
        .client => try node_relay_client.converse(self, at, random),
    };
}

/// A serving relay's pass, in the order its own work is ordered.
pub fn serve(self: *Node, at: Instant, random: std.Random) Error!bool {
    const role = switch (self.config.relay.role) {
        .serve => |role| role,
        else => return false,
    };
    // A relay that is winding down admits nobody. Without this the
    // shutdown's own passes would re-admit the connections the next phase
    // is about to close, and every one of those would be reported as a
    // client arriving after the relay had already said it was going.
    if (self.accept.shutdown.phase != .serving) return false;
    var moved = try serveAdmit(self, at, random);
    moved = node_relay_release.serveRelease(self) or moved;
    moved = try node_relay_forward.serveRead(self) or moved;
    moved = try node_relay_forward.serveQueues(self, role.drain_room) or moved;
    return moved;
}

/// Give every accepted connection the relay has not been told about a
/// client, and start its handshake.
///
/// The credential offered is `.none`, and that is not a shortcut. This
/// transport has no TLS exporter for a peer whose certificate is a bare
/// ed25519 key, so `relay/server.zig`'s key-material path cannot be taken
/// and the challenge is the only way in — which is upstream's browser path,
/// reached here for the same reason it is the honest one.
///
/// **The challenge comes from `random`**, the generator this node is being
/// driven with, and not from `Io.randomSecure`. A node that drew one
/// admission challenge differently from the last could not be driven twice
/// and compared, and that is the property this whole loop is built for.
/// What it costs is real and is not hidden: a relay serving clients it has
/// not met seeds its engine from `Io.randomSecure` when it is created, and
/// a relay whose seed is known admits anyone who can guess it.
pub fn serveAdmit(self: *Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        // Server-side only, and established: this is the accept path, so a
        // connection this node asked for is never a client of it.
        if (!conn.entry.conn.is_server) continue;
        if (!conn.established()) continue;
        if (node_relay_table.servedFor(self, conn.id()) != null) continue;
        // The relay opens the stream it speaks on and reads the one the
        // client opened. See `Served.out` for why they are two.
        //
        // **The slot is taken before the stream is opened, and that order
        // is what the refusal below survives on.** The core keeps every
        // stream this end opens in `conn.streams` (`stream.zig:1396-1404`)
        // and counts it against the peer's `initial_max_streams_bidi`
        // (`stream.zig:1387`). A credit comes back only from a stream whose
        // receive side the peer has closed (`connection.zig:2940-2946`),
        // and a stream opened for a client this relay then refuses is one
        // nothing will ever close. It is spent for good, and once a
        // connection has spent its peer's whole grant — a hundred
        // (`connection.zig:539`) — it refuses every open for the rest of
        // its life, with nothing but this arm's own counter to say so.
        // Asking for the slot first makes that unreachable: a stream is
        // opened exactly when there is somewhere to put it, so the open
        // streams and the occupied slots are one count and neither can
        // outrun the other.
        //
        // **A refusal that still arrives costs this connection and not the
        // pass.** The peer granted less than this end has used, and
        // `MAX_STREAMS` raises that grant (`connection.zig:2146`), so a
        // later pass gets a different answer. Failing the pass would take
        // down every *other* connection in the table over one that is out
        // of credit, and a relay that stopped serving for that would not
        // be a relay.
        //
        // Everything else is `error.CoreRefused` — an allocator that will
        // not make the core's send ledger above all — and it is propagated
        // rather than caught, because that is a fault in *this node* and a
        // relay that swallowed it would go on serving as though it had
        // admitted a client it never admitted. The split is the whole of
        // this arm; `error.NoStreamRoom` is named for it.
        const slot = node_relay_table.freeClient(self) orelse {
            // Upstream refuses rather than drops, for the reason
            // `endpoint.zig` gives: an attempt accepted and then held
            // nowhere is a client that believes it is connected.
            self.stats.relay_refused += 1;
            continue;
        };
        const stream = bridge_mod.Stream.open(conn) catch |err| switch (err) {
            error.NoStreamRoom => {
                self.stats.relay_stream_deferred += 1;
                continue;
            },
            else => return err,
        };
        const owned = node_relay_table.indexOf(self, slot);
        slot.* = .{
            .live = true,
            .conn = conn.id(),
            .queues = node_relay_table.queuesOf(self, owned),
            .ring = node_relay_table.ringOf(self, owned),
            .out = stream,
        };
        var challenge: [relay_frame.ServerChallenge.challenge_length]u8 = undefined;
        random.bytes(&challenge);
        _ = try serveHandshake(self, at, slot, .{ .offered = .{
            .credential = .none,
            .material = null,
            .challenge = .{ .challenge = challenge },
        } });
        moved = true;
    }
    return moved;
}

/// Run one client's handshake as far as that event lets it, and register
/// it if the handshake is over.
pub fn serveHandshake(
    self: *Node,
    at: Instant,
    slot: *Served,
    event: relay_server.Event,
) Error!bool {
    const stepped = relay_server.step(slot.handshake, event);
    slot.handshake = stepped.state;
    // Access control is this node's own answer and there is none to ask.
    // `.allow` means "the client proved it owns the node id it claims",
    // which is what the challenge's signature says; `Access` exists so an
    // operator can narrow that, and this node has no configuration field
    // for one yet. Named here rather than invented.
    const proved = switch (slot.handshake) {
        .authenticated => true,
        else => false,
    };
    if (proved) {
        const allowed = relay_server.step(slot.handshake, .{ .access = .allow });
        slot.handshake = allowed.state;
        _ = try serveAction(self, at, slot, allowed.action);
        serveRegister(self, slot);
        return true;
    }
    const served = try serveAction(self, at, slot, stepped.action);
    return served;
}

/// Write the one thing a relay handshake step asked for.
pub fn serveAction(
    self: *Node,
    at: Instant,
    slot: *Served,
    action: ?relay_server.Action,
) Error!bool {
    const asked = action orelse return false;
    switch (asked) {
        .write => |message| {
            var stream: bridge_mod.Stream = slot.out;
            try node_relay_frame.writeRelay(&stream, self.relay_out, message);
            return true;
        },
        // Upstream drops the connection without writing. The connection is
        // closed at the core instead, which is what drops it: the relay
        // protocol's silence is the signal, and a CONNECTION_CLOSE is how
        // a QUIC peer is told there will be none.
        .close => {
            slot.ended = true;
            if (node_transport.connFor(self, slot.conn)) |conn| conn.entry.conn.close(0, "", at);
            return true;
        },
    }
}

/// Put an authenticated client in the registry and take the handle that
/// ends it.
///
/// `Registry.admit` is the only way into the table and it hands the handle
/// back, so a client cannot be admitted without one. That is invariant 10
/// restated as a type, and it is why the guard is stored here and nowhere
/// else.
pub fn serveRegister(self: *Node, slot: *Served) void {
    const proof = switch (slot.handshake) {
        .admitted => |proof| proof,
        else => return,
    };
    slot.node_id = proof.node_id;
    const admitted = self.registry.admit(proof.node_id, slot.conn) catch |err| {
        // A registry with no slot left is a relay that has to shed
        // connections, and this is where it finds out.
        std.log.warn("node: the relay could not admit a client: {t}", .{err});
        self.stats.relay_refused += 1;
        return;
    };
    slot.guard = admitted.guard;
    self.stats.relay_admitted += 1;
    const replaced = switch (admitted.admit) {
        .fresh => return,
        .replaced => |id| id,
    };
    self.stats.relay_replaced += 1;
    // The displaced connection is told over its *control* queue, and that
    // is the whole reason there are two: a client whose datagram queue is
    // full is exactly the client that most needs to be told.
    const other = node_relay_table.servedFor(self, replaced) orelse return;
    other.queues.control.push(.{ .status = .same_endpoint_id_connected }) catch {
        self.stats.relay_queue_full += 1;
        return;
    };
    self.stats.relay_told_displaced += 1;
}
