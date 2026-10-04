//! A serving relay's admission walk, and the handshake machine behind it.
//!
//! **The pass driver is here because admission is where a serving pass
//! begins.** `serve` spends slots on the connections that negotiated the relay
//! ALPN, hands back the slots whose connections the core has let go of, and
//! then calls the read and the queue drain — the last two in
//! `node_relay_serve_read.zig` and `node_relay_serve.zig`, neither of which can
//! do anything without a slot. That is the whole of the boundary: what a pass
//! walks before a client exists, and the client it admits is then read for.
//!
//! `Client` is declared here because a handshake is what a client slot is for.
//! The other two halves of the pass take the same slot, and they name it
//! through this declaration rather than each repeating the instantiation.

const std = @import("std");
const node_mod = @import("node.zig");
const config = @import("node_config.zig");
const Error = @import("node_error.zig").Error;
const framing = @import("node_framing.zig");
const node_protocol = @import("node_protocol.zig");
const client = @import("node_relay_client.zig");
const registry = @import("node_relay_registry.zig");
const relay_state = @import("relay_state.zig");
const relay_read = @import("node_relay_serve_read.zig");
const relay_serve = @import("node_relay_serve.zig");
const relay_server = @import("../relay/server_handshake.zig");
const relay_frame = @import("../relay/frame_types.zig");
const quic_stream = @import("../transport/quic_stream.zig");

const Instant = @import("../transport/quic_conn.zig").Instant;

// ziglint mistakes `.client_type` for a value despite the explicit type annotation.
// ziglint-ignore: Z006
pub const Client: type = relay_state.State(
    config.relay_table_slots,
    config.relay_displaced,
).client_type;

pub fn serve(self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    const role = switch (self.config.relay.role) {
        .serve => |role| role,
        else => return false,
    };
    // Shutdown passes must not re-admit connections they are about to close.
    if (self.accept.shutdown.phase != .serving) return false;
    var moved = try serveAdmit(self, at, random);
    moved = registry.serveRelease(self) or moved;
    moved = try relay_read.serveRead(self, at) or moved;
    moved = try relay_serve.serveQueues(self, role.drain_room) or moved;
    return moved;
}

pub fn serveAdmit(self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        if (!conn.established()) continue;
        // A relay client is a peer that negotiated the relay ALPN; another
        // protocol on this node spends no slot and is sent no challenge, and
        // `Config.protocols` may hold more than one.
        //
        // **And a peer that negotiated nothing at all is not one of those.**
        // RFC 7301 §3.2's `no_application_protocol` is the core refusing an
        // empty intersection of an offer that *was* made
        // (`vendor/quic/src/quic/tls13.zig:3169-3178`), and it lives inside
        // the ALPN extension's parse — a ClientHello advertising no protocol
        // never reaches that walk at all (`tls13.zig:3100-3114`), so such a
        // handshake completes and carries on (`tls13.zig:2304-2310`).
        // `Connection.negotiatedAlpn` answers such a peer with
        // `Config.protocols[0]`, so asking it would compare this node's own
        // first configured protocol against a peer that named none — one
        // answer standing in for two questions. `Conn.negotiatedAlpn` is the
        // question that can be asked: it reads the handshake's own selection
        // and answers null when there was none (see
        // `src/transport/quic_conn.zig`). Null is the refusal, and it is this
        // walk's own skip: no slot, no stream, nothing written.
        const alpn = conn.negotiatedAlpn() orelse continue;
        if (!std.mem.eql(u8, alpn, node_protocol.relay_alpn)) continue;
        if (self.relay_state.servedFor(conn.id()) != null) continue;
        // Acquire storage before spending bidi credit; only peer credit is deferred.
        const slot = self.relay_state.freeClient() orelse {
            self.stats.relay_refused += 1;
            continue;
        };
        const stream = quic_stream.openBidi(conn.entry.conn) catch |err| switch (err) {
            error.NoStreamRoom => {
                self.stats.relay_stream_deferred += 1;
                continue;
            },
            else => return err,
        };
        const owned = self.relay_state.indexOf(slot);
        slot.* = .{
            .live = true,
            .conn = conn.id(),
            .queues = self.relay_state.queuesOf(client.queueDepth(self), owned),
            .ring = self.relay_state.ringOf(client.queueDepth(self), config.max_datagram, owned),
            .out = stream,
        };
        // No exporter exists for the bare-key certificate: use the injected CSPRNG challenge.
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

pub fn serveHandshake(
    self: *node_mod.Node,
    at: Instant,
    slot: *Client,
    event: relay_server.Event,
) Error!bool {
    const stepped = relay_server.step(slot.handshake, event);
    slot.handshake = stepped.state;
    // Access is allowed only after the handshake proves ownership of the claimed node id.
    const proved = switch (slot.handshake) {
        .authenticated => true,
        else => false,
    };
    if (proved) {
        const allowed = relay_server.step(slot.handshake, .{ .access = .allow });
        slot.handshake = allowed.state;
        _ = try serveAction(self, at, slot, allowed.action);
        registry.serveRegister(self, slot);
        return true;
    }
    const served = try serveAction(self, at, slot, stepped.action);
    return served;
}

pub fn serveAction(
    self: *node_mod.Node,
    at: Instant,
    slot: *Client,
    action: ?relay_server.Action,
) Error!bool {
    const asked = action orelse return false;
    switch (asked) {
        .write => |message| {
            var stream: quic_stream.Stream = slot.out;
            try framing.writeRelay(&stream, self.relay_state.out, message);
            return true;
        },
        .close => {
            if (node_mod.connFor(self, slot.conn)) |conn| conn.close(0, "", at);
            return true;
        },
    }
}
