//! The datagram half of a serving relay: the frames a client sends once its
//! handshake is over, and the queues this relay drains for its own clients.
//!
//! **The pass driver is not here.** `node_relay_serve_admit.zig` owns `serve`,
//! because a serving pass begins by admitting connections and this file has
//! nothing to reach until it has admitted some; the read that fills the inbox
//! is `node_relay_serve_read.zig`. This file is the reason both of them exist.

const node_mod = @import("node.zig");
const config = @import("node_config.zig");
const Error = @import("node_error.zig").Error;
const framing = @import("node_framing.zig");
const relay_admit = @import("node_relay_serve_admit.zig");
const relay_read = @import("node_relay_serve_read.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_codec = @import("../relay/frame_codec.zig");
const quic_stream = @import("../transport/quic_stream.zig");

const Instant = @import("../transport/quic_conn.zig").Instant;

const Client = relay_admit.Client;

pub fn serveMessages(self: *node_mod.Node, at: Instant, slot: *Client) Error!bool {
    var moved = false;
    var consumed: usize = 0;
    // A failed decode still spends its complete frame and every already-served frame.
    errdefer framing.dropInbox(&slot.inbox, consumed);
    while (try framing.peekFrame(slot.inbox.items, consumed, self.relay_state.scratch)) |found| {
        consumed = found.end;
        const message = try relay_codec.decode(found.frame, .v2);
        try serveMessage(self, at, slot, message);
        moved = true;
    }
    framing.dropInbox(&slot.inbox, consumed);
    return moved;
}

pub fn serveMessage(
    self: *node_mod.Node,
    at: Instant,
    slot: *Client,
    message: relay_frame.Message,
) Error!void {
    // After admission, connection frames no longer belong to the handshake machine.
    switch (slot.handshake) {
        .opened, .challenged => {
            _ = try relay_admit.serveHandshake(self, at, slot, .{ .frame = message });
            return;
        },
        else => {},
    }
    // **The read above cannot decide this frame, and this is the other half of
    // the gate that can.** `serveRead` fills the inbox before a byte of it is
    // decoded, so a client that puts a refusal and a datagram in one run of
    // bytes is refused and served in the same pass — and the frame behind the
    // refusal is offered to a handshake that has already ended. Nothing a
    // client sends after its handshake is over is counted, forwarded or answered.
    if (relay_read.handshakeEnded(slot)) return;
    switch (message) {
        .client_to_relay_datagram, .client_to_relay_datagram_batch => |frame| {
            self.stats.relay_datagrams_in += 1;
            try forward(self, slot, frame);
        },
        .ping => |data| {
            var out: quic_stream.Stream = slot.out;
            try framing.writeRelay(&out, self.relay_state.out, .{ .pong = data });
        },
        else => {},
    }
}

pub fn forward(self: *node_mod.Node, from: *Client, frame: relay_frame.DatagramFrame) Error!void {
    const src = from.node_id orelse return;
    const payload = frame.datagrams.contents;
    const destination = self.relay_state.registry.activeConnectionId(frame.node_id);
    if (destination == null) {
        from.queues.control.push(.{ .peer_gone = frame.node_id }) catch {
            self.stats.relay_queue_full += 1;
            return;
        };
        self.stats.relay_unknown_target += 1;
        return;
    }
    const to = self.relay_state.servedFor(destination.?) orelse return;
    if (payload.len > config.max_datagram) {
        self.stats.relay_oversized += 1;
        return;
    }
    if (to.queues.data.isFull()) {
        self.stats.relay_queue_full += 1;
        return;
    }
    // Queue and payload ring use the same position; popping releases the borrowed packet.
    const depth = to.queues.data.capacity();
    const at = (to.queues.data.head + to.queues.data.count) % depth;
    const bytes = to.ring[at * config.max_datagram ..][0..payload.len];
    @memcpy(bytes, payload);
    to.queues.data.push(.{ .src = src, .data = bytes }) catch {
        self.stats.relay_queue_full += 1;
        return;
    };
    self.stats.relay_forwarded += 1;
}

pub fn serveQueues(self: *node_mod.Node, drain_room: usize) Error!bool {
    var moved = false;
    var room = drain_room;
    for (self.relay_state.clients) |*slot| {
        if (!slot.live) continue;
        var stream: quic_stream.Stream = slot.out;
        // Control traffic precedes data under the same pass-wide write budget.
        // A popped frame that fails to write is lost: the pop happens before
        // the `try`, so there is no errdefer-handed requeue as the serve-side
        // inbox drop has. Moved verbatim from the pre-split module; the split
        // did not change this, and it is recorded here rather than repaired.
        while (room > 0) {
            const control = slot.queues.control.pop() orelse break;
            try framing.writeRelay(&stream, self.relay_state.out, framing.controlFrame(control));
            moved = true;
            room -= 1;
        }
        while (room > 0) {
            const packet = slot.queues.data.pop() orelse break;
            try framing.writeRelay(&stream, self.relay_state.out, .{
                .relay_to_client_datagram = .{
                    .node_id = packet.src,
                    .datagrams = .{
                        .ecn = null,
                        .segment_size = null,
                        .contents = packet.data,
                    },
                },
            });
            moved = true;
            room -= 1;
        }
    }
    return moved;
}
