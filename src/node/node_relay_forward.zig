//! What a serving relay does for the clients it already holds.
//!
//! Reading a client's stream, acting on each whole message it finds, putting a
//! datagram on the queue of the client that owns the node id it names, and
//! writing out what is queued for each client a bounded number of times a pass.
//! None of it admits a client and none of it ends one: `node_relay_serve.zig`
//! does the first and `node_relay_release.zig` the second, and this file is
//! what happens in between.

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_relay_frame = @import("node_relay_frame.zig");
const node_relay_serve = @import("node_relay_serve.zig");
const node_relay_table = @import("node_relay_table.zig");
const node_transport = @import("node_transport.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const relay_frame = @import("../relay/frame.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const max_datagram = node_transport.max_datagram;
const Served = node_relay_table.Served;

/// Take everything the clients have sent, and act on it.
pub fn serveRead(self: *Node) Error!bool {
    var moved = false;
    for (self.clients) |*slot| {
        if (!slot.live) continue;
        const conn = node_transport.connFor(self, slot.conn) orelse continue;
        // The client's half arrives on the stream the *client* opened,
        // which this connection does not hold until the client has written
        // something on it — so it is looked up afresh every pass, and a
        // client that has not spoken yet is a client with nothing to read.
        //
        // Straight onto the inbox, with no buffer in between: the bytes go
        // there once instead of twice, and a read has no length to size a
        // buffer against. See `Stream.drain`.
        //
        // **`drain`'s answer is not "this stream is empty".** It says
        // whether it appended bytes and nothing about what came before
        // them, so a stream the peer ended on a frame boundary and one it
        // ended in the middle of a frame read the same. `discardTail` asks
        // the other half, and it is asked *after* the whole messages are
        // taken, because before that a full inbox is a message this relay
        // has not acted on yet.
        var incoming = conn.peerStream() orelse continue;
        moved = try incoming.drain(self.gpa, &slot.inbox) or moved;
        moved = try serveMessages(self, slot) or moved;
        if (node_relay_frame.discardTail(&slot.inbox, incoming.finished())) {
            self.stats.relay_stream_truncated += 1;
        }
    }
    return moved;
}

/// Every whole message in a client's inbox, acted on in turn.
pub fn serveMessages(self: *Node, slot: *Served) Error!bool {
    var moved = false;
    var consumed: usize = 0;
    // Dropping what the walk has been over is one decision, taken on the
    // way out and on the fault alike. The `try` in the condition below
    // leaves this function without ever reaching the drop, so a walk that
    // only dropped on success would hand back every frame it had already
    // served for the next pass to serve again — the poison in front of a
    // datagram being the worst of it, because it refuses first.
    errdefer node_relay_frame.dropInbox(&slot.inbox, consumed);
    while (try node_relay_frame.peekFrame(slot.inbox.items, consumed, self.relay_scratch)) |found| {
        // The end before the meaning: `decode` is what can fail, and the
        // frame it fails on arrived whole, so it is spent either way.
        consumed = found.end;
        const message = try relay_frame.decode(found.frame, .v2);
        try serveMessage(self, slot, message);
        moved = true;
    }
    node_relay_frame.dropInbox(&slot.inbox, consumed);
    return moved;
}

/// One relay frame from a client.
pub fn serveMessage(
    self: *Node,
    slot: *Served,
    message: relay_frame.Message,
) Error!void {
    switch (slot.handshake) {
        .opened, .challenged => {
            _ = try node_relay_serve.serveHandshake(self, 0, slot, .{ .frame = message });
            return;
        },
        // Past admission the frames belong to the connection rather than to
        // the handshake, and `server.step` folds them in as nothing — so
        // they are read here rather than handed to a machine that has
        // already returned.
        else => {},
    }
    switch (message) {
        .client_to_relay_datagram, .client_to_relay_datagram_batch => |frame| {
            self.stats.relay_datagrams_in += 1;
            try forward(self, slot, frame);
        },
        .ping => |data| {
            var out: bridge_mod.Stream = slot.out;
            try node_relay_frame.writeRelay(&out, self.relay_out, .{ .pong = data });
        },
        // Everything else is a frame this relay has no use for, and the
        // reason is the direction rather than the message: a `.status` and
        // a `.health` are the relay's own one-way declarations about the
        // connection, and this end of the protocol has no frame in which to
        // declare anything — the two this relay sends are the
        // `.same_endpoint_id_connected` it queues for a displaced client
        // and the `.healthy` it queues for one that took over. A
        // `.restarting` names a wait before reconnecting, which is advice
        // to a client and not to the relay. And `.health` cannot arrive at
        // all: it is v1 only and `decode` is called with `.v2`.
        else => {},
    }
}

/// One datagram from a client, onto the queue of the client it names.
pub fn forward(self: *Node, from: *Served, frame: relay_frame.DatagramFrame) Error!void {
    const src = from.node_id orelse return;
    const payload = frame.datagrams.contents;
    const destination = self.registry.activeConnectionId(frame.node_id);
    if (destination == null) {
        // Nobody holds that node id, and the frame that says so goes on the
        // *control* queue. See `serveRegister`.
        from.queues.control.push(.{ .peer_gone = frame.node_id }) catch {
            self.stats.relay_queue_full += 1;
            return;
        };
        self.stats.relay_unknown_target += 1;
        return;
    }
    const to = node_relay_table.servedFor(self, destination.?) orelse return;
    // A relay forwards datagrams, and this is the length of one. A frame
    // that claims more is refused rather than truncated, because a
    // truncated QUIC packet is a packet the peer cannot use.
    if (payload.len > max_datagram) {
        self.stats.relay_oversized += 1;
        return;
    }
    if (to.queues.data.isFull()) {
        self.stats.relay_queue_full += 1;
        return;
    }
    // `Queue` is a ring over `storage[(head + count) % len]` and `ring` is a
    // ring over the same index, so the slot a queued `Packet` borrows is
    // the one its own position names, and it is free the moment it is
    // popped. Copying here is what makes that possible at all: the bytes
    // arrived in the read buffer and are gone by the next read.
    const depth = to.queues.data.capacity();
    const at = (to.queues.data.head + to.queues.data.count) % depth;
    const bytes = to.ring[at * max_datagram ..][0..payload.len];
    @memcpy(bytes, payload);
    to.queues.data.push(.{ .src = src, .data = bytes }) catch {
        self.stats.relay_queue_full += 1;
        return;
    };
    self.stats.relay_forwarded += 1;
}

/// Write out what is queued for each client, a bounded number each.
pub fn serveQueues(self: *Node, drain_room: usize) Error!bool {
    var moved = false;
    var room = drain_room;
    for (self.clients) |*slot| {
        if (!slot.live) continue;
        var stream: bridge_mod.Stream = slot.out;
        // Control first, and not as a courtesy: a client that has stopped
        // reading is the one that most needs to be told, and the queue it
        // would otherwise be behind is exactly the one that is full.
        while (room > 0) {
            const control = slot.queues.control.pop() orelse break;
            try node_relay_frame.writeRelay(
                &stream,
                self.relay_out,
                node_relay_frame.controlFrame(control),
            );
            moved = true;
            room -= 1;
        }
        while (room > 0) {
            const packet = slot.queues.data.pop() orelse break;
            try node_relay_frame.writeRelay(&stream, self.relay_out, .{
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
