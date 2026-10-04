const std = @import("std");
const base_key = @import("../base/key.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const quic_stream = @import("../transport/quic_stream.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_codec = @import("../relay/frame_codec.zig");
const relay_client = @import("../relay/client.zig");
const relay_state = @import("relay_state.zig");
const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const framing = @import("node_framing.zig");
const Error = @import("node_error.zig").Error;

pub fn converse(self: *node_mod.Node, at: quic_conn.Instant, random: std.Random) Error!bool {
    if (self.accept.shutdown.phase != .serving) return false;
    const spoke = if (self.relay_state.spoke) |*held| held else {
        const dialed = try converseOpen(self, at, random);
        return dialed;
    };
    // A relay that ended this handshake has nothing more to hear and this node
    // has nothing left to say, so a pass has nothing to do here: no stream to
    // reopen on a connection that is still established, no frame of its own to
    // act on, and `State.dialled` answering a second dial above.
    //
    // **This is the bound a reopened stream would cross.** The open below runs
    // whenever `stream` is null, so forgetting the handle at the close would
    // have bought one refusal at the price of a fresh stream and a fresh FIN
    // on every pass after it, against a relay that has already refused.
    if (spoke.ended()) return false;
    const conn = node_mod.connFor(self, spoke.conn) orelse return false;
    var stream = if (spoke.stream) |open| open else open_stream: {
        if (!conn.established()) return false;
        const opened = try quic_stream.openBidi(conn.entry.conn);
        spoke.stream = opened;
        break :open_stream opened;
    };
    var moved = false;
    var finished = false;
    // **No cursor, every pass**, for `serveRead`'s reason: `converse`
    // re-derives this handle rather than retaining one, so a cursor advanced
    // past the stream would answer null and stop the drain, and the relay
    // protocol opens one peer stream per connection. This end dialled, so the
    // relay's own stream is the first the peer opened rather than id zero —
    // which is why a `0` cursor happens to work here and does not on the
    // relay's side of the same handshake.
    var inbound = conn.peerStream(null);
    if (inbound) |*incoming| {
        moved = try incoming.drain(self.gpa, &spoke.inbox) or moved;
        finished = incoming.finished();
    }
    var ended = false;
    var consumed: usize = 0;
    errdefer framing.dropInbox(&spoke.inbox, consumed);
    while (try framing.peekFrame(spoke.inbox.items, consumed, self.relay_state.scratch)) |found| {
        consumed = found.end;
        const message = try relay_codec.decode(found.frame, .v2);
        moved = true;
        ended = try converseMessage(self, spoke, &stream, message);
        // A frame behind a refusal is not read: the relay has already said this
        // node is not one it will take, and `relay_client`'s own rule is that a
        // client has nothing left to say after either terminal answer.
        if (ended) break;
    }
    framing.dropInbox(&spoke.inbox, consumed);
    if (framing.discardTail(&spoke.inbox, finished)) {
        self.stats.relay_stream_truncated += 1;
    }
    // Whole frames first and the end of the stream second, for the reason
    // `serveRead` gives: a relay that answers the challenge and ends behind it
    // completed this handshake, and the order the other way round fails one
    // that had not answered yet.
    if (!ended and finished) converseEnded(self, spoke);
    return moved;
}

pub fn converseOpen(self: *node_mod.Node, at: quic_conn.Instant, random: std.Random) Error!bool {
    const peer = switch (self.config.relay.role) {
        .client => |peer| peer,
        else => return false,
    };
    if (self.relay_state.dialled) return false;
    self.relay_state.dialled = true;
    const reached = self.dialer.dial(
        peer.addr,
        peer.id,
        self.socket.address,
        &self.map,
        at,
        random,
    ) catch |err| {
        self.stats.relay_dials_refused += 1;
        std.log.warn("node: the relay was not reached: {t}", .{err});
        return false;
    };
    self.stats.relay_dials += 1;
    self.relay_state.spoke = .{
        .conn = reached.conn.id(),
        .stream = null,
        .handshake = relay_client.start(.signed_challenge),
        .inbox = .empty,
        .delivered = .empty,
    };
    return true;
}

/// Act on one frame the relay sent, and report whether it ended this client.
///
/// True is the terminal the walk in `converse` stops at. It is reported rather
/// than carried out here because carrying it out is `converseClose`, and this
/// frame's borrow of the stream outlives the call that noticed.
pub fn converseMessage(
    self: *node_mod.Node,
    spoke: *relay_state.Spoke,
    stream: *quic_stream.Stream,
    message: relay_frame.Message,
) Error!bool {
    switch (spoke.handshake) {
        .awaiting_relay, .awaiting_verdict => {
            const stepped = relay_client.step(
                spoke.handshake,
                .{ .frame = message },
                &self.config.secret,
            );
            spoke.handshake = stepped.state;
            if (stepped.action) |action| switch (action) {
                .send_client_auth => |auth| {
                    try framing.writeRelay(stream, self.relay_state.out, .{ .client_auth = auth });
                    self.stats.relay_auth_sent += 1;
                    return false;
                },
                .close => {
                    converseClose(self, spoke);
                    return true;
                },
            };
            switch (spoke.handshake) {
                .established => self.stats.relay_established += 1,
                else => {},
            }
            return false;
        },
        else => {},
    }
    switch (message) {
        .relay_to_client_datagram, .relay_to_client_datagram_batch => |frame| {
            try retain(self, spoke, frame);
        },
        .endpoint_gone => {
            self.stats.relay_peer_gone += 1;
        },
        .status => |status| switch (status) {
            .same_endpoint_id_connected => self.stats.relay_displaced += 1,
            else => {},
        },
        .ping => |data| try framing.writeRelay(stream, self.relay_state.out, .{ .pong = data }),
        else => {},
    }
    return false;
}

/// Queue the FIN this relay client says goodbye with, and count the close.
///
/// **The handle stays, and the transport does not keep the promise for it.**
/// `close` queues a FIN that the core sends later bytes ahead of
/// (`vendor/quic/src/quic/stream.zig:1057`, with `writeData` answering on
/// `reset_err` alone at :959), so what stops the bytes is `Spoke.ended` and
/// not the FIN: it is what a later `sendThrough` and a later `converse` both
/// read, and it takes them to the `NoRelay` their own contracts already promise
/// before anything is written or counted.
///
/// **One call ends one relay client.** The machine folds its terminal state into
/// itself and answers no action, so no frame can reach this arm twice, and
/// `Spoke.ended` keeps every pass after it out of `converse` entirely.
fn converseClose(self: *node_mod.Node, spoke: *relay_state.Spoke) void {
    if (spoke.stream) |*open| open.close();
    self.stats.relay_closed += 1;
}

/// Step the client machine with the end of the relay's stream, and carry out
/// whatever answer that asks for.
///
/// **Fed from the FIN and from nothing else.** `Stream.finished` is the peer
/// having said everything it will say; `drain` answers whether it appended
/// bytes and nothing about what came before them, so a stream with nothing on
/// it is a relay that has not spoken rather than one that has finished.
///
/// Mid-handshake the machine fails the handshake and asks for the close, and
/// that is this node's whole answer to a relay that stopped before it was told
/// either way: `converseClose` carries it out and `Spoke.ended` keeps every
/// later pass out. Past `.established` the handshake is a dead end the machine
/// absorbs, and that answer stands: the stream the relay ended is the one it
/// opened to send on, and the one this node writes on is the one it opened to
/// answer, so ending that is not this node's decision to take.
fn converseEnded(self: *node_mod.Node, spoke: *relay_state.Spoke) void {
    const stepped = relay_client.step(spoke.handshake, .stream_ended, &self.config.secret);
    spoke.handshake = stepped.state;
    switch (stepped.action orelse return) {
        .close => converseClose(self, spoke),
        // Unreachable, and named rather than folded into an `else` so that it
        // stays unreachable by evidence: an end of stream is `fail`
        // (`client.zig:515`) from a state that can still move and no action at
        // all from one that cannot (`client.zig:509-511`), and the machine
        // signs nothing for either.
        .send_client_auth => {},
    }
}

pub fn retain(
    self: *node_mod.Node,
    spoke: *relay_state.Spoke,
    frame: relay_frame.DatagramFrame,
) Error!void {
    try spoke.retain(self.gpa, frame);
    self.stats.relay_datagrams_out += 1;
}

/// Datagrams delivered by the relay, oldest first. An unreached relay or a
/// cleared list returns an empty slice.
///
/// The descriptor slice borrows the growable delivered list. Another delivery
/// may reallocate that list, so consume its descriptors before another pass
/// and reacquire the slice afterwards.
///
/// Each Delivered.data payload is a separately allocated copy. Later deliveries
/// do not invalidate it; clearDelivered or node deinitialization does.
/// This shared borrow does not permit concurrent access while a pass runs.
pub fn delivered(self: *const node_mod.Node) []const node_config.Delivered {
    const spoke = self.relay_state.spoke orelse return &.{};
    return spoke.delivered.items;
}

/// Free every retained payload and empty the descriptor list, keeping capacity.
/// Both descriptor slices and payload borrows from delivered become invalid.
/// A repeated clear finds nothing to free, and deinitialization will not free
/// these payloads again.
pub fn clearDelivered(self: *node_mod.Node) void {
    const spoke = &(self.relay_state.spoke orelse return);
    spoke.clearDelivered(self.gpa);
}

/// Queue a datagram for peer through the relay; this performs no I/O or
/// cancellation check. NoRelay precedes the payload-size check when no spoke
/// exists and when the relay ended this handshake; an oversized payload
/// otherwise returns DatagramTooLarge.
///
/// Resolve the retained connection id before borrowing its stream: the core
/// owns the stream handle, and a connection sweep invalidates that handle.
/// A missing connection, an unopened stream or an ended handshake returns
/// NoRelay.
///
/// CoreRefused means the write refused the frame or did not take it whole.
/// The write copies the bytes, so the caller may release them on return.
/// relay_sent increases only after the whole frame has been queued.
pub fn sendThrough(self: *node_mod.Node, peer: base_key.NodeId, bytes: []const u8) Error!void {
    const spoke = self.relay_state.spoke orelse return error.NoRelay;
    if (spoke.ended()) return error.NoRelay;
    if (bytes.len > node_config.max_datagram) return error.DatagramTooLarge;
    if (node_mod.connFor(self, spoke.conn) == null) return error.NoRelay;
    const held = spoke.stream orelse return error.NoRelay;
    var stream: quic_stream.Stream = held;
    try framing.writeRelay(&stream, self.relay_state.out, .{
        .client_to_relay_datagram = .{
            .node_id = peer,
            .datagrams = .{
                .ecn = null,
                .segment_size = null,
                .contents = bytes,
            },
        },
    });
    self.stats.relay_sent += 1;
}

/// Count registered node ids only for a serving relay.
/// Off and client roles have no initialized registry; they return zero rather
/// than reading storage that construction never initialized.
pub fn clientCount(self: *const node_mod.Node) usize {
    return switch (self.config.relay.role) {
        .serve => self.relay_state.registry.nodeCount(),
        else => 0,
    };
}

/// Read queue depth from the current serving configuration for every queue
/// and ring cut. Relay sizing is fixed at construction; retaining a second
/// depth beside that configuration would give those cuts a different answer.
pub fn queueDepth(self: *const node_mod.Node) usize {
    return switch (self.config.relay.role) {
        .serve => |role| role.queue_depth,
        else => 0,
    };
}
