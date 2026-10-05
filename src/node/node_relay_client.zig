//! The client half of the relay protocol, and what a caller does with it.
//!
//! A client dials its relay once, opens one stream on the first pass where the
//! connection is established, and reads the relay's half of the handshake and
//! its datagrams off it. Everything the relay hands over is copied and owned by
//! the node until `clearDelivered` gives it back, which is the lifetime
//! `Delivered` states from the outside and the only reason a caller can keep a
//! payload across a pass.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_relay_frame = @import("node_relay_frame.zig");
const node_transport = @import("node_transport.zig");

const base_key = @import("../base/key.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_client = @import("../relay/client.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const Instant = bridge_mod.Instant;
const NodeId = base_key.NodeId;
const max_datagram = node_transport.max_datagram;

/// One datagram a relay handed this node, and the node it came from.
///
/// `data` is a copy this node allocated from its own `gpa`, not a view of the
/// bytes the relay frame was read from: a relay frame borrows its datagrams out
/// of its inbox and that inbox is reused by the next read, so a payload handed
/// out has to be a copy or it is a view of a buffer that has moved on.
///
/// **Two lifetimes, and they are not the same one.** The payload is owned by
/// the node until `clearDelivered` gives it back — or until `deinit`, which
/// frees whatever is still listed — and the node's allocator is the one that
/// frees it. The list it sits in does not survive the next delivery: appending
/// to it may move it. `Node.delivered` says which is which from the outside.
pub const Delivered = struct {
    /// The node id the relay says this datagram came from. Copied, and so
    /// independent of the payload and of every other item on the list.
    src: NodeId,
    /// The datagram bytes this node copied. Empty is a datagram of no bytes,
    /// which the relay protocol permits and which is not an absence.
    data: []u8,
};

/// The relay this node spoke to, and what it has handed back.
pub const Spoke = struct {
    /// The core connection the relay is on.
    conn: u64,
    /// The stream the relay protocol runs on, once there is one.
    ///
    /// **Not at the dial.** `StreamsMap.openBidiStream` refuses while the
    /// peer's stream limit is still zero (`stream.zig:1385-1389`), and a
    /// dialled connection has not read a peer's transport parameters until its
    /// handshake is through. So the stream is opened on the first pass where
    /// the connection is established, which is also the first pass where
    /// anything could be written on it.
    stream: ?bridge_mod.Stream,
    /// The client half of the handshake, from the dial.
    handshake: relay_client.State,
    /// What has been read and is not yet a whole message.
    inbox: std.ArrayList(u8),
    /// Everything the relay has handed this node, owned until cleared.
    delivered: std.ArrayList(Delivered),
};

/// A relay client's pass: the handshake, then what the relay hands back.
///
/// **A client that is winding down dials nobody and opens no stream**, and
/// this is `serve`'s guard in the same place for the same reason. `close`
/// resumes rather than refusing, so a close that stopped in
/// `closing_endpoint` leaves this node mid-shutdown with its descriptor
/// open, and a pass in between is a call the surface permits. Dialing here
/// would take a new core connection and spend a credit from the relay's
/// stream grant on a node whose every other connection `close_endpoint`
/// has closed, and `relay_dialled` is latched — a node driven on after an
/// abandoned shutdown could never reach that relay again.
pub fn converse(self: *Node, at: Instant, random: std.Random) Error!bool {
    if (self.accept.shutdown.phase != .serving) return false;
    // The stream opened below must be retained in the node, not a Spoke copy.
    const spoke = if (self.spoke) |*held| held else {
        const dialed = try converseOpen(self, at, random);
        return dialed;
    };
    const conn = node_transport.connFor(self, spoke.conn) orelse return false;
    var stream = if (spoke.stream) |open| open else open_stream: {
        if (!conn.established()) return false;
        // `Spoke.stream`'s own note says the open is deferred past the
        // dial, and it is deferred on the `try` rather than on a question:
        // **by the time this runs the core has the peer's stream grant or
        // it will not have it ever.** The grant is applied in the same call
        // that marks the connection established — `setMaxStreams` at
        // `connection.zig:2650`, and `isEstablished` is that state
        // (`:4079`) — so an established connection has always had one, and
        // the open below can only be refused for being out of credit. This
        // node opens one stream in a connection's life and `sendThrough`
        // reuses it, so a refusal here means the relay advertised none,
        // and `MAX_STREAMS` raises a grant already made rather than
        // granting from nothing. There is nothing to wait for and nothing
        // to retry, and the pass says so by failing instead of answering
        // `false` on every pass from here on with nothing to show for it.
        const opened = try bridge_mod.Stream.open(conn);
        spoke.stream = opened;
        break :open_stream opened;
    };
    var moved = false;
    // The relay's half arrives on the stream the *relay* opened, which is
    // the mirror of `Served.out` and for the same reason. Straight onto the
    // inbox, as `serveRead` does it and for the same reason, and asking
    // `Stream.drain`'s second half for the same reason: what it appended is
    // not what came before it. See `discardTail`.
    var finished = false;
    var inbound = conn.peerStream();
    if (inbound) |*incoming| {
        moved = try incoming.drain(self.gpa, &spoke.inbox) or moved;
        finished = incoming.finished();
    }
    var consumed: usize = 0;
    // The walk `serveMessages` does, down to why the two drops are one
    // decision: a frame this node cannot decode is refused once rather
    // than on every pass after it, and the frame in front of it is acted
    // on once rather than once per pass.
    errdefer node_relay_frame.dropInbox(&spoke.inbox, consumed);
    while (true) {
        const found = try node_relay_frame.peekFrame(
            spoke.inbox.items,
            consumed,
            self.relay_scratch,
        ) orelse break;
        consumed = found.end;
        const message = try relay_frame.decode(found.frame, .v2);
        try converseMessage(self, spoke, &stream, message);
        moved = true;
    }
    node_relay_frame.dropInbox(&spoke.inbox, consumed);
    if (node_relay_frame.discardTail(&spoke.inbox, finished)) {
        self.stats.relay_stream_truncated += 1;
    }
    return moved;
}

/// Dial the relay, once, and start the client handshake on it.
///
/// The path offered is `.signed_challenge` for the reason the server half
/// offers no credential: this transport has no key-material exporter, so a
/// challenge is the only way a relay can tell who is calling.
pub fn converseOpen(self: *Node, at: Instant, random: std.Random) Error!bool {
    const peer = switch (self.config.relay.role) {
        .client => |peer| peer,
        else => return false,
    };
    if (self.relay_dialled) return false;
    self.relay_dialled = true;
    const reached = self.dialer.dial(
        peer.addr,
        peer.id,
        self.socket.address,
        &self.map,
        at,
        random,
    ) catch |err| {
        // A relay that cannot be reached is a fact about the network and
        // not a reason to retry, for the reason `Config.peers` gives: the
        // retry policy belongs with discovery.
        self.stats.relay_dials_refused += 1;
        std.log.warn("node: the relay was not reached: {t}", .{err});
        return false;
    };
    self.stats.relay_dials += 1;
    self.spoke = .{
        .conn = reached.conn.id(),
        .stream = null,
        .handshake = relay_client.start(.signed_challenge),
        .inbox = .empty,
        .delivered = .empty,
    };
    return true;
}

/// One relay frame, to this node's relay client.
pub fn converseMessage(
    self: *Node,
    spoke: *Spoke,
    stream: *bridge_mod.Stream,
    message: relay_frame.Message,
) Error!void {
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
                    try node_relay_frame.writeRelay(
                        stream,
                        self.relay_out,
                        .{ .client_auth = auth },
                    );
                    self.stats.relay_auth_sent += 1;
                },
                .close => {
                    stream.close();
                    self.stats.relay_closed += 1;
                },
            };
            switch (spoke.handshake) {
                .established => self.stats.relay_established += 1,
                else => {},
            }
            return;
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
        // **One status is a fact about this node and the other three are
        // information it has nowhere to put.** A
        // `.same_endpoint_id_connected` means a later connection took this
        // node's id at the relay, which is the one thing a caller of
        // `sendThrough` has to be told, so it is counted. `.healthy`
        // reports a recovery from trouble this transport never reported,
        // `.rate_limited` is advice about a send queue this protocol does
        // not have, and `.unknown` is a discriminant this build has no
        // name for. None of them changes what this node does next, so they
        // are dropped rather than counted; `relay_frame.Status` is where
        // the four are defined and why `.unknown` is kept at all.
        .status => |status| switch (status) {
            .same_endpoint_id_connected => self.stats.relay_displaced += 1,
            else => {},
        },
        .ping => |data| try node_relay_frame.writeRelay(stream, self.relay_out, .{ .pong = data }),
        // Two groups reach here and neither is acted on. The handshake's
        // own frames — `.server_challenge`, `.server_confirms_auth`,
        // `.server_denies_auth` — cannot: `relay_client.step` above folds
        // any frame its state does not name into `.failed`, so a relay that
        // sent one out of order has been closed by it and this node is no
        // longer reading that stream. What is left is `.restarting`, and
        // it is valid, decoded, and dropped: this client dials a relay
        // once in its life and `relay_dialled` is latched, so there is no
        // reconnect to schedule and the frame's wait and budget have
        // nothing here to bound. `.health` cannot reach this arm at all —
        // it is v1 only and `decode` is called with `.v2`. Nothing is
        // counted for either, because nothing happened.
        else => {},
    }
}

/// Retain one datagram the relay handed this node, and count it.
///
/// **The copy is the node's, and the guard for it is taken before the list
/// is.** `relay_frame.decode` borrows a frame's datagrams out of the bytes
/// that frame was read from, and those bytes are reused by the next read,
/// so a payload handed to a caller has to be copied rather than pointed
/// at. Copying makes it an allocation this node owns from that line on,
/// and the append that publishes it can still fail — so the `errdefer`
/// sits between the two: an append that cannot be given the copy releases
/// it rather than leaving one payload behind for every frame refused on
/// the way to the list.
///
/// Nothing bounds the list. `delivered` hands out what is on it and
/// `clearDelivered` is what gives the payloads back, so a relay that keeps
/// answering grows it until a caller clears it — which is the same
/// contract `Delivered` states from the outside.
pub fn retain(self: *Node, spoke: *Spoke, frame: relay_frame.DatagramFrame) Error!void {
    const owned = try self.gpa.dupe(u8, frame.datagrams.contents);
    errdefer self.gpa.free(owned);
    try spoke.delivered.append(self.gpa, .{
        .src = frame.node_id,
        .data = owned,
    });
    self.stats.relay_datagrams_out += 1;
}

/// What this node's relay has handed back, oldest first. A node that has
/// not reached a relay answers an empty slice, and so does one that has
/// called `clearDelivered`: both are "nothing is waiting", not "no relay".
///
/// **The slice is a descriptor into a list that grows, and the payloads in
/// it are not.** Two different lifetimes, and a caller has to know which
/// one it is holding:
///
/// - *The returned slice* points into `spoke.delivered`, an `ArrayList`
///   this node appends to in `retain`. The next datagram a relay hands
///   over may reallocate that list, and the slice this call returned
///   describes the old storage. Take the items — or `data.len`, or the
///   count — before driving another pass, and take the slice again if you
///   need it after one.
/// - *Each `Delivered.data`* is a copy this node allocated, and it stays
///   valid across every later delivery. What ends it is `clearDelivered`,
///   or `deinit` if the caller never got there.
///
/// `delivered` takes `*const Node` and mutates nothing, so reading the
/// list is safe from a caller holding only a shared borrow; it is not safe
/// from another thread while a pass is running.
pub fn delivered(self: *const Node) []const Delivered {
    const spoke = self.spoke orelse return &.{};
    return spoke.delivered.items;
}

/// Forget everything the relay has handed back, and free the payloads.
///
/// Each `data` is freed here and nowhere else, and the list is emptied in
/// the same pass, so a second call finds nothing to free and `deinit`
/// finds nothing to give back. A caller holding a slice from `delivered`
/// holds freed memory afterwards; a caller holding one `data` holds it
/// until this call and not one pass longer.
///
/// The list's capacity is kept, so a caller that clears every pass pays
/// for one growth rather than one per pass. A caller that never clears
/// grows the list for as long as the relay keeps answering — the copy in
/// `retain` is the price of handing a caller bytes it can keep.
pub fn clearDelivered(self: *Node) void {
    const spoke = &(self.spoke orelse return);
    for (spoke.delivered.items) |item| self.gpa.free(item.data);
    spoke.delivered.clearRetainingCapacity();
}

/// Send one datagram to `peer` through this node's relay.
///
/// The relay forwards it to the client holding `peer`'s node id, and when
/// nobody holds it the datagram is dropped and a `peer_gone` comes back
/// here. That is the whole of what a relay is for, and the drop is
/// upstream's (`server/clients.rs:218-224`).
///
/// This only queues bytes in memory; it performs no I/O or cancellation
/// check. `CoreRefused` can report a refused stream allocation.
pub fn sendThrough(self: *Node, peer: NodeId, bytes: []const u8) Error!void {
    // Two refusals, asked in the order they are asked below: a node with no
    // relay answers `NoRelay` whatever it was handed, and the payload bound
    // is about the caller's bytes, which only matter once there is a relay
    // to refuse them to.
    const spoke = self.spoke orelse return error.NoRelay;
    if (bytes.len > max_datagram) return error.DatagramTooLarge;
    const held = spoke.stream orelse return error.NoRelay;
    var stream: bridge_mod.Stream = held;
    try node_relay_frame.writeRelay(&stream, self.relay_out, .{
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
