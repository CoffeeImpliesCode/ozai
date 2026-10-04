//! One node's topics: each one's state machine, the contact data it holds, and
//! the stream each peer is written on. Fixed storage throughout, so a node's
//! whole swarm membership is one allocation it already owns.
//!
//! **A table, because a swarm is more than a state machine.** `gossip_state.State`
//! is one topic, and two swarms must not mix their timers, their named-peer
//! rings or their trees, so each `hyparview.TopicId` names a slot.
//!
//! **The stream is per topic because upstream's is.** iroh-gossip opens one
//! unidirectional QUIC stream per topic and names it in a `StreamHeader` at the
//! head of that stream (`net/util.rs:58-61`). A route here is that stream: which
//! peer, which topic, and whether the header has gone out yet.
//!
//! **Two streams per peer, not one and not unbounded.** The first is live; when
//! the peer's credit is spent the second opens alongside it, because
//! `error.NoSendCredit` is a fact about *now*.

const std = @import("std");
const base_key = @import("../base/key.zig");
const hyparview = @import("../gossip/hyparview.zig");
const quic_stream = @import("../transport/quic_stream.zig");
const config = @import("node_config.zig");
const gossip_state = @import("gossip_state.zig");

const NodeId = base_key.NodeId;
const TopicId = hyparview.TopicId;
const PeerData = hyparview.PeerData;
const Allocator = std.mem.Allocator;

/// What this table refuses on its own account, apart from the state machines'
/// own errors. **Narrow on purpose**: each of these is a bound this file
/// chose, and a caller that cannot name the bound it hit cannot report it.
pub const PeerError = error{ PeerDataFull, PeerDataTooLong };
pub const RouteError = error{RouteSlotsFull};

/// The whole of what this table can refuse, for a caller that wants one set.
pub const Error = gossip_state.Error || error{ TopicTableFull, RouteSlotsFull };

/// One unidirectional stream to one peer, for one topic.
pub const Route = struct {
    peer: NodeId,
    /// Borrowed from the connection's entry: good until the bridge sweeps it,
    /// which is the same promise `quic_conn.Conn` makes about itself.
    stream: quic_stream.UniStream,
    /// Whether the 32 topic bytes are already on this stream. Written once per
    /// stream, before any frame, because that is where upstream reads them from.
    header_written: bool = false,

    /// Whether `bytes` may go on this stream now.
    pub fn room(self: *const Route, bytes: usize) bool {
        return @as(u64, @intCast(bytes)) <= self.stream.credit();
    }
};

/// A peer whose contact data this topic holds.
const Peer = struct {
    id: NodeId,
    data: PeerData,
};

pub const Topic = struct {
    id: TopicId,
    /// The state machine, its timers and the peers its actions named.
    state: gossip_state.State(config.named_ring),
    peers: [config.topic_peer_slots]Peer = undefined,
    peer_len: usize = 0,
    routes: [config.topic_route_slots]Route = undefined,
    route_len: usize = 0,

    /// Contact data for a peer this topic already holds, or null.
    pub fn peerData(self: *const Topic, peer: NodeId) ?*const PeerData {
        for (self.peers[0..self.peer_len]) |*held| {
            if (held.id.order(peer) == .eq) return &held.data;
        }
        return null;
    }

    /// Hold a peer's contact data, replacing what a previous message claimed
    /// about it, or answer `error.PeerDataFull` and keep every peer held. **The
    /// refusal drops nothing**: a peer whose data went would stop being dialable
    /// and stop being re-advertised, and no entry carries an age that would
    /// make dropping the oldest one the honest answer.
    pub fn peerPut(self: *Topic, peer: NodeId, data: []const u8) PeerError!void {
        // The bound is proved here, at the copy, for `hyparview.PeerDataMap`'s
        // reason: the bytes are a peer's claim about itself carried in a
        // message, and a length this record cannot spell is a length it cannot
        // own. Copied before the write, because `data` very often borrows the
        // slot being replaced.
        if (data.len > hyparview.peer_data_max) return error.PeerDataTooLong;
        var copy: PeerData = .{};
        @memcpy(copy.bytes[0..data.len], data);
        copy.len = @intCast(data.len);
        for (self.peers[0..self.peer_len]) |*held| {
            if (held.id.order(peer) == .eq) {
                held.data = copy;
                return;
            }
        }
        if (self.peer_len == self.peers.len) return error.PeerDataFull;
        self.peers[self.peer_len] = .{ .id = peer, .data = copy };
        self.peer_len += 1;
    }

    pub fn peerCount(self: *const Topic) usize {
        return self.peer_len;
    }

    pub fn routeCount(self: *const Topic) usize {
        return self.route_len;
    }

    /// A route for `peer` with room for `bytes` right now, or null: this topic
    /// has no stream to that peer, or every one it holds is out of credit.
    pub fn routeFor(self: *Topic, peer: NodeId, bytes: usize) ?*Route {
        for (self.routes[0..self.route_len]) |*route| {
            if (route.peer.order(peer) != .eq) continue;
            if (route.room(bytes)) return route;
        }
        return null;
    }

    /// Take one more route to `peer`, or answer `error.RouteSlotsFull` and keep
    /// the ones held: a pool at its bound is a peer that is not reading, and
    /// dropping a live stream to make room would throw away the messages the
    /// window is about to accept. **Two per peer, and two for the topic's pool
    /// as a whole** — the per-peer bound is the one that matters, and it is
    /// checked here rather than left to the caller, because a peer whose
    /// windows stay shut would otherwise fill the whole topic pool with its own
    /// streams and starve every other peer.
    pub fn routeOpen(
        self: *Topic,
        peer: NodeId,
        stream: quic_stream.UniStream,
    ) RouteError!*Route {
        if (self.route_len == self.routes.len) return error.RouteSlotsFull;
        var held: usize = 0;
        for (self.routes[0..self.route_len]) |*route| {
            if (route.peer.order(peer) == .eq) held += 1;
        }
        if (held == config.streams_per_peer) return error.RouteSlotsFull;
        self.routes[self.route_len] = .{ .peer = peer, .stream = stream };
        self.route_len += 1;
        return &self.routes[self.route_len - 1];
    }

    /// Close and drop every route to `peer`, and report how many went.
    ///
    /// **The stream is closed rather than reset**: these carry whole frames a
    /// peer has not necessarily read, and a FIN says "that is all of it" where
    /// a RESET_STREAM says "discard what I sent", which would turn a full
    /// window into a lost message on the peer's side.
    pub fn routeForget(self: *Topic, peer: NodeId) usize {
        var index: usize = 0;
        var dropped: usize = 0;
        while (index < self.route_len) {
            const route = &self.routes[index];
            if (route.peer.order(peer) == .eq) {
                route.stream.close();
                self.routes[index] = self.routes[self.route_len - 1];
                self.route_len -= 1;
                dropped += 1;
                continue;
            }
            index += 1;
        }
        return dropped;
    }
};

pub const Table = struct {
    topics: [config.max_topics]Topic = undefined,
    len: usize = 0,

    pub fn count(self: *const Table) usize {
        return self.len;
    }

    pub fn at(self: *Table, index: usize) *Topic {
        std.debug.assert(index < self.len);
        return &self.topics[index];
    }

    /// Join `id`, or answer `error.TopicTableFull` and join nothing.
    ///
    /// Re-joining a topic already held returns that topic rather than building
    /// a second one: upstream's topic actor is keyed by id, so two live actors
    /// for one swarm would be two trees answering for the same message ids.
    pub fn add(
        self: *Table,
        id: TopicId,
        me: NodeId,
        me_data: ?PeerData,
        topic_config: hyparview.TopicConfig,
        rng: hyparview.Rng,
    ) Error!*Topic {
        if (self.find(id)) |held| return held;
        if (self.len == self.topics.len) return error.TopicTableFull;
        self.topics[self.len] = .{
            .id = id,
            .state = try gossip_state.State(config.named_ring).init(
                me,
                me_data,
                topic_config,
                rng,
            ),
        };
        self.len += 1;
        return &self.topics[self.len - 1];
    }

    /// The topic at `index` read-only, or null when this node is in fewer than
    /// that many. `Node.namedPeers` reads a topic without holding it open to
    /// writes, which is the one question this asks that `at` cannot.
    pub fn peek(self: *const Table, index: usize) ?*const Topic {
        if (index >= self.len) return null;
        return &self.topics[index];
    }

    pub fn find(self: *Table, id: TopicId) ?*Topic {
        for (self.topics[0..self.len]) |*topic| {
            if (topic.id.eql(id)) return topic;
        }
        return null;
    }

    /// Give back every topic's timer list. See `gossip_state.State.deinit`: the
    /// topic itself holds no heap, so this is the whole of what a table owns.
    pub fn deinit(self: *Table, gpa: Allocator) void {
        for (self.topics[0..self.len]) |*topic| topic.state.deinit(gpa);
        self.len = 0;
    }

    /// Drop every topic's pending timers, keeping the list's room. See
    /// `gossip_state.State.clearTimers` for why this is the handler's own
    /// shutdown rather than teardown.
    pub fn clearTimers(self: *Table) void {
        for (self.topics[0..self.len]) |*topic| topic.state.clearTimers();
    }

    /// Close and drop every route naming `peer`, across every topic.
    ///
    /// Asked when a connection ends rather than by the topic that noticed: a
    /// connection is one, and the streams on it belong to every swarm it was
    /// serving.
    pub fn routeForgetPeer(self: *Table, peer: NodeId) usize {
        var dropped: usize = 0;
        for (self.topics[0..self.len]) |*topic| dropped += topic.routeForget(peer);
        return dropped;
    }
};
