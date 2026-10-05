//! Where a datagram the core wants to send actually goes, and what a relay does
//! with one it cannot deliver.
//!
//! `node_transport.drain` is the node's whole egress: for every `Egress` the
//! core produces it calls `self.socket.send(io, egress.to, egress.send)`
//! (`node_transport.zig:121-132`). That is right for a direct path and wrong for
//! every other one, because a dial through a relay is told a *synthetic* address
//! (`transport/dial_route.zig`: `fd15:70a:510b:1::/64`, one allocation per
//! `(peer, relay)` pair) and a socket has no idea where to send one. A datagram
//! addressed to a peer behind the relay has to become a `client_to_relay_datagram`
//! on this node's relay stream and nothing else — `relay/carrier.zig` builds the
//! frame, and this file decides that it is a relay frame at all.
//!
//! # Four answers, and two of them are refusals
//!
//! **`route` answers from the address alone, because the address is the whole of
//! what the core knows.** The map is what turns a synthetic address back into the
//! key that owns it (`addr_map.MappedAddrs.lookup`), so:
//!
//! - a real address is `.direct`, and the socket is right;
//! - a relay-subnet address this map handed out is `.relay` with the peer behind
//!   it — the one case where a UDP send would be a packet to `fd15:...` that
//!   nobody can route;
//! - an `any_path` address is `.multipath`, the peer itself, and **this module
//!   does not choose a path for it**: upstream duplicates a packet addressed to
//!   the peer across every candidate path (`iroh/src/socket/remote_map.rs`), and
//!   that is a decision about paths rather than about relaying. A caller that
//!   wants one path picks it and calls again;
//! - anything else this map does not own is `.unroutable`, and the two refusals
//!   are different facts. `.foreign` is a synthetic address belonging to somebody
//!   else's map, which is what a stray packet in this node's ULAs looks like.
//!   `.custom` is a registered non-IP transport address this node *does* own, and
//!   the relay protocol has no frame that carries it: no relay forwards a custom
//!   address, so a datagram for one has nowhere to go on this path.
//!
//! # The other direction needs the address, not only the peer
//!
//! **`sourceOf` is what a relay-handed datagram is presented to the core as
//! coming from.** The core matches an incoming datagram to a connection by its
//! source address (`Bridge.recv`, `transport/quic_bridge.zig:574`), and a datagram
//! that arrived inside a relay frame has no such address until the node allocates
//! the one its own map holds for `(this relay, the peer that sent it)`. That is
//! the same key `dial_route.resolveRoute` builds for an outbound relay route, so
//! both directions of one relayed peer share one synthetic address — which is the
//! fact that makes the connection the core built for it the connection this
//! datagram belongs to.
//!
//! # Queue pressure drops the datagram and not the peer
//!
//! `deliver` is the rule the relay's forward path has to follow, and its order is
//! the decision. **An unknown target is told so on the control queue even when
//! the datagram queue is full**, because those are two queues (`server_queue.zig`,
//! invariant 9) and a full one cannot swallow the news; a full datagram queue
//! drops the datagram and nothing else, and upstream says exactly that
//! (`server/clients.rs:218-224`). A refusal is a dropped datagram, never a
//! dropped connection and never an `endpoint_gone` sent to a peer that is still
//! there: `peer_gone` means "nobody holds that node id", and a client with a full
//! queue holds it.
//!
//! Nothing here reads a clock, opens a socket or allocates except `sourceOf`,
//! which allocates from the allocator it is handed because `addr_map.get` does.

const std = @import("std");

const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("../transport/addr_map.zig");
const batch = @import("../transport/batch.zig");
const carrier = @import("../relay/carrier.zig");
const frame = @import("../relay/frame.zig");

const t = std.testing;

/// The node id a datagram is for, or came from.
pub const NodeId = base_key.NodeId;

/// A peer's address, direct or synthetic. See `base/addr.zig`.
pub const SocketAddr = base_addr.SocketAddr;

/// Where a relay lives. See `base/relay.zig`.
pub const RelayUrl = base_addr.RelayUrl;

/// One relay route's address, as a `RelayUrl` compares.
pub const RelayNode = addr_map.RelayNode;

/// Why an address cannot be carried.
pub const Unroutable = enum {
    /// A synthetic address this node's map never handed out: it belongs to
    /// somebody else's map, or it is a stray packet in this node's ULAs.
    foreign,
    /// A registered non-IP transport address this node owns. No relay carries
    /// one, so there is no frame for it on this path.
    custom,
};

/// Where one datagram goes, decided from the address alone.
pub const Route = union(enum) {
    /// A real socket address: the socket is the carrier.
    direct,
    /// The relay subnet, and the peer behind it. One `client_to_relay_datagram`.
    ///
    /// **Two relays to one peer route alike, and the relay is not in this union
    /// on purpose.** The frame is addressed to the node id, and which relay a
    /// datagram goes out on is a fact the caller already holds: it chose the
    /// path that named the stream.
    relay: NodeId,
    /// The peer itself, before a path was chosen. See the module doc for why
    /// this module does not choose one.
    multipath: NodeId,
    /// Not this node's to carry.
    unroutable: Unroutable,
};

/// Where `socket` goes.
///
/// **It reads the map and the subnet and nothing else** — no connection table, no
/// relay client, no socket. A caller that has an egress and an address gets an
/// answer from those two bytes and can act on it before anything else is
/// consulted, which is what keeps the decision testable without a node.
pub fn route(map: *const addr_map.MappedAddrs, socket: SocketAddr) Route {
    const classified = base_ula.classify(socket);
    const owned = switch (classified) {
        .ip => null,
        .any_path, .relay, .custom => |octets| map.lookup(octets),
    };
    if (owned) |key| {
        return switch (key) {
            .any_path => |node| .{ .multipath = node },
            .relay => |pair| .{ .relay = pair.node },
            .custom => .{ .unroutable = .custom },
        };
    }
    return switch (classified) {
        .ip => .direct,
        .relay => .{ .unroutable = .foreign },
        .any_path, .custom => .{ .unroutable = .foreign },
    };
}

/// What `sourceOf` can refuse. See `addr_map.MappedAddrs.GetError`.
pub const SourceError = addr_map.GetError;

/// The address a datagram from `peer` through `relay` must appear to come from.
///
/// **It is this node's map's allocation for that pair, memoised like every
/// other**, so a second call draws no host bits and the core sees one address for
/// that peer for the life of the map. That is what makes an inbound relayed
/// datagram find the connection the core built when this node dialled that peer
/// through that relay.
///
/// `random` is the caller's generator, for the reason `addr_map.get` gives: a
/// process-global RNG is what `base` forbids, and a test passes a seeded engine.
pub fn sourceOf(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    relay: RelayUrl,
    peer: NodeId,
    random: std.Random,
) SourceError!SocketAddr {
    const allocated = try map.get(gpa, .{ .relay = .{ .relay = relay, .node = peer } }, random);
    return base_ula.socketAddrFor(.relay, addr_map.hostBitsOf(allocated));
}

/// The payload a core egress carries. See `transport/batch.zig`.
pub const Send = batch.Send;

/// The frame one relay message carries. See `relay/carrier.zig`.
pub const Message = carrier.Message;

/// Why a payload cannot be carried. See `relay/carrier.zig`.
pub const CarryError = carrier.Error;

/// The one relay message that carries `send` to `peer`.
///
/// **This is where the core's payload type becomes the protocol's, and the two
/// are field for field the same** — `batch.Send` is `{ ecn, contents,
/// segment_size }` (`batch_run.zig:48`) and `frame.Datagrams` is the same three
/// with the same "a segment size is set exactly when the payload holds more than
/// one datagram" rule (`frame_types.zig:418`), and `batch.Ecn` *is*
/// `frame.Ecn` (`batch_run.zig:29`). So the move is three assignments, no copy,
/// and a GSO burst from the core arrives at the relay as the GSO burst it was.
///
/// `peer` is what `route` returned in its `.relay` arm, and the caller is the one
/// that has to pass it: nothing here looks an address up, because the direction
/// was already decided by whoever called `route`.
pub fn relayMessage(peer: NodeId, send: Send) CarryError!Message {
    return carrier.carry(peer, .{
        .ecn = send.ecn,
        .segment_size = send.segment_size,
        .contents = send.contents,
    }, .client_to_relay);
}

/// The facts one relay datagram's delivery turns on.
pub const Delivery = struct {
    /// Whether the relay holds a connection for the node id it is addressed to.
    /// This is a registry fact, not a socket one: the relay looks the peer up in
    /// its own table (`node_relay_forward.zig:124`).
    target_held: bool,
    /// How deep that client's datagram queue is, and how deep it may get. The
    /// queue is the relay's own storage, so this is a count and not a guess.
    queued: usize,
    capacity: usize,
    /// The datagram's length, and the relay's bound on one.
    len: usize,
    max_datagram: usize,
};

/// Why a datagram was not delivered, each named because each is a different
/// counter and a different fault.
pub const Drop = enum {
    /// Nobody holds the destination node id, so the peer is told on the control
    /// queue and the datagram goes. Upstream's rule
    /// (`server/clients.rs:218-224`).
    unknown_peer,
    /// The destination client is not reading and its datagram queue is full. The
    /// peer is still there and is told nothing: this is a slow client, not a
    /// lost one.
    backlogged,
    /// A datagram longer than the relay's slot for one. Refused rather than
    /// truncated, because a truncated QUIC packet is a packet the peer cannot
    /// use.
    oversized,
};

/// What the relay does with one datagram.
pub const Disposition = union(enum) {
    /// Put it on the destination client's data queue.
    queued,
    /// Drop it, for the named reason.
    dropped: Drop,
};

/// The rule the forward path follows, as a function of the facts.
///
/// **The order is the decision, and it is upstream's.** An unknown peer is
/// answered before the queue is consulted at all, because the answer goes on the
/// control queue and the queue that is full is the other one; then length, then
/// room. A caller that checked room first would tell a client whose queue is full
/// that its peer was gone, which is false and is the one mistake in this function
/// that would be visible on the wire.
pub fn deliver(delivery: Delivery) Disposition {
    if (!delivery.target_held) return .{ .dropped = .unknown_peer };
    if (delivery.len > delivery.max_datagram) return .{ .dropped = .oversized };
    if (delivery.queued >= delivery.capacity) return .{ .dropped = .backlogged };
    return .queued;
}

// --- tests

const relay_test_ids = @import("../relay/relay_test_ids.zig");

/// A seeded engine, because `addr_map.get` draws host bits and a test that
/// wanted a different answer every run could not name one.
const Prng = std.Random.DefaultPrng;

/// The relay every test below dials through.
fn relayUrl() !RelayUrl {
    return RelayUrl.parse("https://relay.example.com/");
}

/// The `(relay, peer)` pair that owns `address`, compared as the map compares
/// keys.
///
/// **`KeyContext.eql` is key sameness and `==` is not**: `RelayUrl.parse` leaves
/// everything past the host unwritten, so two equal relay URLs built by two
/// calls differ in bytes no comparison of a key may read. An answer of `null`,
/// or an address outside the relay subnet, is a failed assertion and not a
/// reason to take the test binary down with it.
fn expectRelayKey(
    map: *const addr_map.MappedAddrs,
    want: addr_map.RelayNode,
    address: SocketAddr,
) !void {
    const octets = switch (base_ula.classify(address)) {
        .relay => |octets| octets,
        else => return error.TestUnexpectedResult,
    };
    const found = map.lookup(octets) orelse return error.TestUnexpectedResult;
    try t.expect(addr_map.KeyContext.eql(.{}, .{ .relay = want }, found));
}

test "a relayed peer's datagram goes to the relay and a direct one to the socket" {
    var engine = Prng.init(41);
    const random = engine.random();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(41);
    const relay = try relayUrl();
    const via = try sourceOf(t.allocator, &map, relay, peer, random);

    // The synthetic address is in the relay subnet, at the relay's mapped port,
    // and the map says whose it is — three separate answers a caller needs.
    try t.expectEqual(
        base_ula.Classification{ .relay = via.ip.v6 },
        base_ula.classify(via),
    );
    try t.expectEqual(
        Route{ .relay = peer },
        route(&map, via),
    );

    // And a real address is direct, whatever the map holds.
    const direct: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };
    try t.expectEqual(Route.direct, route(&map, direct));
}

// The whole egress path in one test: a core payload addressed to a synthetic
// relay address becomes one relay message for the peer behind it, with the
// segmentation the core asked for, and reads back the same.
test "an egress for a relayed peer is one relay message, not a socket write" {
    var engine = Prng.init(45);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(45);
    const via = try sourceOf(t.allocator, &map, try relayUrl(), peer, engine.random());

    // What `Conn.drain` would have handed the socket: a GSO burst of three
    // datagrams of four bytes with a codepoint, addressed to the synthetic
    // address the core was told.
    const send: Send = try batch.Send.batch("abcdefghijk", 4, .ect0);
    try t.expectEqual(@as(usize, 3), send.datagramCount());

    // The address decides it is the relay's, and the payload becomes one frame
    // under the batch tag.
    const routed = route(&map, via);
    try t.expectEqual(Route{ .relay = peer }, routed);
    const message = try relayMessage(routed.relay, send);
    try t.expectEqual(
        frame.FrameType.client_to_relay_datagram_batch,
        std.meta.activeTag(message),
    );

    // Through the real codec it comes back as three datagrams of the same
    // segmentation, addressed to that peer — which is what the relay will put on
    // the destination client's queue.
    var out: [128]u8 = undefined;
    const decoded = carrier.carried(
        try frame.decode(try frame.encode(message, .v2, &out), .v2),
    ).?;
    try t.expectEqual(peer, decoded.node_id);
    try t.expectEqual(@as(?u16, 4), decoded.datagrams.segment_size);
    try t.expectEqual(@as(?frame.Ecn, .ect0), decoded.datagrams.ecn);
    try t.expectEqualStrings("abcdefghijk", decoded.datagrams.contents);

    // The same egress to a real address is not a relay message at all, so a
    // caller that routes first never has to ask twice.
    const direct: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };
    try t.expectEqual(Route.direct, route(&map, direct));
}

test "the same relay and peer are one address, in both directions" {
    var engine = Prng.init(42);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(42);
    const relay = try relayUrl();
    const first = try sourceOf(t.allocator, &map, relay, peer, engine.random());

    // Memoised: a second draw from a *different* generator does not change the
    // address, so the core sees one address for this peer however many datagrams
    // arrive for it.
    var other = Prng.init(7);
    const second = try sourceOf(t.allocator, &map, relay, peer, other.random());
    try t.expectEqual(first, second);
    try t.expectEqual(@as(usize, 1), map.by_key.count());

    // A different relay or a different peer is a different key and a different
    // address, because the subnet is per `(peer, relay)` pair. The reverse
    // index is what makes "a different key" a fact rather than an inference,
    // so each address is asked which pair owns it.
    const other_relay = try RelayUrl.parse("https://other.example.com/");
    const elsewhere = try sourceOf(
        t.allocator,
        &map,
        other_relay,
        peer,
        other.random(),
    );
    try t.expect(first.order(elsewhere) != .eq);
    try expectRelayKey(&map, .{ .relay = relay, .node = peer }, first);
    try expectRelayKey(&map, .{ .relay = other_relay, .node = peer }, elsewhere);

    // Both addresses route to the one peer, and pinning that is what stops a
    // caller reading the relay out of a route that never carried it. The route
    // says the datagram is the relay's and names its destination; the two
    // addresses differ in the relay, not in the peer.
    try t.expectEqual(Route{ .relay = peer }, route(&map, first));
    try t.expectEqual(Route{ .relay = peer }, route(&map, elsewhere));

    // The other half of the claim, which varying the relay alone never covered:
    // a different peer through the *same* relay is a third key and a third
    // address, and here the route differs as well, because the node id is the
    // half of the key `route` does carry.
    const stranger = try relay_test_ids.testNodeId(43);
    const third = try sourceOf(t.allocator, &map, relay, stranger, other.random());
    try t.expect(first.order(third) != .eq);
    try t.expect(elsewhere.order(third) != .eq);
    try expectRelayKey(&map, .{ .relay = relay, .node = stranger }, third);
    try t.expectEqual(Route{ .relay = stranger }, route(&map, third));
    try t.expectEqual(@as(usize, 3), map.by_key.count());
    try t.expectEqual(@as(usize, 3), map.by_addr.count());
}

test "an address this map never handed out is not carried anywhere" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    // Somebody else's relay subnet: this node's reverse index has nothing for
    // it, and a packet in this node's ULAs looks the same way.
    const foreign: SocketAddr = base_ula.socketAddrFor(.relay, @splat(0x11));
    try t.expectEqual(Route{ .unroutable = .foreign }, route(&map, foreign));
    try t.expectEqual(Route{ .unroutable = .foreign }, route(&map, base_ula.socketAddrFor(
        .any_path,
        @splat(0x22),
    )));

    // A custom transport address this node *does* own is a different refusal:
    // the address is ours and the relay protocol still has no frame for it.
    var engine = Prng.init(43);
    var payload: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const custom = addr_map.CustomKey.from(.{
        .id = 7,
        .data = payload[0..],
    }) catch return error.TestUnexpectedResult;
    const owned = try map.get(t.allocator, .{ .custom = custom }, engine.random());
    try t.expectEqual(
        Route{ .unroutable = .custom },
        route(&map, base_ula.socketAddrFor(.custom, addr_map.hostBitsOf(owned))),
    );
}

test "an address naming the peer before a path was chosen is left to the caller" {
    var engine = Prng.init(44);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(44);
    const any = try map.get(t.allocator, .{ .any_path = peer }, engine.random());
    try t.expectEqual(
        Route{ .multipath = peer },
        route(&map, base_ula.socketAddrFor(.any_path, addr_map.hostBitsOf(any))),
    );
}

// Queue pressure drops the datagram, tells the peer only when it is genuinely
// gone, and drops nothing else.
test "a full queue drops the datagram and never the peer" {

    // Room for four datagrams, and two are queued.
    const roomy: Delivery = .{
        .target_held = true,
        .queued = 2,
        .capacity = 4,
        .len = 1200,
        .max_datagram = 1500,
    };
    try t.expectEqual(Disposition.queued, deliver(roomy));

    // Full: the datagram goes and the peer is told nothing. A `peer_gone` here
    // would be a lie — this client holds the node id and is merely behind.
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        deliver(.{
            .target_held = true,
            .queued = 4,
            .capacity = 4,
            .len = 1200,
            .max_datagram = 1500,
        }),
    );

    // Nobody holds the node id: the datagram goes *and* the caller is told to
    // say so on the control queue — even with the data queue full, which is the
    // order that keeps the news from being swallowed.
    try t.expectEqual(
        Disposition{ .dropped = .unknown_peer },
        deliver(.{
            .target_held = false,
            .queued = 4,
            .capacity = 4,
            .len = 1200,
            .max_datagram = 1500,
        }),
    );

    // Too long: refused before the queue is asked, so a payload that could not
    // be carried is never counted as waiting for room.
    try t.expectEqual(
        Disposition{ .dropped = .oversized },
        deliver(.{
            .target_held = true,
            .queued = 2,
            .capacity = 4,
            .len = 1501,
            .max_datagram = 1500,
        }),
    );

    // A queue with no room at all refuses everything, which is a configuration
    // this node refuses at construction (`RelayQueueDepthZero`) and which the
    // decision still answers honestly rather than dividing by zero.
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        deliver(.{
            .target_held = true,
            .queued = 0,
            .capacity = 0,
            .len = 1200,
            .max_datagram = 1500,
        }),
    );
}