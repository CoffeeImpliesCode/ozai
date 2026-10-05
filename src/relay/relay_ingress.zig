//! A datagram a relay handed this node, and the address it is presented from.
//!
//! The other half of `relay/relay_egress.zig`. That file answers where an
//! egress goes; this one answers what a frame arriving on this node's relay
//! stream *is*, which is a datagram from the peer the relay named rather than
//! from the relay's own address. The core matches an incoming datagram to a
//! connection by its source address (`Bridge.recv`,
//! `transport/quic_bridge.zig:574`), and a datagram that arrived inside a relay
//! frame has no such address until this node names the one its own map holds
//! for `(this relay, that peer)`.
//!
//! # The address is the map's, asked every time and cached nowhere
//!
//! **`resolve` reads the forward table and allocates nothing.** That is the
//! whole of the address rule, and both halves of it are load-bearing:
//!
//! - The address is `node_relay_route.sourceOf`'s — the same `(relay, peer)`
//!   key `transport/dial_route.resolveRoute` builds for the outbound route
//!   (`dial_route.zig:70-75`) — so both directions of one relayed peer share
//!   one address, and a relayed datagram finds the connection the core built
//!   when this node dialled that peer through that relay.
//! - **A peer whose address changes is not reachable at the old one.** The map
//!   memoises, so within one map an address never changes; across maps it does,
//!   and `resolve` answers out of whichever map it is given. The old address
//!   then belongs to nobody: `node_relay_route.route` calls it
//!   `.unroutable = .foreign`, and a frame arriving afterwards is presented from
//!   the *new* address or not at all.
//!
//! **A lookup and not an allocation, and that is a decision rather than a
//! saving.** Drawing host bits for a pair nobody asked for would let a relay
//! grow this node's map one entry per datagram with node ids of its own
//! choosing, and `addr_map` evicts nothing. Worse, the address it would mint is
//! not the address any core connection was dialled with, so the datagram would
//! be presented from an address the core holds no connection for — which is
//! what `node_relay_route`'s `.foreign` refusal says about it from the other
//! end. `sourceOf` is the allocating half and belongs to the dial; this is the
//! reading half and belongs to the data path.
//!
//! # An unknown peer is dropped, and named rather than raised
//!
//! **A frame naming a peer this node holds no path for is a
//! `Disposition.dropped` carrying `node_relay_route.Drop.unknown_peer`, and the
//! datagram is gone.** Refusing loudly is the other half of the wrong answer:
//! an error out of the data path costs availability for something that is not
//! this node's fault, and the cost lands on every other peer on the stream, for
//! `node_relay_client.converse` walks one inbox and one stranger's frame must
//! not stop the frames behind it. Dropping it *silently* is the rest of the
//! wrong answer, because a relay naming a peer this node never dialled is a
//! misrouting and a misrouting nobody can see is a misrouting never fixed. So
//! it is not silent: the reason is in the returned value, which no caller
//! discards without saying so, and the counter is the caller's to keep.
//!
//! **Nothing goes on the wire.** `peer_gone` is a relay-to-client control frame
//! (`relay/server_queue.zig`'s `Control`), and a client that emitted one would
//! be speaking the server's half of a protocol it is not the server of.
//!
//! # One queue, one bound, and `deliver`'s order
//!
//! **`Room` is this node's own storage between the relay stream and the core,
//! and the decision is `node_relay_route.deliver`'s, called rather than
//! re-derived.** That is why the drop vocabulary here is that enum and not a
//! second one: the three reasons are the same three facts seen from the other
//! end — a peer this node holds no path for, a datagram too long for the bound,
//! a queue with no room — so a caller reading a drop count reads one set of
//! names whichever side of the relay produced it.
//!
//! The one field `Room` leaves out of `node_relay_route.Delivery` is
//! `target_held`, and it leaves it out because **this file is what answers
//! it**: a caller that supplied it could contradict the map it is asking about.
//!
//! **A batch is measured by its longest datagram, and one call is one queued
//! payload.** The bound is on one datagram, and `Datagrams` is the type that
//! knows where the segmentation is: a batch's datagrams are all exactly
//! `segment_size` but the last, so the segment size is the largest any of them
//! can be. Queue accounting counts whatever the caller offers — one datagram
//! is one payload, and a batch offered undrained is also one, never half of a
//! frame's segmentation. Nothing is truncated either way: `oversized` refuses
//! the frame, which is what a truncated QUIC packet cannot survive.

const std = @import("std");

const carrier = @import("carrier.zig");
const node_route = @import("../node/node_relay_route.zig");
const addr_map = @import("../transport/addr_map.zig");
const base_ula = @import("../base/ula.zig");

/// The node id a datagram came from. See `base/key.zig`.
pub const NodeId = node_route.NodeId;

/// A peer's address, direct or synthetic. See `base/addr.zig`.
pub const SocketAddr = node_route.SocketAddr;

/// Where a relay lives. See `base/relay.zig`.
pub const RelayUrl = node_route.RelayUrl;

/// The datagrams one relay frame carries. See `relay/frame.zig`.
pub const Datagrams = carrier.Datagrams;

/// Why a datagram was not delivered.
///
/// **`node_relay_route`'s enum and not a second one.** The reasons are the same
/// three facts seen from the other end, so a caller reading a drop count reads
/// one vocabulary whichever side of the relay produced it.
pub const Drop = node_route.Drop;

/// How much room this node's inbound queue has.
///
/// **The bound is the caller's, and it is never a number this file invents.**
/// `relay/server_queue.zig` makes the same arrangement for the relay's own
/// queues — capacity is the length of the storage the caller owns — and the
/// length bound is `max_datagram` because that is this node's datagram bound
/// (`node_transport.max_datagram`), which is the node's to state and not this
/// file's to guess.
pub const Room = struct {
    /// How many datagrams are already queued. A count and never a capacity.
    queued: usize,
    /// How many more the queue accepts.
    capacity: usize,
    /// The longest datagram this node will carry.
    max_datagram: usize,
};

/// What one arriving datagram becomes.
pub const Disposition = union(enum) {
    /// Present it to the core as coming from this address.
    ///
    /// **The address travels with the answer** rather than being left in the
    /// caller, because a caller that cached it would be holding a second
    /// opinion about where a peer is reached and the map is the only one this
    /// tree has.
    from_peer: SocketAddr,
    /// Drop it, for the reason `node_relay_route.Drop` names.
    dropped: Drop,
};

/// The address a datagram from `peer` over `relay` must be presented as coming
/// from, or null when this node's map holds no path for that pair.
///
/// **A reading of the map and never a change to it.** `MappedAddrs.by_key` is
/// the forward table `get` fills and this reads (`node_relay_route`'s own tests
/// read its counts for the same reason), and the key is the one
/// `node_relay_route.sourceOf` allocates: `(relay, peer)`, which lands in the
/// relay subnet. An `any_path` allocation for the same peer is a different key
/// and is not this datagram's address — it names no relay, and this datagram
/// arrived on one.
pub fn resolve(
    map: *const addr_map.MappedAddrs,
    relay: RelayUrl,
    peer: NodeId,
) ?SocketAddr {
    const key: addr_map.Key = .{ .relay = .{ .relay = relay, .node = peer } };
    const allocated = map.by_key.get(key) orelse return null;
    return base_ula.socketAddrFor(.relay, addr_map.hostBitsOf(allocated));
}

/// One payload arriving from a relay, and what it becomes.
///
/// `peer` is the node id the relay's frame named. `datagrams` is what the
/// caller offers: one datagram, or a whole batch, which is also one queued
/// payload. A caller that wants one datagram per queue slot drains the batch
/// with `Datagrams.takeSegments` and calls this once per segment, which is what
/// `node_relay_client.retain` copies. `room` is this node's queue, and its
/// three fields are `node_relay_route.deliver`'s.
///
/// **The order is `deliver`'s, unchanged:** whether this node holds the peer at
/// all, then the length, then the room. Each is a different fault with a
/// different repair, and a caller that asked about the queue first would call a
/// peer this node cannot reach "backlogged" — which says the queue is full when
/// the truth is that the peer is not here.
pub fn receive(
    map: *const addr_map.MappedAddrs,
    relay: RelayUrl,
    peer: NodeId,
    datagrams: Datagrams,
    room: Room,
) Disposition {
    const from = resolve(map, relay, peer);
    const delivery: node_route.Delivery = .{
        .target_held = from != null,
        .queued = room.queued,
        .capacity = room.capacity,
        .len = longestDatagram(datagrams),
        .max_datagram = room.max_datagram,
    };
    // The unwrap is the claim `deliver` proves: `.queued` is reached only for a
    // delivery whose `target_held` is true, and `target_held` is `from != null`.
    return switch (node_route.deliver(delivery)) {
        .queued => .{ .from_peer = from.? },
        .dropped => |why| .{ .dropped = why },
    };
}

/// The longest datagram among these, which is the bound `Room.max_datagram` is
/// about.
///
/// **A batch's answer is its segment size and not its length**, because a batch
/// is several datagrams of exactly `segment_size` with a last that may be
/// shorter, so the segment size is the largest any of them can be. It is not
/// `Send.lastDatagramLen`, which answers a different question — how much the
/// tail is short by — and would refuse every batch whose tail is small.
fn longestDatagram(datagrams: Datagrams) usize {
    return datagrams.segment_size orelse datagrams.contents.len;
}

// --- tests

const relay_test_ids = @import("relay_test_ids.zig");

const t = std.testing;

/// A relay this node is reached through.
fn relayUrl() !RelayUrl {
    return RelayUrl.parse("https://relay.example.com/");
}

/// A second relay, so a pair can be shown to be about the relay as well.
fn otherRelayUrl() !RelayUrl {
    return RelayUrl.parse("https://other.example.com/");
}

/// A queue with room in it, so a test that is not about pressure says so.
fn roomy() Room {
    return .{ .queued = 0, .capacity = 8, .max_datagram = 1500 };
}

/// One unsegmented datagram, which is the shape most arrivals have.
fn oneDatagram(payload: []const u8) Datagrams {
    return .{ .ecn = null, .segment_size = null, .contents = payload };
}

/// The address a disposition presents its datagram from, failing the test
/// rather than the runner when the datagram was dropped: a `.dropped` here is
/// a failed assertion, and `std.testing` has one error for that.
fn presented(got: Disposition) !SocketAddr {
    return switch (got) {
        .from_peer => |from| from,
        .dropped => return error.TestUnexpectedResult,
    };
}

/// A generator that hands out one scripted host value per draw, so a test can
/// name the allocation it expects.
///
/// The shape is `addr_map`'s own test generator: a real generator produces
/// distinct values, and pinning them is what lets a test about *which* address a
/// peer is at be a statement rather than a probability.
const Scripted = struct {
    script: []const base_ula.HostBits,
    at: usize = 0,

    fn fill(self: *Scripted, buf: []u8) void {
        std.debug.assert(self.script.len > 0);
        const step = @min(self.at, self.script.len - 1);
        self.at = step + 1;
        @memcpy(buf, &self.script[step]);
    }

    fn random(self: *Scripted) std.Random {
        std.debug.assert(self.script.len > 0);
        return std.Random.init(self, fill);
    }
};

// The address a relayed datagram is presented from is the one this node's map
// holds for that pair, and the core's own route names the same peer through it
// — which is what makes the datagram find the connection the core built.
test "a relayed datagram is presented from the peer's own address" {
    var engine: std.Random.DefaultPrng = .init(51);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(51);
    const relay = try relayUrl();
    // The address the *outbound* route hands the core, drawn by the module that
    // owns allocation.
    const dialled = try node_route.sourceOf(
        t.allocator,
        &map,
        relay,
        peer,
        engine.random(),
    );

    const arrived = receive(&map, relay, peer, oneDatagram("ozai"), roomy());
    try t.expectEqual(dialled, try presented(arrived));

    // It is a relay-subnet address on the mapped port, and the map says whose
    // it is: three answers a caller needs and one lookup supplies.
    try t.expectEqual(
        base_ula.Classification{ .relay = dialled.ip.v6 },
        base_ula.classify(dialled),
    );
    try t.expectEqual(node_route.Route{ .relay = peer }, node_route.route(&map, dialled));

    // Asked again, the answer is the same address and the map holds exactly as
    // many entries as it did: the ingress read the map and allocated nothing,
    // so it has no address of its own to go stale.
    try t.expectEqual(@as(usize, 1), map.by_key.count());
    try t.expectEqual(@as(?SocketAddr, dialled), resolve(&map, relay, peer));
    try t.expectEqual(
        dialled,
        try presented(receive(&map, relay, peer, oneDatagram("ozai"), roomy())),
    );
    try t.expectEqual(@as(usize, 1), map.by_key.count());
}

// A peer this node holds no path for is dropped by name, in the route's own
// vocabulary, and mints nothing on the way to the refusal.
test "a peer this node holds no path for is dropped by name and mints nothing" {
    var engine: std.Random.DefaultPrng = .init(52);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const relay = try relayUrl();
    const dialled_peer = try relay_test_ids.testNodeId(52);
    const held = try node_route.sourceOf(
        t.allocator,
        &map,
        relay,
        dialled_peer,
        engine.random(),
    );
    const stranger = try relay_test_ids.testNodeId(53);

    // A node id no map of this node's holds: dropped, and named.
    try t.expectEqual(
        Disposition{ .dropped = .unknown_peer },
        receive(&map, relay, stranger, oneDatagram("ozai"), roomy()),
    );

    // The pair is the key, so the same peer over a relay this node holds no
    // path for is the same refusal rather than a near miss. It is asked *after*
    // an `any_path` allocation for that peer exists, because that allocation
    // names no relay and a datagram that arrived over one is never answered
    // with the address the peer had before a path was chosen.
    _ = try map.get(
        t.allocator,
        .{ .any_path = dialled_peer },
        engine.random(),
    );
    try t.expectEqual(
        Disposition{ .dropped = .unknown_peer },
        receive(
            &map,
            try otherRelayUrl(),
            dialled_peer,
            oneDatagram("ozai"),
            roomy(),
        ),
    );

    // Nothing was allocated on the way to either refusal: the two tables hold
    // the dialled pair and the `any_path` key and nothing else, so a relay
    // naming node ids of its own cannot grow this node's map. And the pair that
    // *is* held still resolves to the address it was dialled at.
    try t.expectEqual(@as(usize, 2), map.by_key.count());
    try t.expectEqual(@as(usize, 2), map.by_addr.count());
    try t.expectEqual(@as(?SocketAddr, held), resolve(&map, relay, dialled_peer));
    try t.expectEqual(@as(?SocketAddr, null), resolve(&map, try otherRelayUrl(), dialled_peer));
}

// The queue is bounded by the caller's storage, one datagram at a time: a
// queue with no room refuses everything, and reaching the bound is a refusal
// rather than an eviction.
test "the queue is bounded, and reaching the bound refuses" {
    var engine: std.Random.DefaultPrng = .init(54);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const peer = try relay_test_ids.testNodeId(54);
    const relay = try relayUrl();
    _ = try node_route.sourceOf(t.allocator, &map, relay, peer, engine.random());
    const from = resolve(&map, relay, peer) orelse return error.TestUnexpectedResult;
    const held = oneDatagram("ozai");

    try t.expectEqual(
        Disposition{ .from_peer = from },
        receive(&map, relay, peer, held, roomy()),
    );

    // One slot short of the bound is carried and one at it is not, which is
    // what makes the bound a count rather than a comparison with slack. The
    // datagram is dropped and nothing else: this node's queue is full, and the
    // peer it belongs to is still there.
    try t.expectEqual(
        Disposition{ .from_peer = from },
        receive(&map, relay, peer, held, .{ .queued = 7, .capacity = 8, .max_datagram = 1500 }),
    );
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        receive(&map, relay, peer, held, .{ .queued = 8, .capacity = 8, .max_datagram = 1500 }),
    );

    // A queue with no room at all refuses everything, which the decision
    // answers honestly rather than dividing by zero, and a queue asked about
    // beyond its depth is refused on the same rule rather than underflowing.
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        receive(&map, relay, peer, held, .{ .queued = 0, .capacity = 0, .max_datagram = 1500 }),
    );
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        receive(&map, relay, peer, held, .{ .queued = 9, .capacity = 8, .max_datagram = 1500 }),
    );

    // A batch is measured and queued as one payload, because a caller cannot be
    // handed half of one frame's segmentation: three datagrams of four bytes
    // fit a queue of eight and do not fit a queue of two.
    const batch: Datagrams = .{ .ecn = .ect1, .segment_size = 4, .contents = "abcdefghijk" };
    try t.expectEqual(
        Disposition{ .from_peer = from },
        receive(&map, relay, peer, batch, roomy()),
    );
    try t.expectEqual(
        Disposition{ .dropped = .backlogged },
        receive(&map, relay, peer, batch, .{ .queued = 2, .capacity = 2, .max_datagram = 1500 }),
    );
}

// The bound is on one datagram, so a batch is measured by the segment size and
// not by its length, and nothing is truncated.
test "the bound is on one datagram, so a batch is measured by its segment size" {
    var engine: std.Random.DefaultPrng = .init(55);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const peer = try relay_test_ids.testNodeId(55);
    const relay = try relayUrl();
    _ = try node_route.sourceOf(t.allocator, &map, relay, peer, engine.random());
    const from = resolve(&map, relay, peer) orelse return error.TestUnexpectedResult;

    // Four datagrams of exactly the bound is 6000 bytes and is carried: the
    // bound is 1500 *a datagram*, and 6000 bytes of payload is four of them.
    const at_bound: Datagrams = .{ .ecn = null, .segment_size = 1500, .contents = "x" ** 6000 };
    try t.expectEqual(
        Disposition{ .from_peer = from },
        receive(&map, relay, peer, at_bound, roomy()),
    );

    // One byte over the bound in a single datagram is refused rather than
    // truncated, because a truncated QUIC packet is one the peer cannot use.
    const too_long = oneDatagram("x" ** 1501);
    try t.expectEqual(
        Disposition{ .dropped = .oversized },
        receive(&map, relay, peer, too_long, roomy()),
    );
    // And one byte over it in every datagram of a batch is the same refusal,
    // measured off the segment size rather than off the payload.
    try t.expectEqual(
        Disposition{ .dropped = .oversized },
        receive(
            &map,
            relay,
            peer,
            .{ .ecn = null, .segment_size = 1501, .contents = "x" ** 3002 },
            roomy(),
        ),
    );

    // The reason is the length and not the queue: refused with room to spare,
    // because a datagram that could not be carried must never be counted as
    // waiting for room.
    try t.expectEqual(
        Disposition{ .dropped = .oversized },
        receive(
            &map,
            relay,
            peer,
            too_long,
            .{ .queued = 0, .capacity = 8, .max_datagram = 1500 },
        ),
    );
}

// Every drop reason `node_relay_route.Drop` names is reachable from this
// direction, and the table is as long as the enum so a reason added there fails
// here rather than passing unnoticed.
test "every drop reason in the route's vocabulary is reachable here" {
    var engine: std.Random.DefaultPrng = .init(56);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const peer = try relay_test_ids.testNodeId(56);
    const relay = try relayUrl();
    _ = try node_route.sourceOf(t.allocator, &map, relay, peer, engine.random());
    const held = oneDatagram("ozai");
    const long = oneDatagram("x" ** 1501);
    const full = Room{ .queued = 8, .capacity = 8, .max_datagram = 1500 };

    const reachable = [_]struct { peer: NodeId, payload: Datagrams, room: Room, want: Drop }{
        // A peer this node holds no path for.
        .{
            .peer = try relay_test_ids.testNodeId(57),
            .payload = held,
            .room = roomy(),
            .want = .unknown_peer,
        },
        // A datagram longer than the bound, with room to spare.
        .{ .peer = peer, .payload = long, .room = roomy(), .want = .oversized },
        // A queue with no room, for a datagram that would otherwise be carried.
        .{ .peer = peer, .payload = held, .room = full, .want = .backlogged },
    };
    try t.expectEqual(@typeInfo(Drop).@"enum".fields.len, reachable.len);
    for (reachable) |case| {
        try t.expectEqual(
            Disposition{ .dropped = case.want },
            receive(&map, relay, case.peer, case.payload, case.room),
        );
    }
}

// A peer whose address changed is presented from the address the map holds now,
// and the one it held before reaches nothing: the ingress reads the map per
// datagram and keeps no address of its own to go stale.
test "a peer whose address changed is not reachable at the old one" {
    const first_hosts = [_]base_ula.HostBits{.{0x11} ** 8};
    const second_hosts = [_]base_ula.HostBits{.{0x22} ** 8};
    const peer = try relay_test_ids.testNodeId(58);
    const relay = try relayUrl();
    const payload = oneDatagram("ozai");

    var first_script: Scripted = .{ .script = &first_hosts };
    var first = addr_map.MappedAddrs.init();
    const old = try node_route.sourceOf(
        t.allocator,
        &first,
        relay,
        peer,
        first_script.random(),
    );
    try t.expectEqual(old, try presented(receive(&first, relay, peer, payload, roomy())));
    first.deinit(t.allocator);

    // The map is rebuilt and the same pair is allocated different host bits.
    var second_script: Scripted = .{ .script = &second_hosts };
    var second = addr_map.MappedAddrs.init();
    defer second.deinit(t.allocator);
    const new = try node_route.sourceOf(
        t.allocator,
        &second,
        relay,
        peer,
        second_script.random(),
    );
    // `.order` and not `==`: this build refuses the equality operator on an
    // aggregate, and `SocketAddr` is one. `node_relay_route`'s own test says
    // the same of two `sourceOf` results it drew the same way.
    try t.expect(old.order(new) != .eq);

    // The datagram is presented from the address in force now, and the one it
    // was presented from before belongs to nobody: `route` calls it foreign,
    // which is what stops a connection built against it from being reached.
    try t.expectEqual(new, try presented(receive(&second, relay, peer, payload, roomy())));
    try t.expectEqual(
        node_route.Route{ .unroutable = .foreign },
        node_route.route(&second, old),
    );

    // And a map that never allocated this pair at all answers nothing rather
    // than a fresh address, so a datagram from an unknown peer cannot invent a
    // path for itself.
    var empty = addr_map.MappedAddrs.init();
    defer empty.deinit(t.allocator);
    try t.expectEqual(
        Disposition{ .dropped = .unknown_peer },
        receive(&empty, relay, peer, payload, roomy()),
    );
}
