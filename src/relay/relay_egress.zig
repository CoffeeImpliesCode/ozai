//! Where one datagram the core wants to send actually goes, and what a write
//! that failed leaves behind.
//!
//! `node_transport.drain` is the node's whole egress: for every datagram the
//! core produces it calls `self.socket.send(io, egress.to, egress.send)`
//! (`node_transport.zig:121-132`). That is right for a direct path and wrong
//! for every other one, because a peer reached through a relay is dialled at a
//! *synthetic* address (`transport/dial_route.zig`) and no socket can route a
//! packet to `fd15:70a:510b:1::/64`. This file is the decision in front of that
//! write: the carrier is the socket or this node's relay stream, and the answer
//! comes from the address alone.
//!
//! # Everything routing is `node_relay_route`'s, and none of it is restated
//!
//! `node/node_relay_route.zig` already answers "where does an egress go" from
//! the address, and owns the address a relayed peer is reached at. `step` calls
//! its `route` and passes nothing else; the payload becomes a frame through
//! its `relayMessage`, which is `relay/carrier.zig`'s `carry` with the peer the
//! route named. What is added here is the part that only a node can be true
//! about: which arm a caller acts on, what the three refusals mean at a
//! socket, and what a write that failed does.
//!
//! # The address decides, and a peer is not a relay
//!
//! **`Carrier.socket` is right for every real address and `Carrier.relay` for
//! exactly one subnet.** The map is what turns `fd15:70a:510b:1::/64` back into
//! the node id behind it, so "is this the relay's" is a fact about this node's
//! own allocations and not about the address's shape — a `fd15:` address
//! somebody else's map handed out is refused rather than sent to UDP.
//!
//! **A `RelayWrite` names the peer and not the relay, and that is the route's
//! own rule** rather than a convenience: the frame is addressed to the node id,
//! and which relay a datagram goes out on is a fact the caller already holds —
//! it chose the path that named the stream. Two relays to one peer therefore
//! produce two identical `RelayWrite`s, which is correct: the bytes are the
//! same and only the stream differs.
//!
//! # A failed direct path does not redirect this datagram
//!
//! **The datagram is spent, the path is recorded, and the next egress is the
//! first that may go elsewhere.** Three facts, and the first settles it:
//!
//! 1. **A route is a property of the address, and the address is fixed.** The
//!    core was dialled with one synthetic address per `(peer, relay)` pair and
//!    every egress it produces for that connection names that address. Sending
//!    one of them through the relay instead puts a single connection's packets
//!    on two paths, which is path migration: the peer has to validate the new
//!    path and this transport has nothing to ask it with. There is also nowhere
//!    to move it *to* — a peer with no relay route has no `(peer, relay)` key
//!    in the map, and minting one is a dial, not a send.
//! 2. **A failed write is a fact about a path, and the tree already owns when
//!    traffic moves.** `net/path_table` records a path and `net/path_select`
//!    refuses an `.unusable` one and picks again. Counting failures here would
//!    be a second policy about a fact one module already answers.
//! 3. **Immediate fallback turns one unreachable peer into relay traffic.** A
//!    drain hands back up to `node_transport.max_egress` (8) datagrams and a
//!    GSO burst is one egress carrying several, so a single refused write
//!    would turn the rest of the burst into relay frames for a peer that is not
//!    there — frames a relay queues and then drops as `backlogged`. The
//!    counters lie as well: `node_transport.drain` adds
//!    `send.datagramCount()` to `datagrams_out` *before* the socket write, so a
//!    re-send through the relay is counted twice for one datagram.
//!
//! So `failed` reports what the refusal was and names no carrier, and `step` —
//! whose parameters have nowhere to put a failure — answers the next egress
//! from the route alone.
//!
//! Nothing here reads a clock, opens a socket, allocates, or holds state:
//! `step` is a function of an address and a payload, `failed` of a carrier, and
//! the `Message` a `RelayWrite` carries borrows the caller's payload exactly as
//! `carrier.carry` documents.

const std = @import("std");

const node_route = @import("../node/node_relay_route.zig");
const addr_map = @import("../transport/addr_map.zig");


/// The node id a datagram is for. See `base/key.zig`.
pub const NodeId = node_route.NodeId;

/// A peer's address, direct or synthetic. See `base/addr.zig`.
pub const SocketAddr = node_route.SocketAddr;

/// The payload a core egress carries. See `transport/batch.zig`.
pub const Send = node_route.Send;

/// The frame one relay message carries. See `relay/carrier.zig`.
pub const Message = node_route.Message;

/// Why a payload cannot be carried. See `relay/carrier.zig`.
pub const CarryError = node_route.CarryError;

/// Why an address cannot be carried. See `node/node_relay_route.zig`.
pub const Unroutable = node_route.Unroutable;

/// The relay stream write one relayed egress becomes.
///
/// **Both fields are borrowed or copied out of values the caller holds.**
/// `message` carries `Send.contents` without copying it, so the payload must
/// stay alive and unmutated until the caller has encoded the frame — the same
/// rule `carrier.carry` states.
pub const RelayWrite = struct {
    /// The peer behind the address, which is the frame's destination.
    peer: NodeId,
    /// The one message to write on the relay stream.
    message: Message,
};

/// The two carriers one egress has, and which of them carries it.
pub const Carrier = union(enum) {
    /// A socket write, at exactly the address the core asked for.
    ///
    /// **The address travels with the answer** rather than being left in the
    /// caller, because `Route.direct` is armless: `route` answers `.direct`
    /// for anything that is not one of its three synthetic subnets and carries
    /// no address of its own, so a `void` arm would send a caller back to the
    /// egress it already had.
    socket: SocketAddr,
    /// One relay message on the stream for the path that named it.
    relay: RelayWrite,
};

/// Why there is no carrier, and each one named because each is a different
/// fault with a different repair.
pub const Refusal = union(enum) {
    /// The address names the peer before a path was chosen.
    ///
    /// **This module does not choose paths, and the refusal is what says so.**
    /// `route` answers `.multipath` with the peer and stops: upstream
    /// duplicates a packet addressed to the peer across every candidate path
    /// (`iroh/src/socket/remote_map.rs`), which is a decision about paths and
    /// not about relaying. A caller that wants one path picks it and calls
    /// `step` again with an address that names it.
    path_unselected,
    /// Not this node's to carry, in `route`'s own two ways: a synthetic
    /// address this node's map never handed out, or a custom transport address
    /// it does own and the relay protocol has no frame for.
    unroutable: Unroutable,
    /// The payload this protocol cannot carry, in `carrier`'s own words: longer
    /// than the frame's bound, or a batch frame whose segment size names no
    /// datagram. Refused rather than truncated, for the reason
    /// `node_relay_route.Drop`'s `.oversized` gives.
    uncarryable: CarryError,
};

/// What one egress becomes: the carrier, or the reason there is none.
pub const Step = union(enum) {
    /// Write it here.
    carried: Carrier,
    /// It goes nowhere, and this is why.
    refused: Refusal,
};

/// What one egress becomes, given where the core addressed it.
///
/// **The address is the whole input, and `route` reads the map and nothing
/// else** — no connection table, no relay client, no socket. A caller with an
/// egress and an address gets its answer before anything else is consulted,
/// which is what keeps the decision testable without a node.
///
/// The order is `route`'s: an address the map owns is resolved before the
/// payload is looked at, so a relayed peer never has its datagram measured
/// against a socket's bound, and a payload the codec cannot carry is refused
/// before any message exists — a relay must never count a datagram it then
/// failed to write.
pub fn step(map: *const addr_map.MappedAddrs, to: SocketAddr, send: Send) Step {
    return switch (node_route.route(map, to)) {
        .direct => .{ .carried = .{ .socket = to } },
        .relay => |peer| relayWrite(peer, send),
        .multipath => .{ .refused = .path_unselected },
        .unroutable => |why| .{ .refused = .{ .unroutable = why } },
    };
}

/// One relay message for `peer`, or the codec's own refusal.
fn relayWrite(peer: NodeId, send: Send) Step {
    const message = node_route.relayMessage(peer, send) catch |err| {
        return .{ .refused = .{ .uncarryable = err } };
    };
    return .{ .carried = .{ .relay = .{ .peer = peer, .message = message } } };
}

/// What one refused write leaves behind, given the carrier that refused it.
///
/// **No arm carries a carrier, a route or an address, and that is the whole of
/// the decision above.** A refused write is reported and nothing is re-sent: a
/// `direct_refused` tells the caller to record the path before it selects
/// again, and neither arm answers "put it on the other carrier".
pub const Failure = union(enum) {
    /// The socket refused the datagram, so the direct path is unusable and the
    /// caller must record that — `net/path_table` owns where a recorded
    /// failure lives, and `net/path_select.selectable` is what then refuses to
    /// select onto it.
    direct_refused,
    /// The relay could not be given the datagram: it did not fit, or the
    /// stream would not take it. No path is implicated — the direct one was
    /// never tried, and a relay's queue is the relay's storage rather than a
    /// network path this node has failed.
    relay_refused,
};

/// What a write that failed means for routing.
///
/// `attempted` is the arm `step` answered, and the caller holds the datagram's
/// fate already: it belongs to one egress on one path, and the core owns its
/// retransmission, so nothing here offers it a second carrier.
pub fn failed(attempted: Carrier) Failure {
    return switch (attempted) {
        .socket => .direct_refused,
        .relay => .relay_refused,
    };
}

// --- tests

const relay_test_ids = @import("relay_test_ids.zig");
const base_ula = @import("../base/ula.zig");
const carrier = @import("carrier.zig");
const frame = @import("frame.zig");

const t = std.testing;

/// The relay the tests below dial through.
fn relayUrl() !node_route.RelayUrl {
    return node_route.RelayUrl.parse("https://relay.example.com/");
}

/// A real socket address, which no map owns and which `route` calls direct.
fn directAddr() SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };
}

/// The socket address a mapped allocation is reached at, which is the subnet of
/// the key arm and nothing else.
fn anyPathAddr(allocated: base_ula.Ula) SocketAddr {
    return base_ula.socketAddrFor(.any_path, addr_map.hostBitsOf(allocated));
}

/// The custom transport address a mapped allocation is reached at.
fn customAddr(allocated: base_ula.Ula) SocketAddr {
    return base_ula.socketAddrFor(.custom, addr_map.hostBitsOf(allocated));
}

// The whole egress in one test: a peer behind the relay becomes one relay
// message on the wire, a real address becomes a socket write at that address,
// and the second relay to the same peer changes nothing but the stream.
test "a relayed peer's egress is one relay message and a direct one a socket write" {
    var engine: std.Random.DefaultPrng = .init(41);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const peer = try relay_test_ids.testNodeId(41);
    const relay = try relayUrl();
    const via = try node_route.sourceOf(t.allocator, &map, relay, peer, engine.random());

    // What `Conn.drain` would have handed the socket: a GSO burst of three
    // datagrams of four bytes with a codepoint, addressed to the synthetic
    // address the core was dialled with.
    const send = try Send.batch("abcdefghijk", 4, .ect0);
    try t.expectEqual(@as(usize, 3), send.datagramCount());

    const stepped = step(&map, via, send);
    const carried = stepped.carried;
    try t.expectEqual(peer, carried.relay.peer);
    try t.expectEqual(
        frame.FrameType.client_to_relay_datagram_batch,
        std.meta.activeTag(carried.relay.message),
    );

    // Through the real codec the message comes back as three datagrams of the
    // same segmentation and the same codepoint, addressed to that peer — which
    // is what the relay will put on the destination client's queue.
    var out: [128]u8 = undefined;
    const decoded = carrier.carried(
        try frame.decode(try frame.encode(carried.relay.message, .v2, &out), .v2),
    ).?;
    try t.expectEqual(peer, decoded.node_id);
    try t.expectEqual(@as(?u16, 4), decoded.datagrams.segment_size);
    try t.expectEqual(@as(?frame.Ecn, .ect0), decoded.datagrams.ecn);
    try t.expectEqualStrings("abcdefghijk", decoded.datagrams.contents);

    // A real address is a socket write at exactly the address asked for, and
    // one `Send` value produces both — the payload is not consumed by the
    // relay arm and nothing is copied by either.
    const real = directAddr();
    try t.expectEqual(
        Step{ .carried = .{ .socket = real } },
        step(&map, real, send),
    );

    // The second relay to the same peer puts the *same bytes* on the wire: the
    // route carries the peer and not the relay, so which stream it is written
    // to is a fact the caller holds and this file is never told. Comparing the
    // encoded frames rather than the two `Message` values is what makes the
    // claim about the wire instead of about this tree's borrowing.
    const elsewhere = try node_route.sourceOf(
        t.allocator,
        &map,
        try node_route.RelayUrl.parse("https://other.example.com/"),
        peer,
        engine.random(),
    );
    var other_bytes: [128]u8 = undefined;
    try t.expectEqualSlices(
        u8,
        try frame.encode(carried.relay.message, .v2, &out),
        try frame.encode(
            step(&map, elsewhere, send).carried.relay.message,
            .v2,
            &other_bytes,
        ),
    );
}

// A peer before a path was chosen is refused rather than guessed at, and the
// two addresses this node's map never handed out are refused in `route`'s own
// words rather than a second set.
test "an address this node cannot carry is refused, and by route's own names" {
    var engine: std.Random.DefaultPrng = .init(43);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const send = Send.single("ozai", null);

    // The peer itself, before a path was chosen: this module does not choose
    // one, and a caller that wants one picks it and calls again.
    const any = try map.get(
        t.allocator,
        .{ .any_path = try relay_test_ids.testNodeId(43) },
        engine.random(),
    );
    try t.expectEqual(
        Step{ .refused = .path_unselected },
        step(&map, anyPathAddr(any), send),
    );

    // Somebody else's relay subnet, and a packet in this node's own ULAs,
    // look the same way from here: the reverse index holds nothing for either.
    const foreign = base_ula.socketAddrFor(.relay, @splat(0x11));
    try t.expectEqual(
        Step{ .refused = .{ .unroutable = .foreign } },
        step(&map, foreign, send),
    );

    // A custom transport address this node *does* own is a different refusal:
    // the address is ours and the relay protocol still has no frame for it.
    var payload: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const custom = addr_map.CustomKey.from(.{
        .id = 7,
        .data = payload[0..],
    }) catch return error.TestUnexpectedResult;
    const owned = try map.get(t.allocator, .{ .custom = custom }, engine.random());
    try t.expectEqual(
        Step{ .refused = .{ .unroutable = .custom } },
        step(&map, customAddr(owned), send),
    );
}

// The relay's bound is the relay's, checked before a message exists, and it is
// not applied to a payload that is going to a socket.
test "a payload the protocol cannot carry is refused by the codec's own name" {
    const peer = try relay_test_ids.testNodeId(44);
    const gpa = t.allocator;
    const room = carrier.max_payload - carrier.DatagramFrame.header_length;
    const exact = try gpa.alloc(u8, room);
    defer gpa.free(exact);
    const over = try gpa.alloc(u8, room + 1);
    defer gpa.free(over);

    var engine: std.Random.DefaultPrng = .init(44);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(gpa);
    const via = try node_route.sourceOf(
        gpa,
        &map,
        try relayUrl(),
        peer,
        engine.random(),
    );

    // One byte over the frame's bound, refused as the codec would refuse it and
    // not as a name of this file's own.
    try t.expectEqual(
        Step{ .refused = .{ .uncarryable = error.FrameTooLarge } },
        step(&map, via, Send.single(over, null)),
    );
    // A batch frame whose segment size names no datagram is the other codec
    // refusal, and it is reached the same way.
    try t.expectEqual(
        Step{ .refused = .{ .uncarryable = error.ZeroSegmentSize } },
        step(&map, via, .{ .ecn = null, .segment_size = 0, .contents = "" }),
    );
    // Exactly filling the bound is carried, so the refusal is the bound and not
    // an off-by-one.
    try t.expectEqual(
        peer,
        step(&map, via, Send.single(exact, null)).carried.relay.peer,
    );

    // The same payload to a socket is a socket write, and the relay's bound is
    // not this node's datagram bound: a direct socket has its own, and a
    // payload the relay protocol cannot carry is still a datagram.
    const real = directAddr();
    try t.expectEqual(
        Step{ .carried = .{ .socket = real } },
        step(&map, real, Send.single(over, null)),
    );
}

// A failed write is told apart from a failed relay, and neither arm can carry
// a second carrier: the decision that a refused direct write is not re-sent is
// a property of the type rather than of a comment.
test "a refused write is reported and re-addresses nothing" {
    var engine: std.Random.DefaultPrng = .init(45);
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    const send = try Send.batch("abcdefghijk", 4, .ect0);
    const peer = try relay_test_ids.testNodeId(45);
    const via = try node_route.sourceOf(
        t.allocator,
        &map,
        try relayUrl(),
        peer,
        engine.random(),
    );

    const two: [2]Failure = .{
        failed(step(&map, directAddr(), send).carried),
        failed(step(&map, via, send).carried),
    };
    try t.expectEqual(Failure.direct_refused, two[0]);
    try t.expectEqual(Failure.relay_refused, two[1]);

    // No arm carries anything at all: `void` is the type of a payload-less
    // union field, so an arm holding a route, an address or a carrier fails
    // here rather than passing review.
    const fields = @typeInfo(Failure).@"union".fields;
    try t.expectEqual(@as(usize, 2), fields.len);
    inline for (fields) |field| try t.expect(field.type == void);

    // And the decision is in `step`'s own signature: three parameters, and none
    // of them is a failure, a carrier or a route. A `step` that could see a
    // refused write would need a fourth, and this fails when one is added —
    // which is what stops the redirect from arriving as an "improvement".
    const params = @typeInfo(@TypeOf(step)).@"fn".params;
    try t.expectEqual(@as(usize, 3), params.len);
    inline for (params) |param| {
        try t.expect(param.type.? != Failure);
        try t.expect(param.type.? != Carrier);
    }
}