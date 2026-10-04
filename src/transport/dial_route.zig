//! The address half of a dial: a target becomes an address, and an address
//! becomes the key that owns it.
//!
//! `dial.zig` opens a connection. This file answers the two questions either
//! side of that needs answered first and asks again on every datagram:
//!
//!   * **which address** does this target live at — the core's half of the
//!     split, where the core is told a socket address and the caller is handed
//!     the key it stands for, and
//!   * **whose key** owns a socket address — the egress-side twin of what
//!     `Bridge.recv` computes on the way in.
//!
//! `dial.zig`'s module doc is where the *why* is: `base/ula.zig` maps the two
//! non-IP arms of a target onto synthetic RFC 4193 addresses,
//! `transport/addr_map.zig` memoises them, and the two vocabularies — the core's
//! address and this project's — meet in exactly one place on each side.
//!
//! # Nothing here opens a connection
//!
//! That is the split. Everything below is arithmetic over a map, a subnet and
//! a key: no manager, no TLS, no `Connection`, no socket. A direct target does
//! not allocate at all; the two synthetic ones go through `addr_map`, which is
//! where their ownership lives — a mapping outlives the frame that produced the
//! address, so a key that borrowed from that frame would be read back over
//! bytes already reused. That is why the custom arm copies its payload with
//! `addr_map.CustomKey.from` and the relay arm takes its URL by value.
//!
//! # Purity, with one exception that is named rather than hidden
//!
//! No clock and no global. `random` is a parameter of `resolveRoute` and not of
//! `ownerOf`, because resolving a target into an address draws host bits and
//! turning an address back into a key does not: the second is a lookup, and a
//! lookup that drew entropy would be a lookup whose answer depended on how many
//! times it had been asked.

const std = @import("std");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const base_transport_addr = @import("../base/transport_addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");

const NodeId = base_key.NodeId;
const SocketAddr = base_addr.SocketAddr;
const TransportAddr = base_transport_addr.TransportAddr;

/// What this path refuses.
///
/// Routing can refuse an invalid custom key, a failed map allocation, or a
/// relay target without a peer identity. It does not depend on the dial driver.
pub const Error = base_addr.CustomAddrParseError || addr_map.GetError || error{NoPeerId};

/// The address a target is reached at, and the key behind it.
pub const Route = struct {
    /// The address the core is told. A synthetic RFC 4193 address for a relay
    /// or a custom target, and the target's own address for a direct one.
    socket: SocketAddr,
    /// The key that owns `socket`, or null on a direct path: upstream never
    /// puts an IP in the map, and this one does not either.
    key: ?addr_map.Key,
    /// Which synthetic subnet `socket` sits in, or null on a direct path, which
    /// has none. This and `key` are both null exactly when `socket` is one of
    /// the caller's own.
    subnet: ?base_ula.Path,
};

/// What a target becomes: one address the core is told, and one key the caller
/// keeps.
///
/// Direct targets do not allocate. Relay targets require `peer` and return
/// `error.NoPeerId` when it is null. Custom targets copy their payload into the
/// key and do not use `peer`. Allocation errors leave existing mappings intact,
/// but may retain map capacity and consume random draws.
pub fn resolveRoute(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    transport: TransportAddr,
    peer: ?NodeId,
    random: std.Random,
) Error!Route {
    switch (transport) {
        .ip => |socket| return .{ .socket = socket, .key = null, .subnet = null },
        .relay => |url| return routeThrough(
            gpa,
            map,
            .{ .relay = .{ .relay = url, .node = peer orelse return error.NoPeerId } },
            .relay,
            random,
        ),
        .custom => |custom| return routeThrough(
            gpa,
            map,
            // `from` copies the data into the key. An entry outlives the frame
            // that produced the address, so a key pointing into it would be
            // read back over bytes already reused.
            .{ .custom = try addr_map.CustomKey.from(custom) },
            .custom,
            random,
        ),
    }
}

/// The address a synthetic key is reached at, on the subnet its arm names.
fn routeThrough(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    key: addr_map.Key,
    subnet: base_ula.Path,
    random: std.Random,
) Error!Route {
    return .{
        .socket = base_ula.socketAddrFor(
            subnet,
            addr_map.hostBitsOf(try map.get(gpa, key, random)),
        ),
        .key = key,
        .subnet = subnet,
    };
}

/// The key that owns `socket` on this node's map, or null.
///
/// The egress-side twin of what `Bridge.recv` computes on the way in
/// (`quic_bridge.zig:574`). A sender has to answer the same two questions a
/// receiver does — which subnet the address is in, and whose key stands behind
/// it — to know which socket to put the datagram on, and `Conn.drain` hands
/// over the address alone. It is the same `classify`-then-`lookup` the bridge
/// makes; there is no seam to call there, so it is written out, and the two
/// must agree about the three subnets or a dialled connection is sent on a
/// socket it did not open.
pub fn ownerOf(map: *const addr_map.MappedAddrs, socket: SocketAddr) ?addr_map.Key {
    return switch (base_ula.classify(socket)) {
        .ip => null,
        .any_path, .relay, .custom => |octets| map.lookup(octets),
    };
}

const t = std.testing;

/// Seeded engine kept stable while calls use its `std.Random` interface.
const Prng = std.Random.DefaultPrng;

/// A node whose id pairs with a relay in a `(relay, node)` key.
const peer_seed: [base_key.SecretKey.seed_length]u8 = @splat(0x3c);

/// A direct target's address, which is the caller's own and stays that way.
const direct_addr: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 4433 };

/// The relay every relay-arm test resolves. A URL is a parsed value and a
/// hand-built one would be a second way to say the same thing.
fn relayTarget() !TransportAddr {
    return .{ .relay = try base_relay_url.RelayUrl.parse("https://relay.example.com") };
}

test "a direct target is its own address, and nothing is allocated for it" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(1);

    const route = try resolveRoute(
        t.allocator,
        &map,
        .{ .ip = direct_addr },
        null,
        engine.random(),
    );

    // Both key and subnet null is what "a direct path" is, and the address is
    // the target's own rather than something out of the map.
    try t.expectEqual(direct_addr, route.socket);
    try t.expectEqual(@as(?addr_map.Key, null), route.key);
    try t.expectEqual(@as(?base_ula.Path, null), route.subnet);
    // And the egress side agrees with the ingress side: a real IP is nobody's
    // key, which is the answer `Bridge.recv` computes on the way in too.
    try t.expectEqual(
        base_ula.Classification{ .ip = direct_addr },
        base_ula.classify(route.socket),
    );
    try t.expectEqual(@as(?addr_map.Key, null), ownerOf(&map, route.socket));

    // Nothing was allocated, in either direction of the map.
    try t.expectEqual(@as(usize, 0), map.by_key.count());
    try t.expectEqual(@as(usize, 0), map.by_addr.count());
}

test "a relay target is one synthetic address, and the map says whose" {
    var peer = try base_key.SecretKey.fromSeed(peer_seed);
    defer peer.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(2);

    const route = try resolveRoute(
        t.allocator,
        &map,
        try relayTarget(),
        peer.nodeId(),
        engine.random(),
    );

    try t.expectEqual(base_ula.Path.relay, route.subnet.?);

    // The address is a real one this host could open a socket on, in the relay
    // subnet rather than anywhere the relay actually listens — which is the
    // whole of what `DECISIONS/0001` asks for and why `Conn.drain` has to hand
    // the caller a key to go with it.
    try t.expectEqual(
        @as(?addr_map.Key, route.key.?),
        ownerOf(&map, route.socket),
    );
    try t.expectEqual(@as(usize, 1), map.by_key.count());
    try t.expectEqual(@as(usize, 1), map.by_addr.count());
}

test "a relay target with no peer is refused, and draws nothing" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(3);

    try t.expectError(
        error.NoPeerId,
        resolveRoute(t.allocator, &map, try relayTarget(), null, engine.random()),
    );

    // The refusal is the first thing that arm does, so no host bits were drawn
    // and no entry allocated: a refused relay route leaves nothing to clean up.
    try t.expectEqual(@as(usize, 0), map.by_key.count());
    try t.expectEqual(@as(usize, 0), map.by_addr.count());
}

test "a custom target is its own subnet, and the key owns the bytes" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(4);

    var payload = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const route = try resolveRoute(
        t.allocator,
        &map,
        .{ .custom = .{ .id = 7, .data = &payload } },
        null,
        engine.random(),
    );

    try t.expectEqual(base_ula.Path.custom, route.subnet.?);
    try t.expectEqual(@as(u64, 7), route.key.?.custom.id);
    try t.expectEqual(@as(?addr_map.Key, route.key.?), ownerOf(&map, route.socket));

    // **The key owns the payload.** `CustomAddr.data` borrows the caller's
    // bytes, so a key pointing at them would be read back over whatever the
    // caller put there next — which is what the map entry outliving the frame
    // that produced it means. Overwriting the caller's copy proves the key is
    // not pointing at it.
    @memset(&payload, 0xa5);
    try t.expectEqualSlices(
        u8,
        &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
        route.key.?.custom.dataSlice(),
    );
}

test "a custom address too long for a key is refused, not truncated" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(5);

    const oversize = [_]u8{0x01} ** (base_addr.max_inline_length + 1);
    try t.expectError(
        error.DataTooLong,
        resolveRoute(
            t.allocator,
            &map,
            .{ .custom = .{ .id = 1, .data = &oversize } },
            null,
            engine.random(),
        ),
    );

    // A key that silently cut the payload off would send the peer somewhere
    // that is not here, so the refusal is the whole of the answer — and it
    // happened before a single host bit was drawn.
    try t.expectEqual(@as(usize, 0), map.by_key.count());
}
