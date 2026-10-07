//! A target becomes one address the core is told and one key the caller keeps,
//! and one address turns back into its key on the way out.
//!
//! Split out of `transport/dial.zig`, which is now the facade over this and
//! three other named modules. The boundary is drawn before the connection
//! exists: everything here is a decision about an address, and `dial_client`
//! is the machine that turns the answer into a `Connection`. That is also
//! where the hard one-path-per-connection ceiling is stated — one target, one
//! address, one connection — because a second address on a live connection is a
//! migration, and the choice of which target to use belongs to the caller.

const std = @import("std");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const quic_bridge = @import("quic_bridge.zig");
const dial_config = @import("dial_config.zig");

const NodeId = base_key.NodeId;
const SocketAddr = base_addr.SocketAddr;
const TransportAddr = base_addr.TransportAddr;

const Error = dial_config.Error;
const Conn = quic_bridge.Conn;

/// One target and the node behind it: a dial's whole reason to exist.
///
/// A `NodeAddr` is a list of these, and one of them is one connection — see the
/// module doc on paths.
pub const Dial = struct {
    /// The connection, borrowed out of the manager. Drive it with the bridge's
    /// `recv`, `tick` and `sweep` exactly as an accepted one, and it is freed
    /// by `sweep` or by `Bridge.destroy`, never by the dialer.
    conn: Conn,
    /// The address the core was told, and what it stands for.
    route: Route,
};

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
/// Relay URLs choose the physical carrier, not the inner peer identity. Relay
/// ingress and every configured relay for this peer share its any-path address.
pub fn resolveRoute(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    transport: TransportAddr,
    peer: ?NodeId,
    random: std.Random,
) Error!Route {
    switch (transport) {
        .ip => |socket| return .{ .socket = socket, .key = null, .subnet = null },
        .relay => return routeThrough(
            gpa,
            map,
            .{ .any_path = peer orelse return error.NoPeerId },
            .any_path,
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

// The pair of ends a dial is closed against, named here so the tests below
// stand as they were written.
const pair_mod = @import("dial_pair.zig");
const client_seed = pair_mod.client_seed;
const server_seed = pair_mod.server_seed;
const direct_addr = pair_mod.direct_addr;
const Prng = pair_mod.Prng;
const CustomAddr = base_addr.CustomAddr;
const Pair = pair_mod.Pair;
const relayTarget = pair_mod.relayTarget;

test "a relay target becomes one address the core is told, and the map says whose" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 1, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();

    var route_engine = Prng.init(2);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        try relayTarget(),
        peer,
        route_engine.random(),
    );

    // Three separate answers, and the dial needs all three: the core is told
    // the address, the caller is handed the key, and `ula.classify` is what a
    // receiver on the other side will use to get the key back.
    try t.expectEqual(base_ula.Path.any_path, route.subnet.?);
    try t.expectEqual(
        base_ula.Classification{ .any_path = route.socket.ip.v6 },
        base_ula.classify(route.socket),
    );
    // The peer identity is stable across carrier URLs and ingress/egress.
    try t.expectEqualSlices(u8, &base_ula.prefixFor(.any_path), route.socket.ip.v6[0..8]);
    try t.expectEqual(base_ula.mapped_port, route.socket.port);
    const expected_key: addr_map.Key = .{ .any_path = peer };
    try t.expectEqual(expected_key, route.key.?);
    // And the map agrees, which is what lets a sender turn an `Egress` back
    // into a peer and a relay.
    try t.expectEqual(route.key.?, ownerOf(&pair.map, route.socket).?);

    // Memoised: the same target answers with the same address for the life of
    // the map, so a second call draws no host bits and a second generator
    // cannot change the answer.
    var again_engine = Prng.init(999);
    const again = try resolveRoute(
        t.allocator,
        &pair.map,
        try relayTarget(),
        peer,
        again_engine.random(),
    );
    try t.expectEqual(route.socket, again.socket);
    const ingress = try pair.map.get(t.allocator, .{ .any_path = peer }, again_engine.random());
    try t.expectEqual(route.socket,
        base_ula.socketAddrFor(.any_path, addr_map.hostBitsOf(ingress)));
    const other_relay = try resolveRoute(t.allocator, &pair.map,
        .{ .relay = try base_addr.RelayUrl.parse("http://another-relay.example/") },
        peer, again_engine.random());
    try t.expectEqual(route.socket, other_relay.socket);
    try t.expectEqual(@as(usize, 1), pair.map.by_key.count());
}

test "a custom target is its own subnet, and the key owns the bytes" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 3, true);
    defer pair.deinit();

    var payload: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const custom: CustomAddr = .{ .id = 7, .data = payload[0..] };
    var route_engine = Prng.init(4);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        .{ .custom = custom },
        pair.server_secret.nodeId(),
        route_engine.random(),
    );

    try t.expectEqual(base_ula.Path.custom, route.subnet.?);
    // The address is the custom /64 plus host bits, and `classify` names that
    // same subnet back out of the bytes it was handed.
    try t.expectEqualSlices(u8, &base_ula.prefixFor(.custom), route.socket.ip.v6[0..8]);
    try t.expectEqual(
        base_ula.Classification{ .custom = route.socket.ip.v6 },
        base_ula.classify(route.socket),
    );

    // The key copied the data, and the copy still reads correctly after the
    // buffer it came from has been overwritten. A key pointing into a popped
    // frame would send the peer somewhere that is not here.
    @memset(payload[0..], 0xa5);
    try t.expectEqual(@as(u8, 7), route.key.?.custom.id);
    try t.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, route.key.?.custom.dataSlice());
}

test "a direct target keeps its own address and never enters the map" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 5, true);
    defer pair.deinit();

    var route_engine = Prng.init(6);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        .{ .ip = direct_addr },
        null,
        route_engine.random(),
    );

    try t.expectEqual(direct_addr, route.socket);
    try t.expectEqual(@as(?addr_map.Key, null), route.key);
    try t.expectEqual(@as(?base_ula.Path, null), route.subnet);
    try t.expectEqual(
        base_ula.Classification{ .ip = direct_addr },
        base_ula.classify(route.socket),
    );
    try t.expectEqual(@as(?addr_map.Key, null), ownerOf(&pair.map, route.socket));
    // Nothing was allocated, in either direction of the map.
    try t.expectEqual(@as(usize, 0), pair.map.by_key.count());
    try t.expectEqual(@as(usize, 0), pair.map.by_addr.count());
}

test "a custom address too long for a key is refused, not truncated" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 7, true);
    defer pair.deinit();

    const oversize = [_]u8{0x01} ** (base_addr.max_inline_length + 1);
    var route_engine = Prng.init(8);
    try t.expectError(
        error.DataTooLong,
        resolveRoute(
            t.allocator,
            &pair.map,
            .{ .custom = .{ .id = 1, .data = oversize[0..] } },
            pair.server_secret.nodeId(),
            route_engine.random(),
        ),
    );
    try t.expectEqual(@as(usize, 0), pair.map.by_key.count());
}
