//! Synthetic ULAs: how a path that is not an IP path reaches a QUIC stack.
//!
//! A QUIC stack speaks IP and nothing else, so a relay path and a custom
//! transport have to be dressed up as an address before they reach the socket
//! at all. iroh hands out RFC 4193 unique local addresses from one private
//! range and remembers which key owns which address.
//!
//! Captured from n0-computer/iroh, `iroh/src/socket/mapped_addrs.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30. The constants below are that file's
//! `ADDR_PREFIXL`, `ADDR_GLOBAL_ID`, `ENDPOINT_ID_SUBNET`,
//! `RELAY_MAPPED_SUBNET`, `CUSTOM_MAPPED_SUBNET`, `MAPPED_PORT` and
//! `DEFAULT_FAKE_ADDR`, byte for byte, and the tests carry the bytes.
//!
//! Two halves, and only one of them is here. What *is* here is pure: build the
//! /64 prefix, attach the mapped port, classify an address that came back off
//! the wire. What is *not* here is the allocation of an address to a key.
//! Upstream fills the eight host bits from `rand::rng()` and memoises both
//! directions in an `AddrMap` behind a `Mutex` — state, and nondeterminism,
//! neither of which belongs in `src/base`. So the host bits are an explicit
//! argument here, and the map that answers a repeated key with the same
//! address again belongs at the transport seam. See the divergence note in
//! `docs/ARCHITECTURE.md`.

const std = @import("std");
const addr = @import("addr.zig");

const SocketAddr = addr.SocketAddr;
const TransportAddr = addr.TransportAddr;

/// RFC 4193 /l — the first octet of every synthetic address.
pub const prefix_l: u8 = 0xfd;

/// n0's global id, octets 1..6. Fixed for the whole network and not derived
/// from a peer id: upstream has exactly one, and it is not a hash of anything.
pub const global_id: [5]u8 = .{ 0x15, 0x07, 0x0a, 0x51, 0x0b };

/// The subnet discriminator, octets 6..8. This is the load-bearing part of the
/// map: a relay path and a custom path to one peer are separated by these two
/// octets and by nothing else that is guaranteed.
pub const any_path_subnet: [2]u8 = .{ 0x00, 0x00 };
pub const relay_subnet: [2]u8 = .{ 0x00, 0x01 };
pub const custom_subnet: [2]u8 = .{ 0x00, 0x03 };

/// The port on every synthetic address. Made up: the port plays no part in the
/// addressing, it only has to be a port.
pub const mapped_port: u16 = 12345;

/// Which path a synthetic address stands for. Upstream has a newtype per arm —
/// `EndpointIdMappedAddr`, `RelayMappedAddr`, `CustomMappedAddr` — because each
/// has its own `generate` and its own `TryFrom`. A tag says the same thing in
/// one type, and the /64 prefix is the only thing that differs between them.
pub const Path = enum {
    /// `fd15:70a:510b::/64`. The peer itself, before a path is chosen: one
    /// address, every candidate path, packets duplicated onto each.
    any_path,
    /// `fd15:70a:510b:1::/64`. One `(peer, relay)` pair.
    relay,
    /// `fd15:70a:510b:3::/64`. One custom transport address.
    custom,
};

/// A synthetic address, as octets. No port, no flowinfo, no scope.
pub const Ula = [16]u8;

/// The eight host bits that separate one allocation from another.
///
/// Injected, never drawn here — see the module doc. Upstream fills these from
/// the thread RNG and gets stability from a map rather than from a derivation.
pub const HostBits = [8]u8;

/// The largest host value in a subnet, so the top address of `Path.any_path`.
const max_host: HostBits = @splat(0xff);

/// Upstream's `DEFAULT_FAKE_ADDR`.
///
/// Written as octets because upstream writes it as a `SocketAddrV6::new` over
/// eight `u16::from_be_bytes` calls. Flowinfo and scope are both zero, and
/// ozai's `SocketAddr` carries neither.
pub const default_fake_addr: SocketAddr = .{
    .ip = .{ .v6 = .{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    } },
    .port = 12345,
};

/// The subnet discriminator for `path`.
pub fn subnetFor(path: Path) [2]u8 {
    return switch (path) {
        .any_path => any_path_subnet,
        .relay => relay_subnet,
        .custom => custom_subnet,
    };
}

/// The /64 prefix: `/l`, then the global id, then the subnet discriminator.
pub fn prefixFor(path: Path) [8]u8 {
    var prefix: [8]u8 = undefined;
    prefix[0] = prefix_l;
    @memcpy(prefix[1..6], &global_id);
    @memcpy(prefix[6..8], &subnetFor(path));
    return prefix;
}

/// The octets of a synthetic address: the /64 prefix, then the host bits.
///
/// The /64 is fixed by the map and the host bits are the allocation, which is
/// why the same `path` with two different `host` values is two addresses.
pub fn ulaFor(path: Path, host: HostBits) Ula {
    var octets: [16]u8 = undefined;
    @memcpy(octets[0..8], &prefixFor(path));
    @memcpy(octets[8..16], &host);
    // ZBC cannot combine the prefix and host copies to prove all octets are initialized.
    // zbc-disable-next-line: use-undefined
    return octets;
}

/// The socket address for `path`, as handed to the QUIC stack.
///
/// Not routable and not meant to be: the octets are a key into the address map
/// and `mapped_port` is a placeholder that satisfies the stack.
pub fn socketAddrFor(path: Path, host: HostBits) SocketAddr {
    return .{ .ip = .{ .v6 = ulaFor(path, host) }, .port = mapped_port };
}

/// The address to send to before a path is chosen: the peer's own subnet, so
/// the receiver cannot tell which of its paths a datagram arrived on.
pub fn anyPathSocketAddr(host: HostBits) SocketAddr {
    return socketAddrFor(.any_path, host);
}

/// The socket address for `transport`.
///
/// A direct IP path is already a socket address and comes back unchanged —
/// upstream types it `MultipathMappedAddr::Ip` and never puts it in the map.
/// Relay and custom are the two arms that need dressing up.
pub fn syntheticSocketAddr(transport: TransportAddr, host: HostBits) SocketAddr {
    return switch (transport) {
        .relay => socketAddrFor(.relay, host),
        .custom => socketAddrFor(.custom, host),
        .ip => |socket| socket,
    };
}

/// What an address that arrived off the wire turned out to be.
///
/// Mirrors upstream's `MultipathMappedAddr`, which is not a map of ours: it
/// says what the address *is*, and the key it stands for is a separate lookup.
pub const Classification = union(enum) {
    /// `fd15:70a:510b::/64`. The peer itself, path not yet chosen.
    any_path: Ula,
    /// `fd15:70a:510b:1::/64`. One `(peer, relay)` pair.
    relay: Ula,
    /// `fd15:70a:510b:3::/64`. One custom transport address.
    custom: Ula,
    /// Not one of ours. Kept whole, port included — a direct path needs no map
    /// and its port is a real one.
    ip: SocketAddr,
};

/// Classify a received address. Upstream's `From<SocketAddr>` for
/// `MultipathMappedAddr`.
pub fn classify(socket: SocketAddr) Classification {
    switch (socket.ip) {
        // The range is IPv6; an IPv4 address is always a direct path.
        .v4 => return .{ .ip = socket },
        .v6 => |octets| {
            // Order is load-bearing upstream and only safe here because the
            // three subnets are disjoint: `any_path`, then `relay`, then
            // `custom`, then fall through to `ip` unchanged. Collapse two
            // subnets and the first matching arm shadows the rest, so two paths
            // silently share one address.
            if (inSubnet(&octets, .any_path)) return .{ .any_path = octets };
            if (inSubnet(&octets, .relay)) return .{ .relay = octets };
            if (inSubnet(&octets, .custom)) return .{ .custom = octets };
            return .{ .ip = socket };
        },
    }
}

/// Whether `octets` sits in `path`'s subnet.
///
/// Upstream spells the same test as three comparisons — octet 0 against
/// `ADDR_PREFIXL`, octets 1..6 against `ADDR_GLOBAL_ID`, octets 6..8 against
/// the subnet. The prefix is exactly those three runs of bytes.
fn inSubnet(octets: *const Ula, path: Path) bool {
    return std.mem.eql(u8, octets[0..8], &prefixFor(path));
}

const t = std.testing;

/// A host value that is not all zero, so a golden vector cannot be satisfied by
/// an address that happens to be zero. Named apart from the `host` parameters
/// above, which it would otherwise shadow.
const test_host: HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

/// The three prefixes, written out as upstream writes them in the doc comments
/// on the constants above: `fd15:70a:510b::/64`, `fd15:70a:510b:1::/64` and
/// `fd15:70a:510b:3::/64`.
const captured_prefixes = [_]struct { path: Path, octets: [8]u8 }{
    .{ .path = .any_path, .octets = .{ 0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x00 } },
    .{ .path = .relay, .octets = .{ 0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01 } },
    .{ .path = .custom, .octets = .{ 0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x03 } },
};

comptime {
    // A new path arm has to arrive with a captured prefix, not without one.
    if (captured_prefixes.len != @typeInfo(Path).@"enum".field_names.len) {
        @compileError("a Path variant has no captured prefix");
    }
}

test "the map builds the prefixes upstream names" {
    inline for (captured_prefixes) |case| {
        try t.expectEqualSlices(u8, &case.octets, &prefixFor(case.path));
    }
}

test "a synthetic address is the prefix then the host bits" {
    // Written out in full. Flip one bit of the /l, the global id or the subnet
    // discriminator and an octet moves, and this fails.
    try t.expectEqualSlices(u8, &[_]u8{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    }, &ulaFor(.any_path, test_host));
    try t.expectEqualSlices(u8, &[_]u8{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    }, &ulaFor(.relay, test_host));
    try t.expectEqualSlices(u8, &[_]u8{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x03,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    }, &ulaFor(.custom, test_host));
}

test "every synthetic address carries the one mapped port" {
    // Change `mapped_port` by one bit and this fails: the QUIC stack is handed
    // the address and the peer answers on the port the map promised.
    try t.expectEqual(@as(u16, 12345), mapped_port);
    inline for (captured_prefixes) |case| {
        try t.expectEqual(mapped_port, socketAddrFor(case.path, test_host).port);
    }
}

test "the default fake address is the top of the any-path subnet" {
    // Upstream builds it from the same constants, so this asks whether the
    // literal above still agrees with the map — not whether the map agrees with
    // itself.
    try t.expectEqual(socketAddrFor(.any_path, max_host), default_fake_addr);
    const want: Classification = .{ .any_path = ulaFor(.any_path, max_host) };
    try t.expectEqual(want, classify(default_fake_addr));
}

test "an address that arrives off the wire classifies by subnet" {
    // `expectEqual` compares the tag first, so a misclassification fails here
    // instead of reading the wrong arm.
    inline for (captured_prefixes) |case| {
        const want: Classification = switch (case.path) {
            .any_path => .{ .any_path = ulaFor(.any_path, test_host) },
            .relay => .{ .relay = ulaFor(.relay, test_host) },
            .custom => .{ .custom = ulaFor(.custom, test_host) },
        };
        try t.expectEqual(want, classify(socketAddrFor(case.path, test_host)));
    }
}

test "no two paths share a subnet, which is what makes the match order moot" {
    // `classify` tries `any_path`, `relay`, `custom` in that order and the
    // first match wins. Collapse two subnets and the earlier arm swallows the
    // later one, so a relay path and a custom path to one peer land on a single
    // address with no error anywhere.
    for (captured_prefixes, captured_prefixes) |a, b| {
        if (a.path != b.path) try t.expect(!std.mem.eql(u8, &a.octets, &b.octets));
    }
}

test "anything outside the map is a direct path" {
    // IPv4 never occupies a synthetic subnet.
    const v4: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };
    try t.expectEqual(Classification{ .ip = v4 }, classify(v4));

    // Neither does IPv6 with the wrong /l or global id, nor IPv6 in the right
    // range on a subnet upstream never allocates: 0, 1 and 3 are taken, 2 is
    // not, and mistaking 2 for a live one is the failure this pins.
    const zeros: [8]u8 = @splat(0x00);
    const unclaimed = [_]Ula{
        zeros ++ zeros,
        .{ 0xfd, 0x16, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x00 } ++ zeros,
        .{ 0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x02 } ++ zeros,
    };
    for (unclaimed) |octets| {
        const socket: SocketAddr = .{ .ip = .{ .v6 = octets }, .port = 443 };
        try t.expectEqual(Classification{ .ip = socket }, classify(socket));
    }
}

/// One `TransportAddr` of every variant, in tag order, with the socket address
/// the map gives it. Written out rather than computed: this is the vector.
const per_variant = [_]SocketAddr{
    .{ .ip = .{ .v6 = .{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    } }, .port = 12345 },
    .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 },
    .{ .ip = .{ .v6 = .{
        0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x03,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    } }, .port = 12345 },
};

test "every transport variant maps to a socket address" {
    // `TransportAddr` is `union(enum) { relay, ip, custom }` and `per_variant`
    // is in that order. A fourth variant stops the build here rather than
    // slipping through unmapped.
    const transports = [_]TransportAddr{
        .{ .relay = try addr.RelayUrl.parse("https://use1-1.relay.iroh.network./") },
        .{ .ip = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 } },
        .{ .custom = .{ .id = 0x2a, .data = &.{} } },
    };
    comptime {
        if (transports.len != @typeInfo(TransportAddr).@"union".field_names.len) {
            @compileError("a TransportAddr variant has no captured address");
        }
    }
    inline for (transports, 0..) |transport, index| {
        try t.expectEqual(index, @backingInt(std.meta.activeTag(transport)));
        try t.expectEqual(per_variant[index], syntheticSocketAddr(transport, test_host));
    }
}

test "two paths to one peer never alias" {
    // Upstream allocates a fresh address per key and retries on collision, so
    // one peer behind a relay and the same peer on a direct path are two
    // addresses. Injecting the same host bits for all three makes the claim
    // stronger, not weaker: the subnet discriminator is then the only thing
    // left that could separate them, and it has to.
    var peer = try addr.NodeAddr.withRelay(
        t.allocator,
        try addr.NodeId.fromBytes(@as([32]u8, @splat(1))),
        try addr.RelayUrl.parse("https://use1-1.relay.iroh.network./"),
    );
    defer peer.deinit(t.allocator);
    peer = (try peer.insert(t.allocator, .{ .ip = .{
        .ip = .{ .v4 = .{ 192, 0, 2, 7 } },
        .port = 7842,
    } })) orelse return error.TestUnexpectedResult;
    peer = (try peer.insert(t.allocator, .{
        .custom = .{ .id = 0x2a, .data = &.{} },
    })) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 3), peer.addrs.len);

    var sockets: [3]SocketAddr = undefined;
    for (peer.addrs, &sockets) |transport, *slot| {
        slot.* = syntheticSocketAddr(transport, test_host);
    }
    var i: usize = 1;
    while (i < sockets.len) : (i += 1) {
        var j: usize = 0;
        while (j < i) : (j += 1) {
            try t.expect(sockets[i].order(sockets[j]) != .eq);
        }
    }
}
