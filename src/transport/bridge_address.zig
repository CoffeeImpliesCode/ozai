//! The two address vocabularies meeting, and nowhere else.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over it
//! and five other named modules. Both bridges write a path and read one back,
//! and both directions are this one `switch`; the socket seam's own
//! conversions live in `transport/socket.zig` and never see the core's type.
//! Two small functions and the one asymmetry between the two types — a scope
//! the core has and this project has no name for — is a boundary of its own.

const quic = @import("quic");
const base_addr = @import("../base/addr.zig");

const SocketAddr = base_addr.SocketAddr;

/// This project's address as the core's own.
///
/// The core's address is a tagged union over the two families with no kernel
/// struct behind it (`vendor/quic/src/address.zig`), and this project's is a
/// tagged union with no scope, so the conversion is the bytes and the port
/// and nothing else has to be decided. This and `fromCoreAddress` are the only
/// two places the two vocabularies meet; the socket seam's own conversions
/// live in `transport/socket.zig` and never see the core's type.
pub fn toCoreAddress(socket: SocketAddr) quic.address.Address {
    return switch (socket.ip) {
        .v4 => |octets| quic.address.Address.initIpv4(octets, socket.port),
        // The scope is zero because `SocketAddr` carries none. A link-local
        // address would need one and this project has no name for it; the
        // synthetic ULAs are not link-local, which is why the core's scope
        // comparison can never disagree with `ula` for them.
        .v6 => |octets| quic.address.Address.initIpv6(octets, socket.port, 0),
    };
}

/// The core's address as this project's.
///
/// Null for the one value `SocketAddr` cannot spell — `unset`, a path the
/// core has not been given an address for — and null rather than a wildcard
/// for it, because a datagram sent to a path with no address reaches nobody.
pub fn fromCoreAddress(core: *const quic.address.Address) ?SocketAddr {
    return switch (core.*) {
        .unset => null,
        .ipv4 => |v4| .{ .ip = .{ .v4 = v4.bytes }, .port = v4.port },
        .ipv6 => |v6| .{ .ip = .{ .v6 = v6.bytes }, .port = v6.port },
    };
}