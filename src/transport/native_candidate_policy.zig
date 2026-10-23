//! NAT candidates name physical UDP destinations, not address-map keys.
//! The normal connection path may still be a synthetic relay or custom path.
const std = @import("std");
const quic = @import("quic");
const ula = @import("../base/ula.zig");
const bridge_address = @import("bridge_address.zig");

/// Pure factory policy; generic QUIC validation handles ports and routability.
pub fn admit(candidate: quic.address.Address) bool {
    const socket = bridge_address.fromCoreAddress(&candidate) orelse return false;
    return ula.classify(socket) == .ip;
}

test "native candidate admission rejects every synthetic subnet independently of port and host" {
    for ([_]ula.Path{ .any_path, .relay, .custom }) |path| {
        for ([_]ula.HostBits{ @splat(0), @splat(0xff) }) |host| {
            for ([_]u16{ 1, ula.mapped_port, 65535 }) |port| {
                var socket = ula.socketAddrFor(path, host);
                socket.port = port;
                try std.testing.expect(!admit(bridge_address.toCoreAddress(socket)));
            }
        }
    }
}

test "native candidate admission accepts physical families and adjacent private subnets" {
    try std.testing.expect(admit(quic.address.Address.initIpv4(.{ 192, 0, 2, 1 }, 443)));
    try std.testing.expect(admit(quic.address.Address.initIpv6(
        .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        443,
        0,
    )));
    var adjacent = ula.ulaFor(.relay, @splat(0));
    adjacent[7] = 2;
    try std.testing.expect(admit(quic.address.Address.initIpv6(adjacent, 443, 0)));
    adjacent = ula.ulaFor(.custom, @splat(0));
    adjacent[5] ^= 1;
    try std.testing.expect(admit(quic.address.Address.initIpv6(adjacent, 443, 0)));
    try std.testing.expect(!admit(.unset));
}
