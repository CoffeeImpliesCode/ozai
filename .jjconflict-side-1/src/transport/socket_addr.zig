//! An address in the kernel's own layout, and nothing else about it.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the address word: everything else
//! about an address belongs to the path and not to the socket, and this is the
//! only place under `src/` that knows `s_addr` *is* the address in wire order —
//! so a bit cast is the conversion and a byte swap would reverse the octets.

const std = @import("std");
const base_addr = @import("../base/addr.zig");

const c = std.c;
const linux = std.os.linux;

const socklen_t = c.socklen_t;

/// Write `address` into `out` in the kernel's own layout and say how many
/// bytes of `out` are the address.
///
/// The port goes out in network order. The IPv4 address does not get the
/// same treatment, and the reason is worth writing down: `s_addr` is a word
/// whose four bytes *are* the address in wire order, so a bit cast is the
/// conversion and a byte swap would reverse the octets. Everything else
/// about an address belongs to the path and not to the socket.
pub fn writeSockaddr(address: base_addr.SocketAddr, out: *c.sockaddr.storage) socklen_t {
    switch (address.ip) {
        .v4 => |octets| {
            const target: *c.sockaddr.in = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, address.port),
                .addr = @bitCast(octets),
            };
            return @sizeOf(c.sockaddr.in);
        },
        .v6 => |octets| {
            const target: *c.sockaddr.in6 = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET6,
                .port = std.mem.nativeToBig(u16, address.port),
                .flowinfo = 0,
                .addr = octets,
                .scope_id = 0,
            };
            return @sizeOf(c.sockaddr.in6);
        },
    }
}

/// Read a name the kernel filled, or null when it is not an address this
/// module speaks — an `AF_UNIX` peer, which a UDP socket can still be handed
/// by a caller that used the wrong type.
pub fn readSockaddr(raw: *const c.sockaddr.storage) ?base_addr.SocketAddr {
    const name: *const c.sockaddr = @ptrCast(@alignCast(raw));
    return switch (name.family) {
        linux.AF.INET => v4: {
            const peer: *const c.sockaddr.in = @ptrCast(@alignCast(raw));
            break :v4 base_addr.SocketAddr{
                .ip = .{ .v4 = @bitCast(peer.addr) },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        linux.AF.INET6 => v6: {
            const peer: *const c.sockaddr.in6 = @ptrCast(@alignCast(raw));
            break :v6 base_addr.SocketAddr{
                .ip = .{ .v6 = peer.addr },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        else => null,
    };
}
