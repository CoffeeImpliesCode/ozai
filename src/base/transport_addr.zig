//! One way to reach a node: a relay server, a direct IP socket, or a
//! registered custom transport.
//!
//! `TransportAddr` owns nothing: the relay and socket arms are inline values
//! and the custom arm borrows its payload, so one may be copied into storage
//! that outlives the bytes it points at. The order below is the order every
//! sorted address list in ozai iterates in, which is why the free comparator
//! a sort needs lives beside the value whose order it applies.

const std = @import("std");
const addr = @import("addr.zig");
const relay_url = @import("relay_url.zig");

const CustomAddr = addr.CustomAddr;
const IpAddress = addr.IpAddress;
const RelayUrl = relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

pub const TransportAddr = union(enum) {
    /// A relay server that will forward datagrams for us.
    relay: RelayUrl,
    /// A directly reachable IP socket.
    ip: SocketAddr,
    /// A registered non-IP transport.
    custom: CustomAddr,

    /// Variant first — relay, then ip, then custom — and the inner value's own
    /// order within a variant. Every sorted list in ozai is ordered by this,
    /// so it is also what decides which of two equal-looking addresses a
    /// duplicate collapses to.
    pub fn order(self: TransportAddr, other: TransportAddr) std.math.Order {
        const self_tag = std.meta.activeTag(self);
        const other_tag = std.meta.activeTag(other);
        if (self_tag != other_tag) {
            return std.math.order(@intFromEnum(self_tag), @intFromEnum(other_tag));
        }
        return switch (self) {
            .relay => |url| url.order(other.relay),
            .ip => |socket| socket.order(other.ip),
            .custom => |custom_addr| custom_addr.order(other.custom),
        };
    }

    /// `relay:`, `ip:` or `custom:` followed by the inner value's own text
    /// form. For a human and a log; the wire has its own encoding.
    pub fn format(self: TransportAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .relay => |url| {
                try writer.writeAll("relay:");
                try url.format(writer);
            },
            .ip => |socket| {
                try writer.writeAll("ip:");
                try socket.format(writer);
            },
            .custom => |custom_addr| {
                try writer.writeAll("custom:");
                try custom_addr.format(writer);
            },
        }
    }
};

/// `std.sort.lowerBound` takes a free function, not a method, and a list of
/// these is sorted with one from another module. It is here rather than beside
/// that caller because the order it applies is this value's.
pub fn orderTransport(a: TransportAddr, b: TransportAddr) std.math.Order {
    return a.order(b);
}

const t = std.testing;

test "transport address ordering is variant, then inner" {
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://r.example./") };
    const unspecified = IpAddress.parse("0.0.0.0") orelse return error.TestUnexpectedResult;
    const ip: TransportAddr = .{ .ip = .{ .ip = unspecified, .port = 1 } };
    const custom: TransportAddr = .{ .custom = .{ .id = 0, .data = &.{} } };

    try t.expectEqual(std.math.Order.lt, relay.order(ip));
    try t.expectEqual(std.math.Order.lt, ip.order(custom));
    try t.expectEqual(std.math.Order.eq, relay.order(relay));

    // The free comparator is what a sort is handed, so it has to agree with
    // the method rather than be a second statement of the same order.
    try t.expectEqual(std.math.Order.lt, orderTransport(relay, ip));
    try t.expectEqual(std.math.Order.eq, orderTransport(custom, custom));
}
