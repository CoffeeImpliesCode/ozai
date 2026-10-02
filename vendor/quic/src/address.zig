//! Sans-IO path identity without kernel layouts or target-dependent types.
//! Ports use host byte order. IPv6 paths also carry their interface scope.
//! `unset` preserves an unassigned path without treating it as a wildcard.
//! Two unassigned paths compare equal, so they do not trigger migration.

const std = @import("std");
const mem = std.mem;

pub const Ipv4Address = struct {
    bytes: [4]u8,
    /// The socket seam converts host byte order to kernel byte order.
    port: u16,
};

pub const Ipv6Address = struct {
    bytes: [16]u8,
    port: u16,
    /// RFC 4007 interface zone. Synthetic ULAs do not need a zone.
    scope_id: u32 = 0,
};

pub const Address = union(enum) {
    unset,
    ipv4: Ipv4Address,
    ipv6: Ipv6Address,

    pub fn initIpv4(bytes: [4]u8, port: u16) Address {
        return .{ .ipv4 = .{ .bytes = bytes, .port = port } };
    }

    pub fn initIpv6(bytes: [16]u8, port: u16, scope_id: u32) Address {
        return .{ .ipv6 = .{ .bytes = bytes, .port = port, .scope_id = scope_id } };
    }

    /// Path identity includes the port and IPv6 scope.
    pub fn eql(a: Address, b: Address) bool {
        return switch (a) {
            .unset => switch (b) {
                .unset => true,
                else => false,
            },
            .ipv4 => |left| switch (b) {
                .ipv4 => |right| mem.eql(u8, &left.bytes, &right.bytes) and
                    left.port == right.port,
                else => false,
            },
            .ipv6 => |left| switch (b) {
                .ipv6 => |right| mem.eql(u8, &left.bytes, &right.bytes) and
                    left.port == right.port and
                    left.scope_id == right.scope_id,
                else => false,
            },
        };
    }

    /// Migration compares IP bytes only, preserving the existing behavior
    /// independently of port and interface scope.
    pub fn sameIp(a: Address, b: Address) bool {
        return switch (a) {
            .unset => switch (b) {
                .unset => true,
                else => false,
            },
            .ipv4 => |left| switch (b) {
                .ipv4 => |right| mem.eql(u8, &left.bytes, &right.bytes),
                else => false,
            },
            .ipv6 => |left| switch (b) {
                .ipv6 => |right| mem.eql(u8, &left.bytes, &right.bytes),
                else => false,
            },
        };
    }

    /// `::ffff:a.b.c.d`, which is what a dual-stack socket hands back for a
    /// peer that connected over IPv4.
    pub fn isIpv4Mapped(self: Address) bool {
        const six = switch (self) {
            .ipv6 => |v6| v6,
            else => return false,
        };
        return isMappedIpv6(six);
    }

    /// Count mapped IPv6 as IPv4 when choosing the other preferred-address family.
    pub fn isEffectivelyIpv4(self: Address) bool {
        return switch (self) {
            .ipv4 => true,
            .ipv6 => |v6| isMappedIpv6(v6),
            .unset => false,
        };
    }

    /// Canonical token binding includes the complete IP, port and scope.
    /// A family tag distinguishes otherwise identical zero IPv4/IPv6 values.
    /// The old kernel byte window omitted the IPv6 tail.
    pub fn identity(self: Address) [identity_length]u8 {
        var out = [_]u8{0} ** identity_length;
        out[0] = @intFromEnum(std.meta.activeTag(self));
        switch (self) {
            .unset => {},
            .ipv4 => |v4| {
                const port = mem.nativeToBig(u16, v4.port);
                @memcpy(out[1..3], mem.asBytes(&port));
                @memcpy(out[3..7], &v4.bytes);
            },
            .ipv6 => |v6| {
                const port = mem.nativeToBig(u16, v6.port);
                const scope = mem.nativeToBig(u32, v6.scope_id);
                @memcpy(out[1..3], mem.asBytes(&port));
                @memcpy(out[3..19], &v6.bytes);
                @memcpy(out[19..23], mem.asBytes(&scope));
            },
        }
        return out;
    }
};

/// Both token formats use this fixed width.
pub const identity_length: usize = 1 + 2 + 16 + 4;

/// `::ffff:0:0/96`: ten zero octets and two `0xff`.
fn isMappedIpv6(six: Ipv6Address) bool {
    if (!mem.eql(u8, six.bytes[0..10], &[_]u8{0} ** 10)) return false;
    return six.bytes[10] == 0xff and six.bytes[11] == 0xff;
}

const t = std.testing;

/// 2001:db8::1.
const documented: [16]u8 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};

test "an unset path is an address the core does not have yet" {
    const unset: Address = .unset;
    try t.expect(unset.eql(unset));
    try t.expect(unset.sameIp(unset));
    try t.expect(!unset.isEffectivelyIpv4());
    try t.expect(!unset.isIpv4Mapped());
    const real = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    try t.expect(!unset.eql(real));
    try t.expect(!real.eql(unset));
    try t.expect(!unset.sameIp(real));
    try t.expect(!real.sameIp(unset));
    const bound = real.identity();
    try t.expect(!std.mem.eql(u8, &bound, &unset.identity()));
}

test "eql: same IPv4 addresses" {
    const a = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const b = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    try t.expect(a.eql(b));
}

test "eql: different IPv4 ports" {
    const a = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const b = Address.initIpv4(.{ 127, 0, 0, 1 }, 4434);
    try t.expect(!a.eql(b));
}

test "eql: different IPv4 addresses" {
    const a = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const b = Address.initIpv4(.{ 192, 168, 1, 1 }, 4433);
    try t.expect(!a.eql(b));
}

test "eql: a family is part of the answer" {
    // Mapped IPv6 and native IPv4 remain different path families.
    const v4 = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 };
    const mapped = Address.initIpv6(bytes, 4433, 0);
    try t.expect(!v4.eql(mapped));
    try t.expect(!mapped.eql(v4));
}

test "eql: the scope is part of a path" {
    const bytes = [_]u8{ 0xfe, 0x80 } ++ [_]u8{0} ** 13 ++ [_]u8{1};
    const on_one = Address.initIpv6(bytes, 4433, 1);
    const on_two = Address.initIpv6(bytes, 4433, 2);
    try t.expect(!on_one.eql(on_two));
    try t.expect(!on_two.eql(on_one));
    try t.expect(on_one.eql(Address.initIpv6(bytes, 4433, 1)));
    // Preserve the old IP-only migration comparison across interface scopes.
    try t.expect(on_one.sameIp(on_two));
}

test "sameIp: same IP different ports" {
    const a = Address.initIpv4(.{ 10, 0, 0, 1 }, 1234);
    const b = Address.initIpv4(.{ 10, 0, 0, 1 }, 5678);
    try t.expect(a.sameIp(b));
    try t.expect(!a.eql(b));
}

test "sameIp: different IPs" {
    const a = Address.initIpv4(.{ 10, 0, 0, 1 }, 1234);
    const b = Address.initIpv4(.{ 10, 0, 0, 2 }, 1234);
    try t.expect(!a.sameIp(b));
}

test "isIpv4Mapped: IPv4-mapped IPv6" {
    const bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 };
    try t.expect(Address.initIpv6(bytes, 4433, 0).isIpv4Mapped());
}

test "isIpv4Mapped: regular IPv6 is not mapped" {
    const bytes = [_]u8{0} ** 15 ++ [_]u8{1};
    try t.expect(!Address.initIpv6(bytes, 4433, 0).isIpv4Mapped());
}

test "isIpv4Mapped: IPv4 is not mapped" {
    try t.expect(!Address.initIpv4(.{ 127, 0, 0, 1 }, 4433).isIpv4Mapped());
}

test "isIpv4Mapped: the prefix is exact" {
    // A final 0xffff alone does not prove the mapped prefix.
    const bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
    try t.expect(!Address.initIpv6(bytes, 4433, 0).isIpv4Mapped());
}

test "isEffectivelyIpv4: IPv4" {
    try t.expect(Address.initIpv4(.{ 10, 0, 0, 1 }, 80).isEffectivelyIpv4());
}

test "isEffectivelyIpv4: IPv4-mapped IPv6" {
    const bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 1 };
    try t.expect(Address.initIpv6(bytes, 80, 0).isEffectivelyIpv4());
}

test "isEffectivelyIpv4: native IPv6 is not v4" {
    const bytes = [_]u8{ 0x20, 0x01 } ++ [_]u8{0} ** 14;
    try t.expect(!Address.initIpv6(bytes, 80, 0).isEffectivelyIpv4());
}

test "identity: two addresses never bind the same bytes" {
    // Changing any identity component must change the token binding.
    const base = Address.initIpv6(documented, 4433, 0);
    var other_tail = documented;
    other_tail[15] = 2;
    var other_head = documented;
    other_head[0] = 0x21;
    const variants = [_]Address{
        Address.initIpv6(documented, 4434, 0),
        Address.initIpv6(documented, 4433, 1),
        Address.initIpv6(other_tail, 4433, 0),
        Address.initIpv6(other_head, 4433, 0),
        Address.initIpv4(.{ 0, 0, 0, 0 }, 4433),
        Address.initIpv4(.{ 32, 1, 13, 184 }, 4433),
        .unset,
    };
    const expected = base.identity();
    for (variants) |variant| {
        try t.expect(!std.mem.eql(u8, &expected, &variant.identity()));
    }
    const zero_ipv4 = Address.initIpv4(.{ 0, 0, 0, 0 }, 0);
    const zero_ipv6 = Address.initIpv6([_]u8{0} ** 16, 0, 0);
    try t.expect(!mem.eql(u8, &zero_ipv4.identity(), &zero_ipv6.identity()));
}

test "identity: the encoding does not depend on the host's byte order" {
    const address = Address.initIpv6(documented, 4433, 0x01020304);
    const bytes = address.identity();
    try t.expectEqual(@as(u8, 2), bytes[0]);
    try t.expectEqualSlices(u8, &[_]u8{ 0x11, 0x51 }, bytes[1..3]);
    try t.expectEqualSlices(u8, &documented, bytes[3..19]);
    try t.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, bytes[19..23]);
    const ipv4 = Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const expected_ipv4 = [_]u8{ 1, 0x11, 0x51, 127, 0, 0, 1 } ++ [_]u8{0} ** 16;
    try t.expectEqualSlices(u8, &expected_ipv4, &ipv4.identity());
}
