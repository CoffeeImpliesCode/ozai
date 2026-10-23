//! Noq 1.3.0 native NAT wire, c1f41156 frame.rs:2284-2493.
//! This is NAT traversal, not the unrelated Number-Time extension.
const std = @import("std");
const builtin = @import("builtin");
const coverage_options = @import("coverage_options");
const varint = @import("../wire/quic_varint.zig");
pub const SocketAddr = @import("../base/addr.zig").SocketAddr;
pub const transport_parameter_id: u64 = 0x3d7f91120401;
pub const add_ipv4: u64 = 0x3d7f90;
pub const add_ipv6: u64 = 0x3d7f91;
pub const reach_ipv4: u64 = 0x3d7f92;
pub const reach_ipv6: u64 = 0x3d7f93;
pub const remove_address: u64 = 0x3d7f94;
pub const max_sequence = varint.max_value;
pub const max_frame_length = 4 + 8 + 16 + 2;
pub const Frame = union(enum) {
    add: struct { sequence: u64, address: SocketAddr },
    reach: struct { round: u64, address: SocketAddr },
    remove: u64,
};
pub const Decoded = struct { frame: Frame, length: usize };
pub const Error = error{ Truncated, NoRoom, UnknownFrame, SequenceTooLarge };

/// Absence disables the extension; zero is not an encoded disabled value.
pub fn decodeParameter(bytes: []const u8) error{InvalidParameter}!u8 {
    if (bytes.len != 1 or bytes[0] == 0) return error.InvalidParameter;
    return bytes[0];
}

pub fn encodeParameter(limit: u8, out: []u8) error{ InvalidParameter, NoRoom }!usize {
    if (limit == 0) return error.InvalidParameter;
    if (out.len == 0) return error.NoRoom;
    out[0] = limit;
    return 1;
}

pub fn encode(frame: Frame, out: []u8) Error!usize {
    const sequence = switch (frame) {
        .add => |value| value.sequence,
        .reach => |value| value.round,
        .remove => |value| value,
    };
    if (sequence > max_sequence) return error.SequenceTooLarge;
    const address: ?SocketAddr = switch (frame) {
        .add => |value| value.address,
        .reach => |value| value.address,
        .remove => null,
    };
    const ipv6 = if (address) |value| value.ip == .v6 else false;
    const kind: u64 = switch (frame) {
        .add => if (ipv6) add_ipv6 else add_ipv4,
        .reach => if (ipv6) reach_ipv6 else reach_ipv4,
        .remove => remove_address,
    };
    var offset = try varint.put(out, kind);
    offset += try varint.put(out[offset..], sequence);
    if (address) |value| {
        const width: usize = if (ipv6) 16 else 4;
        if (out.len - offset < width + 2) return error.NoRoom;
        switch (value.ip) {
            .v4 => |bytes| @memcpy(out[offset..][0..4], &bytes),
            .v6 => |bytes| @memcpy(out[offset..][0..16], &bytes),
        }
        offset += width;
        std.mem.writeInt(u16, out[offset..][0..2], value.port, .big);
        offset += 2;
    }
    return offset;
}

/// Decode one frame, retaining raw IP family exactly as the upstream codec does.
pub fn decode(bytes: []const u8) Error!Decoded {
    var offset: usize = 0;
    const kind = try varint.get(bytes, &offset);
    if (kind < add_ipv4 or kind > remove_address) return error.UnknownFrame;
    const sequence = try varint.get(bytes, &offset);
    if (kind == remove_address) {
        return .{ .frame = .{ .remove = sequence }, .length = offset };
    }
    const ipv6 = kind == add_ipv6 or kind == reach_ipv6;
    const width: usize = if (ipv6) 16 else 4;
    if (bytes.len - offset < width + 2) return error.Truncated;
    var address: SocketAddr = undefined;
    if (ipv6) {
        var octets: [16]u8 = undefined;
        @memcpy(&octets, bytes[offset..][0..16]);
        address.ip = .{ .v6 = octets };
    } else {
        var octets: [4]u8 = undefined;
        @memcpy(&octets, bytes[offset..][0..4]);
        address.ip = .{ .v4 = octets };
    }
    offset += width;
    address.port = std.mem.readInt(u16, bytes[offset..][0..2], .big);
    return .{
        .frame = if (kind == add_ipv4 or kind == add_ipv6)
            .{ .add = .{ .sequence = sequence, .address = address } }
        else
            .{ .reach = .{ .round = sequence, .address = address } },
        .length = offset + 2,
    };
}

/// State keys use canonical IPs; IPv4-mapped IPv6 never creates a second candidate.
pub fn canonical(address: SocketAddr) SocketAddr {
    if (address.ip == .v6) {
        const bytes = address.ip.v6;
        if (std.mem.allEqual(u8, bytes[0..10], 0) and
            bytes[10] == 255 and bytes[11] == 255)
        {
            return .{ .ip = .{ .v4 = bytes[12..16].* }, .port = address.port };
        }
    }
    return address;
}

const t = std.testing;

test "source-derived Noq ADD_ADDRESS vector and all truncations" {
    // Derived from Noq c1f41156 frame.rs encode; not a captured upstream fixture.
    const vector = [_]u8{ 0x80, 0x3d, 0x7f, 0x90, 0x40, 0x40, 192, 0, 2, 1, 0x12, 0x34 };
    const decoded = try decode(&vector);
    try t.expectEqual(@as(u64, 64), decoded.frame.add.sequence);
    try t.expectEqual(@as(u16, 0x1234), decoded.frame.add.address.port);
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(decoded.frame, &out);
    try t.expectEqualSlices(u8, &vector, out[0..length]);
    for (0..vector.len) |length_short|
        try t.expectError(error.Truncated, decode(vector[0..length_short]));
}

test "native NAT parameter strictly one nonzero byte" {
    try t.expectEqual(@as(u8, 32), try decodeParameter(&.{32}));
    try t.expectError(error.InvalidParameter, decodeParameter(&.{}));
    try t.expectError(error.InvalidParameter, decodeParameter(&.{0}));
    try t.expectError(error.InvalidParameter, decodeParameter(&.{ 1, 0 }));
}

test "native codec arbitrary bytes never escape input and roundtrip" {
    var random = std.Random.DefaultPrng.init(0xc1f41156);
    var bytes: [max_frame_length]u8 = undefined;
    var out: [max_frame_length]u8 = undefined;
    for (0..4096) |_| {
        random.random().bytes(&bytes);
        const length = random.random().uintLessThan(usize, bytes.len + 1);
        const decoded = decode(bytes[0..length]) catch continue;
        try t.expect(decoded.length <= length);
        const encoded_length = try encode(decoded.frame, &out);
        const again = try decode(out[0..encoded_length]);
        try t.expectEqualDeep(decoded.frame, again.frame);
    }
}

test "all native frame kinds and varint boundaries preserve fields" {
    const addresses = [_]SocketAddr{
        .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 0x1234 },
        .{
            .ip = .{
                .v6 = .{
                    32, 1, 13, 184, 0, 0, 0, 0,
                    0,  0, 0,  0,   0, 0, 0, 1,
                },
            },
            .port = 0x1234,
        },
    };
    var output: [max_frame_length]u8 = undefined;
    for (varint.boundaries) |sequence| {
        for (addresses) |address| {
            const frames = [_]Frame{
                .{ .add = .{ .sequence = sequence, .address = address } },
                .{ .reach = .{ .round = sequence, .address = address } },
                .{ .remove = sequence },
            };
            for (frames) |frame| {
                const length = try encode(frame, &output);
                try t.expectEqualDeep(frame, (try decode(output[0..length])).frame);
                for (0..length) |short| {
                    try t.expectError(error.Truncated, decode(output[0..short]));
                    try t.expectError(error.NoRoom, encode(frame, output[0..short]));
                }
            }
        }
    }
    try t.expectError(error.SequenceTooLarge, encode(.{ .remove = max_sequence + 1 }, &output));
    try t.expectError(error.UnknownFrame, decode(&.{0}));
    try t.expectEqual(@as(usize, 1), try encodeParameter(255, &output));
    try t.expectEqual(@as(u8, 255), try decodeParameter(output[0..1]));
    try t.expectError(error.InvalidParameter, encodeParameter(0, &output));
    try t.expectError(error.NoRoom, encodeParameter(1, output[0..0]));
}

test "native NAT decoder Smith fuzz" {
    // Coverage needs fuzz instrumentation, but Zig 0.16.0's fuzz runner has bug #36326.
    if (comptime builtin.fuzz and coverage_options.coverage) {
        var smith: t.Smith = .{ .in = &.{} };
        try fuzzNativeNatDecoder({}, &smith);
    } else {
        try t.fuzz({}, fuzzNativeNatDecoder, .{});
    }
}

fn fuzzNativeNatDecoder(_: void, smith: *t.Smith) !void {
    var input: [64]u8 = undefined;
    const length = smith.sliceWithHash(&input, 0xc1f41156);
    if (decodeParameter(input[0..length])) |limit| {
        var parameter: [1]u8 = undefined;
        _ = try encodeParameter(limit, &parameter);
        try t.expectEqualSlices(u8, input[0..length], &parameter);
    } else |_| {}
    const decoded = decode(input[0..length]) catch return;
    try t.expect(decoded.length <= length);
    var output: [max_frame_length]u8 = undefined;
    const encoded_length = try encode(decoded.frame, &output);
    try t.expectEqualDeep(decoded.frame, (try decode(output[0..encoded_length])).frame);
}
