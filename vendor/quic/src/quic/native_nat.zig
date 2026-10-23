//! Noq 1.3.0 NAT-traversal wire frames; pure, allocation-free codecs.
//! IPv6 interface scope is local metadata, not part of these wire addresses.

const std = @import("std");
const io = @import("../io_compat.zig");
const packet = @import("packet.zig");
const Address = @import("../address.zig").Address;

test "native NAT varint width boundaries preserve numbers and address bytes" {
    const addresses = [_]Address{
        .initIpv4(.{ 127, 0, 0, 1 }, 1),
        .initIpv6([_]u8{0} ** 16, 0, 0),
    };
    for (addresses, 0..) |address, family| {
        for ([_]u64{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824, 0x3fffffffffffffff }) |number| {
            const add: AddAddress = .{ .sequence = number, .address = address };
            const reach: ReachAddress = .{ .round = number, .address = address };
            var bytes: [32]u8 = undefined;
            var writer = io.fixedBufferStream(&bytes);
            try add.write(&writer);
            var reader = io.fixedBufferStream(writer.buffered()[4..]);
            try std.testing.expectEqualDeep(add, try AddAddress.read(&reader, family == 1));
            writer.seek = 0;
            try reach.write(&writer);
            reader = io.fixedBufferStream(writer.buffered()[4..]);
            try std.testing.expectEqualDeep(reach, try ReachAddress.read(&reader, family == 1));
        }
    }
}

pub const add_ipv4_frame_type: u64 = 0x3d7f90;
pub const add_ipv6_frame_type: u64 = 0x3d7f91;
pub const reach_ipv4_frame_type: u64 = 0x3d7f92;
pub const reach_ipv6_frame_type: u64 = 0x3d7f93;
pub const remove_frame_type: u64 = 0x3d7f94;
pub const transport_parameter_id: u64 = 0x3d7f91120401;

/// Advertises one address under a connection-local sequence number.
/// A value with no owned memory. All IP octets and ports are legal on the wire.
pub const AddAddress = struct {
    sequence: u64,
    address: Address,

    /// Reads the body after the caller has consumed the address-family frame type.
    /// Borrows and advances the reader; truncation propagates its read error.
    pub fn read(reader: anytype, is_ipv6: bool) !AddAddress {
        const sequence = try packet.readVarInt(reader);
        return .{ .sequence = sequence, .address = try readAddress(reader, is_ipv6) };
    }

    /// Writes type and body. Unset addresses fail with FrameEncodingError.
    /// Varints above 2^62-1 fail with VarIntTooLarge; writer errors propagate.
    /// Errors can leave a prefix to discard. IPv6 scope is not serialized.
    pub fn write(self: AddAddress, writer: anytype) !void {
        try writeAddressFrame(
            writer,
            self.sequence,
            self.address,
            .{ .ipv4 = add_ipv4_frame_type, .ipv6 = add_ipv6_frame_type },
        );
    }
};

/// Requests a NAT-traversal attempt using the supplied address and round.
/// A value with no owned memory; the round uses the QUIC varint range.
pub const ReachAddress = struct {
    round: u64,
    address: Address,

    /// Reads the body after the caller has consumed the address-family frame type.
    /// Borrows and advances the reader; truncation propagates its read error.
    pub fn read(reader: anytype, is_ipv6: bool) !ReachAddress {
        const round = try packet.readVarInt(reader);
        return .{ .round = round, .address = try readAddress(reader, is_ipv6) };
    }

    /// Writes type and body with the same error and scope contract as AddAddress.write.
    pub fn write(self: ReachAddress, writer: anytype) !void {
        try writeAddressFrame(
            writer,
            self.round,
            self.address,
            .{ .ipv4 = reach_ipv4_frame_type, .ipv6 = reach_ipv6_frame_type },
        );
    }
};

fn readAddress(reader: anytype, is_ipv6: bool) !Address {
    if (is_ipv6) {
        const bytes = (try reader.takeArray(16)).*;
        return .initIpv6(bytes, try reader.takeInt(u16, .big), 0);
    }
    const bytes = (try reader.takeArray(4)).*;
    return .initIpv4(bytes, try reader.takeInt(u16, .big));
}

fn writeAddressFrame(
    writer: anytype,
    number: u64,
    address: Address,
    frame_types: struct { ipv4: u64, ipv6: u64 },
) !void {
    switch (address) {
        .unset => return error.FrameEncodingError,
        inline .ipv4, .ipv6 => |value, family| {
            try packet.writeVarInt(writer, @field(frame_types, @tagName(family)));
            try packet.writeVarInt(writer, number);
            try writer.writeAll(&value.bytes);
            try writer.writeInt(u16, value.port, .big);
        },
    }
}

// Oracle provenance: independently transcribed from noq-proto 1.3.0
// src/frame.rs:2284-2493 (AddAddress and ReachOut Encodable/read semantics).
// These are source-derived expectations, not bytes captured from a Rust run:
// QUIC varint type, QUIC varint sequence/round, raw IP octets, big-endian u16 port.
test "native NAT source-derived golden bytes cover both frames and address families" {
    try expectGolden(AddAddress, .{
        .sequence = 37,
        .address = .initIpv4(.{ 203, 0, 113, 9 }, 443),
    }, &.{ 0x80, 0x3d, 0x7f, 0x90, 0x25, 203, 0, 113, 9, 1, 0xbb }, false);
    try expectGolden(AddAddress, .{
        .sequence = 64,
        .address = .initIpv6(.{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 0, 0),
    }, &.{
        0x80, 0x3d, 0x7f, 0x91, 0x40, 0x40,
        0x20, 1,    0x0d, 0xb8, 0,    0,
        0,    0,    0,    0,    0,    0,
        0,    0,    0,    1,    0,    0,
    }, true);
    try expectGolden(ReachAddress, .{
        .round = 16384,
        .address = .initIpv4(.{ 0, 0, 0, 0 }, 65535),
    }, &.{ 0x80, 0x3d, 0x7f, 0x92, 0x80, 0, 0x40, 0, 0, 0, 0, 0, 0xff, 0xff }, false);
    try expectGolden(ReachAddress, .{
        .round = 0x3fffffffffffffff,
        .address = .initIpv6([_]u8{0xff} ** 16, 65535, 0),
    }, &.{
        0x80, 0x3d, 0x7f, 0x93, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    }, true);
    try std.testing.expectEqual(@as(u64, 0x3d7f94), remove_frame_type);
    try std.testing.expectEqual(@as(u64, 0x3d7f91120401), transport_parameter_id);
}

fn expectGolden(comptime T: type, expected: T, golden: []const u8, is_ipv6: bool) !void {
    var bytes: [32]u8 = undefined;
    var writer = io.fixedBufferStream(&bytes);
    try expected.write(&writer);
    try std.testing.expectEqualSlices(u8, golden, writer.buffered());
    var reader = io.fixedBufferStream(golden[4..]);
    const decoded = try T.read(&reader, is_ipv6);
    try std.testing.expectEqualDeep(expected, decoded);
    try std.testing.expectEqual(golden.len - 4, reader.seek);
    // Every incomplete body and every undersized output must fail, not succeed partially.
    for (4..golden.len) |cut| {
        var short_reader = io.fixedBufferStream(golden[4..cut]);
        try std.testing.expectError(error.EndOfStream, T.read(&short_reader, is_ipv6));
    }
    for (0..golden.len) |cut| {
        var short_writer = io.fixedBufferStream(bytes[0..cut]);
        try std.testing.expectError(error.NoSpaceLeft, expected.write(&short_writer));
    }
}

test "native NAT accepts nonminimal varints and drops local IPv6 scope" {
    const body = [_]u8{ 0x40, 0, 255, 255, 255, 255, 0, 0, 0xaa };
    var add_reader = io.fixedBufferStream(&body);
    const add = try AddAddress.read(&add_reader, false);
    try std.testing.expectEqual(@as(u64, 0), add.sequence);
    try std.testing.expect(Address.eql(.initIpv4(.{ 255, 255, 255, 255 }, 0), add.address));
    try std.testing.expectEqual(@as(usize, 8), add_reader.seek);
    var reach_reader = io.fixedBufferStream(&body);
    try std.testing.expectEqual(@as(u64, 0), (try ReachAddress.read(&reach_reader, false)).round);
    const scoped: AddAddress = .{
        .sequence = 0,
        .address = .initIpv6([_]u8{0} ** 16, 0, 7),
    };
    var bytes: [32]u8 = undefined;
    var writer = io.fixedBufferStream(&bytes);
    try scoped.write(&writer);
    var reader = io.fixedBufferStream(writer.buffered()[4..]);
    try std.testing.expectEqual(@as(u32, 0), (try AddAddress.read(&reader, true)).address.ipv6.scope_id);
}

test "native NAT rejects unset addresses and out-of-range wire integers" {
    var bytes: [32]u8 = undefined;
    var writer = io.fixedBufferStream(&bytes);
    const add: AddAddress = .{ .sequence = 0, .address = .unset };
    const reach: ReachAddress = .{ .round = 0, .address = .unset };
    try std.testing.expectError(error.FrameEncodingError, add.write(&writer));
    try std.testing.expectError(error.FrameEncodingError, reach.write(&writer));
    try std.testing.expectEqual(@as(usize, 0), writer.seek);
    const overflow_add: AddAddress = .{
        .sequence = 0x4000000000000000,
        .address = .initIpv4(.{ 1, 2, 3, 4 }, 0),
    };
    const overflow_reach: ReachAddress = .{
        .round = 0x4000000000000000,
        .address = overflow_add.address,
    };
    try std.testing.expectError(error.VarIntTooLarge, overflow_add.write(&writer));
    writer.seek = 0;
    try std.testing.expectError(error.VarIntTooLarge, overflow_reach.write(&writer));
}

test "native NAT fuzz decoder canonical encoding is a fixed point" {
    // Coverage needs fuzz instrumentation, but Zig 0.16.0's fuzz runner has bug #36326.
    if (comptime @import("builtin").fuzz and @import("coverage_options").coverage) {
        var smith: std.testing.Smith = .{ .in = &.{} };
        try fuzzDecode({}, &smith);
    } else {
        try std.testing.fuzz({}, fuzzDecode, .{});
    }
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var input: [40]u8 = undefined;
    const count = smith.slice(&input);
    const is_ipv6 = smith.value(bool);
    try fuzzDecodeType(AddAddress, input[0..count], is_ipv6);
    try fuzzDecodeType(ReachAddress, input[0..count], is_ipv6);
}

fn fuzzDecodeType(comptime T: type, input: []const u8, is_ipv6: bool) !void {
    var reader = io.fixedBufferStream(input);
    const decoded = T.read(&reader, is_ipv6) catch return;
    try std.testing.expect(reader.seek <= input.len);
    var bytes: [32]u8 = undefined;
    var writer = io.fixedBufferStream(&bytes);
    try decoded.write(&writer);
    var canonical_reader = io.fixedBufferStream(writer.buffered());
    const frame_type = try packet.readVarInt(&canonical_reader);
    const expected_type: u64 = if (T == AddAddress)
        (if (is_ipv6) add_ipv6_frame_type else add_ipv4_frame_type)
    else
        (if (is_ipv6) reach_ipv6_frame_type else reach_ipv4_frame_type);
    try std.testing.expectEqual(expected_type, frame_type);
    const again = try T.read(&canonical_reader, is_ipv6);
    try std.testing.expectEqualDeep(decoded, again);
    try std.testing.expectEqual(writer.seek, canonical_reader.seek);
    var fixed_bytes: [32]u8 = undefined;
    var fixed_writer = io.fixedBufferStream(&fixed_bytes);
    try again.write(&fixed_writer);
    try std.testing.expectEqualSlices(u8, writer.buffered(), fixed_writer.buffered());
}
