const std = @import("std");

const endian = std.builtin.Endian.big;

/// Width in bytes of an integer or an array of them, for the wire encoders
/// that size a field from its type.
///
/// Only `int` and `array` are supported, and anything else is a compile
/// error rather than a wrong answer: this is used to lay out struct fields
/// that are packed on the wire, where a silently wrong width would be a
/// buffer read or write off the end.
pub fn sizeOf(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .int => |i| @divExact(i.bits, 8),
        .array => |a| a.len * sizeOf(a.child),
        else => @compileError("`sizeOf` only supports `Int` or `Array`"),
    };
}

test "sizeOf" {
    try std.testing.expectEqual(1, sizeOf(u8));
    try std.testing.expectEqual(2, sizeOf(u16));
    try std.testing.expectEqual(3, sizeOf(u24));
    try std.testing.expectEqual(4, sizeOf(u32));
    try std.testing.expectEqual(8, sizeOf(u64));

    try std.testing.expectEqual(3, sizeOf([3]u8));
    try std.testing.expectEqual(4, sizeOf([2]u16));
    try std.testing.expectEqual(6, sizeOf([2]u24));
}
