//! Compile-time byte widths for the integers and fixed arrays the packet
//! codecs slice out of a datagram.
//!
//! Nothing here runs: `sizeOf` is `comptime` and the module exports no other
//! declaration, so importing it costs a build-time answer rather than a
//! runtime call. It reads and writes nothing and borrows nothing.

const std = @import("std");

/// Byte width `T` occupies on the wire: `bits / 8` for an integer, and
/// `len * sizeOf(child)` for an array. `T` must be one of those two; a slice,
/// a struct or a pointer is a `@compileError` rather than a number.
///
/// The division is `@divExact`, so an integer whose bit width is not a
/// multiple of 8 (`u3`, `u20`) fails to compile. That is the intent: callers
/// use the result as the slice length handed to `std.mem.readInt`, and a
/// non-byte-multiple width would make that a partial read.
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
