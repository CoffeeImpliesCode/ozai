//! Fixed-buffer stream over a `[]u8` / `[]const u8`, exposing the
//! `std.Io.Reader` / `std.Io.Writer`-compatible method surface used by
//! our encode/decode paths (`takeByte`, `takeInt`, `readSliceAll`,
//! `readSliceShort`, `takeArray`, `writeAll`, `writeByte`, `writeInt`,
//! `buffered`).
//!
//! Zig 0.16 replaced `std.io.fixedBufferStream` with
//! `std.Io.Reader.fixed` / `std.Io.Writer.fixed`, but the stdlib split
//! reader and writer into separate types — inconvenient for the many
//! call sites that read and write the same buffer. This keeps a unified
//! FBS with the 0.16 method names, so callers can pass `&fbs` to any
//! `anytype` reader/writer parameter.

const std = @import("std");
const mem = std.mem;

/// A cursor over a fixed `[]u8` or `[]const u8` with the reader and writer
/// method names this tree's encode and decode paths use.
///
/// Borrows `buffer` for the stream's lifetime. Views returned by `buffered`
/// and `takeArray` remain valid while that storage lives; moving the cursor
/// does not invalidate them. Writes to their bytes change what the views read.
///
/// `seek` is the one piece of state, and it is the position every method
/// reads at and advances past. A caller sets it directly to skip to the next
/// packet in a coalesced datagram; `seekBy` is the checked way to do that.
///
/// ## Running out of room
///
/// Exact reads fail with `error.EndOfStream` and writes with
/// `error.NoSpaceLeft`, leaving the cursor and destination unchanged.
/// `readSliceShort` instead copies the available prefix and returns its count.
/// Keep `seek <= buffer.len`, including after direct cursor assignments.
///
/// ## A stream over a const buffer
///
/// A const buffer supports reads only. Calling a write method on it is a
/// compile error; a mutable buffer supports both directions.
pub fn FixedBufferStream(comptime Buffer: type) type {
    comptime std.debug.assert(@typeInfo(Buffer) == .pointer);
    const is_const_buf = @typeInfo(Buffer).pointer.is_const;
    const Slice = if (is_const_buf) []const u8 else []u8;

    return struct {
        /// Borrowed caller storage. Constness determines the available operations.
        buffer: Slice,
        /// The cursor: the offset every method reads at and advances past. It
        /// is public because a caller stepping through a coalesced datagram
        /// sets it directly; `seekBy` is the checked form of the same move.
        seek: usize,

        const Self = @This();
        const is_const = is_const_buf;

        /// The short-read operation is infallible and reports its copied count.
        /// Exact reads declare their own `error{EndOfStream}` sets.
        pub const ReadError = error{};
        /// A write that does not fit in what is left of the buffer.
        pub const WriteError = error{NoSpaceLeft};
        /// Reads the byte at the cursor and advances it by one.
        ///
        /// `error.EndOfStream` once the cursor is at the end, with the cursor
        /// unchanged and nothing read — so a caller retrying after seeking is
        /// reading the same byte.
        pub fn takeByte(self: *Self) error{EndOfStream}!u8 {
            if (self.seek >= self.buffer.len) return error.EndOfStream;
            const b = self.buffer[self.seek];
            self.seek += 1;
            return b;
        }

        /// Read `sizeOf(T)` bytes as `T`, or fail without moving.
        ///
        /// A `take`, not a `read`: the bytes are consumed from the stream
        /// rather than copied out of it, so nothing here can be read twice.
        ///
        pub fn takeInt(self: *Self, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const slice = self.buffer[self.seek..][0..n];
            self.seek += n;
            return mem.readInt(T, slice, endian);
        }

        /// Copies exactly `dest.len` bytes into `dest` and advances past them.
        ///
        /// Fewer bytes than asked is `error.EndOfStream` with `dest` untouched
        /// and the cursor unmoved; use `readSliceShort` for the partial case.
        pub fn readSliceAll(self: *Self, dest: []u8) error{EndOfStream}!void {
            if (self.buffer.len - self.seek < dest.len) return error.EndOfStream;
            @memcpy(dest, self.buffer[self.seek..][0..dest.len]);
            self.seek += dest.len;
        }

        /// Copy out whatever is left, up to `dest.len`, and report how much
        /// that was. Zero is a legitimate answer and not an error: it is what
        /// an empty remainder reads as, so a caller that needs `dest.len`
        /// bytes has to check the count rather than the error.
        ///
        pub fn readSliceShort(self: *Self, dest: []u8) ReadError!usize {
            const n = @min(dest.len, self.buffer.len - self.seek);
            @memcpy(dest[0..n], self.buffer[self.seek..][0..n]);
            self.seek += n;
            return n;
        }

        /// Hands back a pointer to the next `n` bytes in place and advances
        /// past them — nothing is copied.
        ///
        /// Borrows `buffer`; const buffers return a const pointer. Subsequent
        /// cursor movement preserves the view; writes to its bytes change it.
        /// `error.EndOfStream` leaves the cursor unmoved.
        pub fn takeArray(
            self: *Self,
            comptime n: usize,
        ) error{EndOfStream}!(if (is_const) *const [n]u8 else *[n]u8) {
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const ptr: if (is_const) *const [n]u8 else *[n]u8 =
                @ptrCast(self.buffer[self.seek..][0..n].ptr);
            self.seek += n;
            return ptr;
        }

        /// Copies `bytes` into the buffer at the cursor and advances past them.
        ///
        /// `error.NoSpaceLeft` leaves the bytes and cursor unchanged.
        pub fn writeAll(self: *Self, bytes: []const u8) WriteError!void {
            if (comptime is_const) @compileError("cannot write to a const buffer");
            if (bytes.len > self.buffer.len - self.seek) return error.NoSpaceLeft;
            @memcpy(self.buffer[self.seek..][0..bytes.len], bytes);
            self.seek += bytes.len;
        }

        /// Writes one byte at the cursor and advances it by one.
        ///
        /// `error.NoSpaceLeft` leaves the bytes and cursor unchanged.
        pub fn writeByte(self: *Self, byte: u8) WriteError!void {
            if (comptime is_const) @compileError("cannot write to a const buffer");
            if (self.seek >= self.buffer.len) return error.NoSpaceLeft;
            self.buffer[self.seek] = byte;
            self.seek += 1;
        }

        /// Writes `sizeOf(T)` bytes of `value` at the cursor and advances past
        /// them.
        ///
        /// `T` must be an integer whose width is a multiple of 8, because the
        /// width comes from `@divExact` over its bit count. Too few bytes left
        /// is `error.NoSpaceLeft` with nothing written and the cursor unmoved.
        pub fn writeInt(self: *Self, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
            if (comptime is_const) @compileError("cannot write to a const buffer");
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.NoSpaceLeft;
            mem.writeInt(T, self.buffer[self.seek..][0..n], value, endian);
            self.seek += n;
        }

        /// The bytes before the cursor: everything read or written so far.
        ///
        /// Borrows `buffer`; cursor movement preserves previously returned
        /// views, while writes change the bytes they reference.
        pub fn buffered(self: *const Self) Slice {
            return self.buffer[0..self.seek];
        }

        /// Skip `offset` bytes, or fail without moving. This is how a caller
        /// steps over a packet whose length a parse already reported.
        ///
        pub fn seekBy(self: *Self, offset: usize) error{NoSpaceLeft}!void {
            if (offset > self.buffer.len - self.seek) return error.NoSpaceLeft;
            self.seek += offset;
        }
    };
}

/// A stream over `buffer`, positioned at its start.
///
/// The slice is borrowed, not copied: the stream is good exactly as long as
/// the caller's memory is, and what is written into that memory under it is
/// what the next read returns.
pub fn fixedBufferStream(buffer: anytype) FixedBufferStream(@TypeOf(buffer)) {
    return .{ .buffer = buffer[0..], .seek = 0 };
}

test "const readers preserve array views and failed-read position" {
    const bytes = [_]u8{ 0x11, 0x22, 0x33 };
    var reader = fixedBufferStream(@as([]const u8, &bytes));
    const first = try reader.takeArray(2);
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22 }, first);
    try std.testing.expectError(error.EndOfStream, reader.takeArray(2));
    try std.testing.expectEqual(@as(usize, 2), reader.seek);
    try std.testing.expectEqual(@as(u8, 0x33), try reader.takeByte());
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22 }, first);
}
