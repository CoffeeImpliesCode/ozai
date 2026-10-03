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
/// The stream owns nothing: `buffer` is the caller's slice, borrowed for as
/// long as the stream is, and every read or write lands in those bytes. A
/// slice handed back by `buffered` or `takeArray` points into `buffer` and is
/// invalidated by any further use of the same stream, or by the caller's own
/// write to that memory — which is why the parsers in this tree either copy
/// what they keep or say in their own doc that they borrow.
///
/// `seek` is the one piece of state, and it is the position every method
/// reads at and advances past. A caller sets it directly to skip to the next
/// packet in a coalesced datagram; `seekBy` is the checked way to do that.
///
/// ## Running out of room
///
/// A read past the end is `error.EndOfStream` and a write past the end is
/// `error.NoSpaceLeft`, never a short read or a partial write: every method
/// either moves the whole of what it was asked for or moves nothing. A
/// decoder that ignores those errors decodes whatever it happens to reach.
///
/// ## A stream over a const buffer
///
/// `[]const u8` makes a read-only stream, and the write methods then compile
/// to nothing at all rather than refusing: a write into a const stream is
/// silently discarded. That is deliberate — a decoder takes the same type as
/// an encoder — and it is why nothing in the tree writes through a stream it
/// did not build with a mutable buffer.
pub fn FixedBufferStream(comptime Buffer: type) type {
    comptime std.debug.assert(@typeInfo(Buffer) == .pointer);
    const is_const_buf = @typeInfo(Buffer).pointer.is_const;
    const Slice = if (is_const_buf) []const u8 else []u8;

    return struct {
        buffer: Slice,
        seek: usize,

        const Self = @This();
        const is_const = is_const_buf;

        /// Reading a `[]const u8` stream cannot fail: every read is bounded by
        /// the buffer and `readSliceShort` is the only one that can come up
        /// short, by reporting the count it copied.
        pub const ReadError = error{};
        /// A write that does not fit in what is left of the buffer.
        pub const WriteError = error{NoSpaceLeft};
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

        pub fn takeArray(self: *Self, comptime n: usize) error{EndOfStream}!*[n]u8 {
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const ptr: *[n]u8 = @ptrCast(self.buffer[self.seek..][0..n].ptr);
            self.seek += n;
            return ptr;
        }

        pub fn writeAll(self: *Self, bytes: []const u8) WriteError!void {
            if (comptime is_const) return;
            if (bytes.len > self.buffer.len - self.seek) return error.NoSpaceLeft;
            @memcpy(self.buffer[self.seek..][0..bytes.len], bytes);
            self.seek += bytes.len;
        }

        pub fn writeByte(self: *Self, byte: u8) WriteError!void {
            if (comptime is_const) return;
            if (self.seek >= self.buffer.len) return error.NoSpaceLeft;
            self.buffer[self.seek] = byte;
            self.seek += 1;
        }

        pub fn writeInt(self: *Self, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
            if (comptime is_const) return;
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.NoSpaceLeft;
            mem.writeInt(T, self.buffer[self.seek..][0..n], value, endian);
            self.seek += n;
        }

        /// The bytes before the cursor: everything read or written so far.
        ///
        /// Borrowed from `buffer`, so it is good until the next use of this
        /// stream. This is how an encoder hands its output to a caller.
        ///
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
