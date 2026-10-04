//! The receive half of the batch seam: one buffer a `recvmsg` filled, which is
//! either one datagram or a list of them coalesced into it.
//!
//! `Send` and `Recv` are mirror images and the hazard is the same one on both
//! sides of rule 7 in `docs/ARCHITECTURE.md`: a buffer holding three
//! datagrams, handed to a caller expecting one, is a caller reading a datagram
//! header out of the middle of a packet. So the stride is in the value rather
//! than implied by the buffer, and every read answers `datagramCount` before
//! anything is taken from it.

const std = @import("std");

const batch = @import("batch.zig");

const Ecn = batch.Ecn;
const Error = batch.Error;
const divCeil = batch.divCeil;

const std_testing = std.testing;

/// One buffer a `recvmsg` filled: one datagram, or a list coalesced into it.
///
/// The mirror image of `Send`, and the hazard is the same one as rule 7's: a
/// buffer holding three datagrams handed to a caller expecting one is a
/// caller that reads a datagram header out of the middle of a packet. So the
/// stride is in the value rather than implied by the buffer, and every read
/// answers `datagramCount` before anything is taken from it.
pub const Recv = struct {
    /// Borrowed views into the receive buffer. Reusing or releasing that
    /// buffer invalidates this value and every returned datagram slice.
    /// The bytes the socket wrote.
    bytes: []const u8,
    /// The size of one datagram in `bytes`. Equal to `bytes.len` unless a
    /// list was coalesced; every datagram but the last is exactly this long
    /// and the last may be shorter.
    stride: usize,
    /// The codepoint the read carried, or null for none. The wire cannot tell
    /// no codepoint from any other value that reduces to zero, so `Ecn` is
    /// the two bits or nothing.
    ecn: ?Ecn,

    /// A read, given the `UDP_GRO` control message that came with it, or null
    /// when no coalescing control message arrived at all.
    ///
    /// noq initialises `RecvMeta::stride` to `len` and overwrites it only
    /// when a `UDP_GRO` control message arrives
    /// (`noq-udp/src/unix.rs:700` and `:781-784`). A null stride and a stride
    /// equal to the buffer's own length are therefore the same value, and a
    /// coalesced read of exactly one datagram is indistinguishable from an
    /// uncoalesced one. That is the property that makes the null arm safe,
    /// and it is what a test pins.
    ///
    /// A zero stride is refused, which also refuses a zero-length read: a
    /// buffer with no datagram in it is not a read this seam models.
    pub fn init(bytes: []const u8, stride: ?usize, ecn: ?Ecn) Error!Recv {
        const size = stride orelse bytes.len;
        if (size == 0) return error.ZeroSegmentSize;
        if (size > bytes.len) return error.StrideExceedsBuffer;
        return .{ .bytes = bytes, .stride = size, .ecn = ecn };
    }

    /// How many datagrams arrived in this one read.
    pub fn datagramCount(self: Recv) usize {
        return divCeil(self.bytes.len, self.stride);
    }

    /// The i-th datagram of the buffer, or null when there is no i-th.
    ///
    /// The last datagram of a coalesced list is short rather than absent, so
    /// this is a slice of the tail and not a truncated one.
    pub fn datagram(self: Recv, index: usize) ?[]const u8 {
        const start = std.math.mul(usize, index, self.stride) catch return null;
        if (start >= self.bytes.len) return null;
        return self.bytes[start..@min(start + self.stride, self.bytes.len)];
    }

    /// The codepoint a read's control message carried, or null when its bits
    /// reduce to zero.
    ///
    /// The wire carries two bits in `IP_TOS` or `IPV6_TCLASS` and zero is
    /// `IP_TOS_NOT_ECT`, so "no codepoint" is a value and not an absence:
    /// a stack that dropped the control message and a stack that read a
    /// not-ECT datagram both land here, which is why `socketOptions` exists.
    pub fn ecnFromBits(bits: u8) ?Ecn {
        return Ecn.fromBits(bits);
    }
};

test "a coalesced read of one datagram is the uncoalesced read" {
    const datagram = [_]u8{0x5a} ** 64;
    const plain = try Recv.init(&datagram, null, .ect1);
    const coalesced = try Recv.init(&datagram, datagram.len, .ect1);
    try std_testing.expectEqual(plain.stride, coalesced.stride);
    try std_testing.expectEqual(plain.datagramCount(), coalesced.datagramCount());
    try std_testing.expectEqual(@as(usize, 1), plain.datagramCount());
    try std_testing.expectEqualSlices(u8, &datagram, plain.datagram(0).?);
    try std_testing.expectEqualSlices(u8, &datagram, coalesced.datagram(0).?);
    try std_testing.expect(coalesced.datagram(1) == null);
    try std_testing.expectEqual(@as(?Ecn, .ect1), coalesced.ecn);
}

test "a coalesced read is a list of datagrams" {
    // Three datagrams of sixteen bytes, each filled with its own index, so a
    // run cut in the wrong place is visible in the bytes and not only in the
    // count. Built here rather than borrowed from the send half's fixture
    // helper: a test that reaches across a module boundary for its data is a
    // test that stops compiling when the other half moves.
    var bytes: [48]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index / 16);
    const recv = try Recv.init(&bytes, 16, null);
    try std_testing.expectEqual(@as(usize, 3), recv.datagramCount());
    var index: usize = 0;
    while (recv.datagram(index)) |datagram| {
        try std_testing.expectEqual(@as(usize, 16), datagram.len);
        index += 1;
    }
    try std_testing.expectEqual(@as(usize, 3), index);

    // The last datagram of a coalesced list is short, not absent, and the
    // bytes past it are the end of the buffer.
    const short = try Recv.init(bytes[0..38], 16, null);
    try std_testing.expectEqual(@as(usize, 3), short.datagramCount());
    try std_testing.expectEqual(@as(usize, 6), short.datagram(2).?.len);
    try std_testing.expect(short.datagram(3) == null);
}

test "a datagram index that overflows the byte offset returns null" {
    // This index would wrap to the first datagram in unchecked builds.
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const recv = try Recv.init(&bytes, 4, null);
    const wrapped_index = std.math.maxInt(usize) / recv.stride + 1;
    try std_testing.expect(recv.datagram(wrapped_index) == null);
}

test "a receive buffer's datagrams put it back together, at every stride" {
    // The mirror of the send-side property, and the one that matters for a
    // caller reading a coalesced read: every datagram is whole except the last,
    // concatenating them in index order reproduces the buffer byte for byte,
    // and the count is the number of datagrams `datagram` will hand out. A
    // stride wider than the buffer is refused rather than clamped, so the
    // stride here is always one the buffer can hold.
    const alloc = std_testing.allocator;
    const lengths = [_]usize{ 1, 2, 7, 16, 64, 100 };
    const strides = [_]usize{ 1, 3, 8, 64, 100 };
    for (lengths) |len| {
        for (strides) |stride| {
            if (stride > len) continue;
            const bytes = try alloc.alloc(u8, len);
            defer alloc.free(bytes);
            for (bytes, 0..) |*byte, index| byte.* = @truncate(index);
            const joined = try alloc.alloc(u8, len);
            defer alloc.free(joined);

            const recv = try Recv.init(bytes, stride, null);
            try std_testing.expectEqual(stride, recv.stride);
            var filled: usize = 0;
            var index: usize = 0;
            while (recv.datagram(index)) |datagram| {
                // Every datagram but the last is exactly one stride, and the
                // last is short rather than absent.
                try std_testing.expect(datagram.len == stride or
                    filled + datagram.len == len);
                @memcpy(joined[filled..][0..datagram.len], datagram);
                filled += datagram.len;
                index += 1;
            }
            try std_testing.expectEqual(recv.datagramCount(), index);
            try std_testing.expectEqualSlices(u8, bytes, joined[0..filled]);
            // And one past the last is null rather than a wrap: this is the
            // index that would overflow the byte offset.
            try std_testing.expect(recv.datagram(index) == null);
        }
    }
}

test "a null stride and a full-buffer stride are the same read" {
    // The property that makes `Recv.init`'s null arm safe, stated over every
    // length a coalesced read can arrive at: a control message that never came
    // and one that named the buffer's own length are the same value, because
    // noq initialises the stride to the length and overwrites it only when one
    // arrives (`noq-udp/src/unix.rs:700`).
    const alloc = std_testing.allocator;
    for ([_]usize{ 1, 2, 7, 64, 1200, 4096 }) |len| {
        const bytes = try alloc.alloc(u8, len);
        defer alloc.free(bytes);
        @memset(bytes, 0x5a);
        const uncoalesced = try Recv.init(bytes, null, .ect0);
        const coalesced = try Recv.init(bytes, len, .ect0);
        try std_testing.expectEqual(uncoalesced.stride, coalesced.stride);
        try std_testing.expectEqual(uncoalesced.datagramCount(), coalesced.datagramCount());
        try std_testing.expectEqual(@as(usize, 1), uncoalesced.datagramCount());
        try std_testing.expectEqualSlices(u8, bytes, uncoalesced.datagram(0).?);
        try std_testing.expectEqualSlices(u8, bytes, coalesced.datagram(0).?);
        try std_testing.expect(coalesced.datagram(1) == null);
    }
}
