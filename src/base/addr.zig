//! Primitive address values: what a path to a node can be spelled as.
//!
//! `IpAddress`, `SocketAddr` and `CustomAddr` are the leaves every higher
//! address is built from. Nothing here knows about a node id, a relay, a
//! transport or a ticket: `relay_url.zig`, `transport_addr.zig` and
//! `node_addr.zig` layer those on top of this module, which is what keeps the
//! dependency graph acyclic.

const std = @import("std");

/// An IP address without a port.
///
/// ozai keeps this separate from `std.Io.net` on purpose: this module is a
/// pure value layer with no runtime dependency, and the transport seam is
/// where the socket types are allowed to appear.
pub const IpAddress = union(enum) {
    /// Address bytes in network order. Every four-byte literal is valid.
    v4: [4]u8,
    /// Address bytes in network order. Every sixteen-byte literal is valid.
    v6: [16]u8,

    /// The address `text` names, or null when it names neither family.
    ///
    /// Both families are parsed bare, without the brackets a URI would carry
    /// around an IPv6 literal, and no zone or prefix is accepted. A name is
    /// not an address: resolving one belongs to `src/discovery/`.
    pub fn parse(text: []const u8) ?IpAddress {
        // `IpAddress.parseLiteral` wants IPv6 in URI bracket form, which is not
        // what anyone types into a config file. Parse each family bare instead.
        const v4 = std.Io.net.Ip4Address.parse(text, 0) catch return parseV6(text);
        return .{ .v4 = v4.bytes };
    }

    fn parseV6(text: []const u8) ?IpAddress {
        const v6 = std.Io.net.Ip6Address.parse(text, 0) catch return null;
        return .{ .v6 = v6.bytes };
    }

    /// Every v4 address before every v6 one, then lexicographic over the
    /// family's bytes. `SocketAddr` and `TransportAddr` order on top of this,
    /// so it is what decides the order a node's addresses encode in.
    pub fn order(self: IpAddress, other: IpAddress) std.math.Order {
        return switch (self) {
            .v4 => |a| switch (other) {
                .v4 => |b| std.mem.order(u8, &a, &b),
                .v6 => .lt,
            },
            .v6 => |a| switch (other) {
                .v4 => .gt,
                .v6 => |b| std.mem.order(u8, &a, &b),
            },
        };
    }

    /// A dotted quad for v4, lowercase hex with no brackets or colons for v6.
    /// `SocketAddr.format` is the form that has both the address and a port;
    /// this one leaves the v6 form unbracketed, so it cannot be pasted where
    /// a URI expects one.
    pub fn format(self: IpAddress, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .v4 => |b| try writer.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }),
            .v6 => |b| try writer.writeAll(&std.fmt.bytesToHex(&b, .lower)),
        }
    }
};

/// An IP address and a port: one directly reachable endpoint.
///
/// An owned fixed-size value with no allocation and no borrow, so it can be
/// stored in a set, put on the wire, and copied freely. The port is whatever
/// the caller put there: zero is not refused here, unlike `RelayUrl`, which
/// has a scheme to infer a default from.
pub const SocketAddr = struct {
    /// The address. Nothing else in the struct borrows or owns.
    ip: IpAddress,
    /// The port. Any `u16` is a valid value of this field.
    port: u16,

    /// The longest text `format` can produce, which is what a caller holding a
    /// buffer of its own sizes it by.
    ///
    /// Two brackets, sixteen address bytes as two hex digits each, the colon
    /// before the port and five port digits: `format` elides no zeros and
    /// writes no zone, so nothing longer can come out of it. A v4 address is
    /// nineteen shorter — fifteen characters of dotted quad against thirty-four
    /// of bracketed hex — so it is not the one that overruns. The bound is the
    /// derivation rather than a round number because a buffer sized to a round
    /// number is a buffer nobody has checked.
    pub const max_text_length: usize = 2 + 2 * 16 + 1 + 5;

    /// `address:port`, with a v6 address in brackets and every field written
    /// out: no elided zeros, no shortened IPv6 form, and no zone. At most
    /// `max_text_length` characters.
    pub fn format(self: SocketAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.ip) {
            .v4 => |address| try writer.print("{d}.{d}.{d}.{d}", .{
                address[0],
                address[1],
                address[2],
                address[3],
            }),
            .v6 => |address| {
                try writer.writeAll("[");
                for (address) |byte| try writer.print("{x:0>2}", .{byte});
                try writer.writeAll("]");
            },
        }
        try writer.print(":{d}", .{self.port});
    }

    /// Address first, then port. The order a set of direct addresses iterates
    /// in, and therefore the order a blob ticket writes them.
    pub fn order(self: SocketAddr, other: SocketAddr) std.math.Order {
        return switch (self.ip.order(other.ip)) {
            .eq => std.math.order(self.port, other.port),
            else => |ordering| ordering,
        };
    }
};

/// The id's width in the binary form: a little-endian `u64`.
pub const custom_id_length = 8;
/// Payload limit enforced by text/binary parsers and decoded tickets.
/// A manually constructed `CustomAddr.data` slice can exceed this bound.
pub const max_inline_length = 30;

/// Everything a custom address's two textual/binary forms refuse.
pub const CustomAddrParseError = error{
    /// No `_` separator, a data half that is not hex, or a binary form shorter
    /// than the id.
    Malformed,
    /// The hex id must fit a u64, so at most 16 digits and no `0x`.
    IdOutOfRange,
    /// The data half is hex, so its length must be even.
    OddDataLength,
    /// More data than a `CustomAddr` value carries inline.
    DataTooLong,
};

/// An address for a transport ozai does not know about, identified by a u64
/// from the public transport registry.
///
/// This is the extension seam: a new wire protocol registers an id here, and
/// everything above it — node addresses, tickets, the router — is unchanged.
///
/// `data` borrows storage the caller owns. Both constructors below say so, and
/// it is the borrow that matters: `NodeAddr.insert` copies a `TransportAddr`
/// onto the heap, so a pointer to a frame that has already been popped keeps
/// being read long after the frame is gone.
pub const CustomAddr = struct {
    /// The transport this address is for, from the public transport registry.
    id: u64,
    /// The transport's payload. Borrowed from whatever `parse` or
    /// `parseBinary` was given, so it has to stay alive and unmodified for as
    /// long as any copy of this address is read — including after the address
    /// has been copied into a `NodeAddr` by `insert`, which does not take a
    /// copy of the bytes.
    data: []const u8,

    /// Binary form: little-endian u64 id, then raw data. Eight bytes minimum.
    /// The result borrows `bytes`; keep them alive for as long as it is read.
    pub fn parseBinary(bytes: []const u8) CustomAddrParseError!CustomAddr {
        if (bytes.len < custom_id_length) return error.Malformed;
        if (bytes.len - custom_id_length > max_inline_length) return error.DataTooLong;
        const id = std.mem.readInt(u64, bytes[0..custom_id_length], .little);
        return .{ .id = id, .data = bytes[custom_id_length..] };
    }

    /// Write the binary form into `out`, which must be exactly
    /// `custom_id_length + self.data.len` long. That is a caller precondition,
    /// checked by a debug assertion: Debug and ReleaseSafe refuse a buffer of
    /// any other length, and ReleaseFast and ReleaseSmall do not check it and
    /// write past the end. The write is whole or nothing — there is no partial
    /// form and no error.
    pub fn writeBinary(self: CustomAddr, out: []u8) void {
        std.debug.assert(out.len == custom_id_length + self.data.len);
        std.mem.writeInt(u64, out[0..custom_id_length], self.id, .little);
        @memcpy(out[custom_id_length..], self.data);
    }

    /// Text form: `<hex id>_<hex data>`, split on the *first* underscore. The id
    /// is bare lowercase hex with no `0x` and no leading zeros, so `0_` is the
    /// canonical spelling of a custom address carrying no data.
    ///
    /// The bytes land in `storage` and the result borrows them, so the borrow's
    /// lifetime is the caller's decision, for the reason `RelayUrl.hostSlice`
    /// gives: a function that fills a local and returns a slice into it hands
    /// back a pointer to a frame that is dead the moment it returns. Here that
    /// pointer is read for as long as anything holds the address, and a
    /// `NodeAddr` holds it on the heap. Keep `storage` alive that long.
    pub fn parse(
        text: []const u8,
        storage: *[max_inline_length]u8,
    ) CustomAddrParseError!CustomAddr {
        const separator = std.mem.indexOfScalar(u8, text, '_') orelse return error.Malformed;
        const id_text = text[0..separator];
        const data_text = text[separator + 1 ..];
        if (id_text.len == 0 or id_text.len > 16) return error.IdOutOfRange;
        if (data_text.len % 2 != 0) return error.OddDataLength;

        const id = std.fmt.parseInt(u64, id_text, 16) catch return error.IdOutOfRange;
        const data_length = data_text.len / 2;
        if (data_length > max_inline_length) return error.DataTooLong;

        _ = std.fmt.hexToBytes(storage[0..data_length], data_text) catch return error.Malformed;
        return .{ .id = id, .data = storage[0..data_length] };
    }

    /// `<hex id>_<hex data>`, the inverse of `parse`: the id without `0x` or
    /// leading zeros, then each payload byte as two hex digits.
    pub fn format(self: CustomAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}_", .{self.id});
        for (self.data) |byte| try writer.print("{x:0>2}", .{byte});
    }

    /// Id first, then payload bytes lexicographically. Two custom addresses
    /// are the same address exactly when this says `.eq`, which is what makes
    /// a repeated one in a ticket a duplicate rather than a second path.
    pub fn order(self: CustomAddr, other: CustomAddr) std.math.Order {
        if (self.id != other.id) return std.math.order(self.id, other.id);
        return std.mem.order(u8, self.data, other.data);
    }
};

const t = std.testing;

/// Fill a frame big enough to cover whatever `parse` or `insert` unwound, so a
/// slice into a dead frame reads back as poison instead of as the bytes it
/// happened to leave behind. `never_inline` is load-bearing: an inlined helper
/// would poison the caller's own live locals rather than the dead region.
pub fn clobberStack() void {
    var poison: [2048]u8 = undefined;
    @memset(&poison, 0xcd);
    std.mem.doNotOptimizeAway(&poison);
}

test "ip address parsing accepts both families and rejects rubbish" {
    const loopback = IpAddress.parse("127.0.0.1") orelse return error.TestUnexpectedResult;
    try t.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &loopback.v4);
    try t.expect(IpAddress.parse("::1") != null);
    try t.expectEqual(@as(?IpAddress, null), IpAddress.parse("127.0.0.256"));
    try t.expectEqual(@as(?IpAddress, null), IpAddress.parse("example.com"));
}

test "the longest text a socket address prints is exactly max_text_length" {
    // Every field at its widest: sixteen v6 bytes that each print as two hex
    // digits, and a port of five digits. That is the whole of
    // `max_text_length` and nothing else can reach it.
    const longest: SocketAddr = .{
        .ip = .{ .v6 = @splat(0xff) },
        .port = std.math.maxInt(u16),
    };
    var text: [SocketAddr.max_text_length]u8 = undefined;
    // Into a buffer of exactly the bound: one with room to spare would pass
    // whether or not the bound is right.
    const printed = try std.fmt.bufPrint(&text, "{f}", .{longest});
    try t.expectEqual(SocketAddr.max_text_length, printed.len);

    // And the narrow family, nineteen shorter: the arithmetic in the constant's
    // doc comment stated as a check rather than left as a claim.
    const narrow: SocketAddr = .{
        .ip = .{ .v4 = .{ 255, 255, 255, 255 } },
        .port = std.math.maxInt(u16),
    };
    try t.expectEqual(
        SocketAddr.max_text_length - 19,
        (try std.fmt.bufPrint(&text, "{f}", .{narrow})).len,
    );
}

test "custom address binary form is a little-endian id then raw data" {
    const addr: CustomAddr = .{ .id = 0x0102, .data = &[_]u8{ 0xaa, 0xbb } };
    var binary: [custom_id_length + 2]u8 = undefined;
    addr.writeBinary(&binary);

    const parsed = try CustomAddr.parseBinary(&binary);
    try t.expectEqual(addr.id, parsed.id);
    try t.expectEqualSlices(u8, addr.data, parsed.data);

    try t.expectError(error.Malformed, CustomAddr.parseBinary(binary[0..7]));
    try t.expectError(
        error.DataTooLong,
        CustomAddr.parseBinary(binary[0..custom_id_length] ++ "x" ** 31),
    );
}

test "custom address text form splits on the first underscore" {
    var storage: [max_inline_length]u8 = undefined;
    const parsed = try CustomAddr.parse("2a_abab", &storage);
    try t.expectEqual(@as(u64, 0x2a), parsed.id);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, parsed.data);

    const no_data = try CustomAddr.parse("0_", &storage);
    try t.expectEqual(@as(usize, 0), no_data.data.len);

    try t.expectError(error.Malformed, CustomAddr.parse("2a", &storage));
    try t.expectError(error.IdOutOfRange, CustomAddr.parse("zz_ab", &storage));
    try t.expectError(error.OddDataLength, CustomAddr.parse("2a_abc", &storage));
    // The fourth arm, from this parser rather than from `parseBinary`: two hex
    // digits per data byte, so `max_inline_length + 1` pairs is one byte past
    // what a `CustomAddr` carries inline, and the length is even so the length
    // check is what refuses it rather than the digit count.
    try t.expectError(
        error.DataTooLong,
        CustomAddr.parse("1_" ++ ("aa" ** (max_inline_length + 1)), &storage),
    );
}

test "custom address text form outlives the frame it was parsed in" {
    // `storage` is the caller's, and outlives the clobber below by
    // construction. `parse` returning a slice into a frame of its own is the
    // bug this pins: that frame dies before the next line runs.
    var storage: [max_inline_length]u8 = undefined;
    const parsed = try CustomAddr.parse("2a_abab", &storage);
    @call(.never_inline, clobberStack, .{});

    // Snapshot with no call in between: the assertion is a call, and its frame
    // lands on the region this test exists to inspect, replacing the poison
    // with unrelated garbage.
    const seen = [_]u8{ parsed.data[0], parsed.data[1] };
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, &seen);
    try t.expectEqual(@as(u64, 0x2a), parsed.id);
}
