//! Node addressing: how a `NodeId` becomes reachable.
//!
//! A node id alone is not an address. `NodeAddr` pairs it with the paths that
//! might reach the node — relay servers, direct IP addresses, and opaque custom
//! transports — sorted and deduplicated so that the same address always
//! produces the same bytes in a ticket.
//!
//! # What lives where
//!
//! This file holds the node-facing half of addressing and is a facade over
//! `base/relay.zig`, which holds the host-facing half: an IP literal, a socket
//! and a relay URL, with the value orders that make two spellings of one
//! address the same. Every name below is bound from exactly one of the two, so
//! a caller that imports this file names neither of them. `TransportAddr` is
//! the one type that spans the boundary and it stays here, because it is the
//! union of the two halves rather than a member of either.

const std = @import("std");
const key = @import("key.zig");
const relay_mod = @import("relay.zig");

pub const NodeId = key.NodeId;

// -- The re-exports ----------------------------------------------------------
//
// `relay.zig` owns these; `base/addr.zig` is where a caller looks for them,
// because a node address is spelled out of them and not next to them.

pub const IpAddress = relay_mod.IpAddress;
pub const SocketAddr = relay_mod.SocketAddr;
pub const RelayUrlParseError = relay_mod.RelayUrlParseError;
pub const RelayUrlResolveError = relay_mod.RelayUrlResolveError;
pub const RelayUrl = relay_mod.RelayUrl;

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

/// One way to reach a node.
///
/// A value with no lifetime of its own: `relay` and `ip` are inline values,
/// and `custom` borrows its payload, so a `TransportAddr` may be copied into
/// storage that outlives the bytes it points at. Nothing here owns anything.
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
            return std.math.order(@backingInt(self_tag), @backingInt(other_tag));
        }
        return switch (self) {
            .relay => |url| url.order(other.relay),
            .ip => |addr| addr.order(other.ip),
            .custom => |addr| addr.order(other.custom),
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
            .ip => |addr| {
                try writer.writeAll("ip:");
                try addr.format(writer);
            },
            .custom => |addr| {
                try writer.writeAll("custom:");
                try addr.format(writer);
            },
        }
    }
};

/// `std.sort.lowerBound` takes a free function, not a method.
fn orderTransport(a: TransportAddr, b: TransportAddr) std.math.Order {
    return a.order(b);
}

/// A node id plus the paths that might reach it.
///
/// `addrs` is kept sorted and duplicate-free. That invariant is what makes an
/// address encode to the same bytes every time, which is in turn what makes a
/// ticket a stable identifier rather than a fresh value on every send.
///
/// **The list is all a `NodeAddr` owns.** One allocation, made by `withRelay`
/// or by a successful `insert` — never by `init`, which hands back an empty
/// literal — and released by exactly one `deinit`. A `.custom`
/// address inside it *borrows* its payload from whoever parsed it; `deinit`
/// does not free a borrow and cannot, since the payload is not reachable from
/// here. A caller that owns such a payload keeps that obligation across every
/// `insert` and after `deinit`.
///
/// Copying a `NodeAddr` copies the handle, not the storage: both copies name
/// one allocation, so exactly one of them may be freed and both read the same
/// addresses. `insert` replaces the allocation, so after a successful insert
/// the previous value is dangling — see `insert`.
pub const NodeAddr = struct {
    /// The identity every one of `addrs` is a path to.
    node_id: NodeId,
    /// Sorted by `TransportAddr.order`, unique. Mutate only through `insert`.
    addrs: []TransportAddr,

    /// An address with no paths: the empty list. It owns nothing, so `deinit`
    /// on it frees nothing and is safe.
    pub fn init(node_id: NodeId) NodeAddr {
        return .{ .node_id = node_id, .addrs = &.{} };
    }

    /// Insert keeping the slice sorted and unique. Returns `null`, with
    /// nothing allocated and the receiver unchanged, when the address was
    /// already present.
    ///
    /// On success the returned `NodeAddr` holds a *new* allocation — `realloc`
    /// may also have moved the old one — so the receiver and every copy of it
    /// are invalid: do not read through them and do not free them. Adopt the
    /// returned value from here on.
    ///
    /// `error.OutOfMemory` leaves the receiver exactly as it was and still
    /// valid, so the caller keeps owning its list; nothing was allocated.
    ///
    /// Either way the caller keeps ownership of `addr`: a successful insert
    /// copies the `TransportAddr` shallowly, so a `.custom` payload stays a
    /// borrow the caller must keep alive for as long as the list is read.
    pub fn insert(
        self: NodeAddr,
        alloc: std.mem.Allocator,
        addr: TransportAddr,
    ) std.mem.Allocator.Error!?NodeAddr {
        const at = std.sort.lowerBound(TransportAddr, self.addrs, addr, orderTransport);
        if (at < self.addrs.len and self.addrs[at].order(addr) == .eq) return null;
        const grown = try alloc.realloc(self.addrs, self.addrs.len + 1);
        // `@memmove`, not `@memcpy`: the destination starts one element
        // *after* the source, so the two ranges overlap and a forward copy
        // would write each element over the one the next step still has to
        // read. `@memmove` is the only one of the two that is defined for
        // overlap, so the direction is its problem to get right and not the
        // caller's to reason about.
        @memmove(grown[at + 1 ..], grown[at..self.addrs.len]);
        grown[at] = addr;
        return .{ .node_id = self.node_id, .addrs = grown };
    }

    /// A one-address `NodeAddr` carrying `url`, with a new list allocation.
    ///
    /// `error.OutOfMemory` allocates nothing, and `url` is a value, so the
    /// caller's copy is unaffected either way.
    pub fn withRelay(
        alloc: std.mem.Allocator,
        node_id: NodeId,
        url: RelayUrl,
    ) std.mem.Allocator.Error!NodeAddr {
        const one = try alloc.dupe(TransportAddr, &.{.{ .relay = url }});
        return .{ .node_id = node_id, .addrs = one };
    }

    /// Free the address list, and nothing else.
    ///
    /// Custom payloads in the list are the caller's and are left untouched;
    /// whoever allocated one still owns it. The address and every copy of it
    /// are invalid afterward, and a second call is a double free.
    pub fn deinit(self: NodeAddr, alloc: std.mem.Allocator) void {
        alloc.free(self.addrs);
    }

    /// How many of `addrs` are relay addresses.
    pub fn relayCount(self: NodeAddr) usize {
        var count: usize = 0;
        for (self.addrs) |addr| {
            if (addr == .relay) count += 1;
        }
        return count;
    }

    /// The node id in hex, then every address as `relay:`, `ip:` or
    /// `custom:`, separated by spaces.
    pub fn format(self: NodeAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.node_id.format(writer);
        for (self.addrs) |addr| {
            try writer.writeAll(" ");
            try addr.format(writer);
        }
    }
};

const t = std.testing;

/// Fill a frame big enough to cover whatever `parse` or `insert` unwound, so a
/// slice into a dead frame reads back as poison instead of as the bytes it
/// happened to leave behind. `never_inline` is load-bearing: an inlined helper
/// would poison the caller's own live locals rather than the dead region.
fn clobberStack() void {
    var poison: [2048]u8 = undefined;
    @memset(&poison, 0xcd);
    std.mem.doNotOptimizeAway(&poison);
}

test "relay url parse fills in the default port and keeps a fully qualified host" {
    const url = try RelayUrl.parse("https://use1-1.relay.iroh.network./");
    try t.expectEqual(RelayUrl.Scheme.https, url.scheme);
    try t.expectEqualStrings("use1-1.relay.iroh.network.", url.hostSlice());
    try t.expectEqual(RelayUrl.default_https_port, url.port);

    const local = try RelayUrl.parse("http://127.0.0.1:7842/");
    try t.expectEqual(@as(u16, 7842), local.port);
}

test "a relay url becomes a socket when its host is a literal, and is refused when it is not" {
    const local = try RelayUrl.parse("http://127.0.0.1:7842/");
    try t.expectEqual(
        SocketAddr{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 7842 },
        try local.socketAddr(),
    );

    // The scheme's default port survives: the port is the URL's either way.
    const named_port = try RelayUrl.parse("http://192.0.2.7/");
    try t.expectEqual(
        SocketAddr{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = RelayUrl.default_http_port },
        try named_port.socketAddr(),
    );

    // A name is discovery's problem, and saying so is the whole answer. It is
    // not `Malformed`: the URL parsed, and what it will not give up is a host.
    try t.expectError(
        error.NotAnIpLiteral,
        (try RelayUrl.parse("https://use1-1.relay.iroh.network./")).socketAddr(),
    );
    try t.expectError(
        error.NotAnIpLiteral,
        (try RelayUrl.parse("http://7842/")).socketAddr(),
    );
}

test "a bracketed ipv6 relay host is an address, not a name" {
    // Brackets are URL syntax, not part of the address, and `std.Uri` hands
    // `parse` the host with both of them still on it. A literal behind them is
    // as good a relay host as any other, so calling it a name drops an address
    // the dial already has.
    const loopback = try RelayUrl.parse("http://[::1]:7842/");
    try t.expectEqual(
        SocketAddr{
            .ip = .{ .v6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
            .port = 7842,
        },
        try loopback.socketAddr(),
    );

    // The port is the URL's either way and is defaulted from the scheme, with
    // the brackets or without, so the second case pins an address that is not
    // a run of zeros against the https default at once.
    const documented = try RelayUrl.parse("https://[2001:db8::1]/");
    try t.expectEqual(
        SocketAddr{
            .ip = .{ .v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
            .port = RelayUrl.default_https_port,
        },
        try documented.socketAddr(),
    );
}

test "relay url rejects what is not a relay" {
    try t.expectError(error.Malformed, RelayUrl.parse("not a url"));
    try t.expectError(error.UnsupportedScheme, RelayUrl.parse("ftp://example.com./"));
    try t.expectError(error.UnexpectedComponent, RelayUrl.parse("https://example.com./relay"));
    try t.expectError(error.UnexpectedComponent, RelayUrl.parse("https://example.com./?x=1"));
    try t.expectError(error.HostTooLong, RelayUrl.parse("https://" ++ (&@as([254:0]u8, @splat('a'))) ++ "./"));
    // Port 0 is the one value of `port` no `RelayUrl` may carry, and `parse`
    // is what keeps it out: `std.Uri` hands `:0` over as the number zero
    // rather than refusing it, so the check is this module's own line. That
    // is what makes `port`'s nonzero a precondition every value already
    // meets — see that field.
    try t.expectError(error.InvalidPort, RelayUrl.parse("https://example.com:0/"));
}

test "relay url ordering is scheme, then port, then host" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const c = try RelayUrl.parse("https://a.example.:8443/");
    const d = try RelayUrl.parse("http://a.example./");

    try t.expectEqual(std.math.Order.lt, a.order(b));
    try t.expectEqual(std.math.Order.lt, a.order(c));
    // `Scheme` is declared http-then-https and the ordering follows the tag, so
    // http sorts first.
    try t.expectEqual(std.math.Order.lt, d.order(a));
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
        CustomAddr.parseBinary(binary[0..custom_id_length] ++ &@as([31:0]u8, @splat('x'))),
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

test "custom address outlives the copy into a node address" {
    const node_id = (try key.SecretKey.fromSeed(@as([key.SecretKey.seed_length]u8, @splat(2)))).nodeId();
    const alloc = t.allocator;
    var storage: [max_inline_length]u8 = undefined;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);

    const custom = try CustomAddr.parse("2a_abab", &storage);
    addr = (try addr.insert(alloc, .{ .custom = custom })) orelse
        return error.TestUnexpectedResult;
    @call(.never_inline, clobberStack, .{});

    // The heap slice now holds what `parse` handed back, so this is the same
    // dangling read as above, one lifetime longer, read the same way.
    const stored = addr.addrs[1].custom;
    const seen = [_]u8{ stored.data[0], stored.data[1] };
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, &seen);
    try t.expectEqual(@as(u64, 0x2a), stored.id);
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(addr.addrs[1]));
}

test "transport address ordering is variant, then inner" {
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://r.example./") };
    const unspecified = IpAddress.parse("0.0.0.0") orelse return error.TestUnexpectedResult;
    const ip: TransportAddr = .{ .ip = .{ .ip = unspecified, .port = 1 } };
    const custom: TransportAddr = .{ .custom = .{ .id = 0, .data = &.{} } };

    try t.expectEqual(std.math.Order.lt, relay.order(ip));
    try t.expectEqual(std.math.Order.lt, ip.order(custom));
    try t.expectEqual(std.math.Order.eq, relay.order(relay));
}

test "node addr keeps its address list sorted and unique" {
    const node_id = (try key.SecretKey.fromSeed(@as([key.SecretKey.seed_length]u8, @splat(1)))).nodeId();
    const alloc = t.allocator;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);
    try t.expectEqual(@as(usize, 1), addr.addrs.len);

    const host = IpAddress.parse("10.0.0.1") orelse return error.TestUnexpectedResult;
    const direct: TransportAddr = .{ .ip = .{ .ip = host, .port = 9 } };
    addr = (try addr.insert(alloc, direct)) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // The duplicate must be rejected, and must not have grown the slice.
    try t.expectEqual(@as(?NodeAddr, null), try addr.insert(alloc, direct));
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // Relay sorts before ip by variant, so it stays at index 0.
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(addr.addrs[0]));
    try t.expectEqual(@as(usize, 1), addr.relayCount());

    var index: usize = 1;
    while (index < addr.addrs.len) : (index += 1) {
        try t.expectEqual(std.math.Order.lt, addr.addrs[index - 1].order(addr.addrs[index]));
    }
}

/// Strictly increasing is sorted *and* unique in one pass, which is the whole
/// invariant `insert` exists to maintain.
fn expectSortedAndUnique(addrs: []const TransportAddr) !void {
    var index: usize = 1;
    while (index < addrs.len) : (index += 1) {
        try t.expectEqual(std.math.Order.lt, addrs[index - 1].order(addrs[index]));
    }
}

test "a mid-list insert keeps every address it shifted" {
    // The relay sorts ahead of both sockets by variant order, so it lands at
    // index 0 with two addresses behind it. Every other insert in this file
    // appended, where the shift copies nothing and a copy in the wrong
    // direction is indistinguishable from a copy in the right one.
    const node_id = (try key.SecretKey.fromSeed(@as([key.SecretKey.seed_length]u8, @splat(1)))).nodeId();
    const alloc = t.allocator;
    const first_host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    const first: TransportAddr = .{ .ip = .{ .ip = first_host, .port = 60165 } };
    const second_host = IpAddress.parse("213.208.157.87") orelse return error.TestUnexpectedResult;
    const second: TransportAddr = .{ .ip = .{ .ip = second_host, .port = 60165 } };
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://relay.example./") };

    var addr: NodeAddr = .{
        .node_id = node_id,
        .addrs = try alloc.dupe(TransportAddr, &.{ first, second }),
    };
    defer addr.deinit(alloc);

    addr = (try addr.insert(alloc, relay)) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 3), addr.addrs.len);
    try expectSortedAndUnique(addr.addrs);

    // Copied forwards, the shift writes `first` over `second`: the length and
    // the variant order both still look right, so the values themselves are
    // the only thing that catches it.
    try t.expectEqual(std.math.Order.eq, addr.addrs[0].order(relay));
    try t.expectEqual(std.math.Order.eq, addr.addrs[1].order(first));
    try t.expectEqual(std.math.Order.eq, addr.addrs[2].order(second));

    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try addr.format(&writer);
    const text = writer.buffered();
    try t.expect(std.mem.indexOf(u8, text, "relay:https://relay.example./") != null);
    try t.expect(std.mem.indexOf(u8, text, "ip:192.168.96.145:60165") != null);
    try t.expect(std.mem.indexOf(u8, text, "ip:213.208.157.87:60165") != null);
}

test "a duplicate with addresses behind it is rejected and changes nothing" {
    // `first` has `second` behind it, so the lower bound lands short of the
    // end. A duplicate at the last index cannot tell a rejection that fires
    // before the shift from one that fires because nothing had to move.
    const node_id = (try key.SecretKey.fromSeed(@as([key.SecretKey.seed_length]u8, @splat(1)))).nodeId();
    const alloc = t.allocator;
    const first_host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    const first: TransportAddr = .{ .ip = .{ .ip = first_host, .port = 60165 } };
    const second_host = IpAddress.parse("213.208.157.87") orelse return error.TestUnexpectedResult;
    const second: TransportAddr = .{ .ip = .{ .ip = second_host, .port = 60165 } };
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://relay.example./") };

    const addr: NodeAddr = .{
        .node_id = node_id,
        .addrs = try alloc.dupe(TransportAddr, &.{ relay, first, second }),
    };
    defer addr.deinit(alloc);

    try t.expectEqual(@as(?NodeAddr, null), try addr.insert(alloc, first));
    try t.expectEqual(@as(usize, 3), addr.addrs.len);
    try expectSortedAndUnique(addr.addrs);
    try t.expectEqual(std.math.Order.eq, addr.addrs[1].order(first));
    try t.expectEqual(std.math.Order.eq, addr.addrs[2].order(second));
}
