//! Node addressing: how a `NodeId` becomes reachable.
//!
//! A node id alone is not an address. `NodeAddr` pairs it with the paths that
//! might reach the node — relay servers, direct IP addresses, and opaque custom
//! transports — sorted and deduplicated so that the same address always
//! produces the same bytes in a ticket.

const std = @import("std");
const key = @import("key.zig");

pub const NodeId = key.NodeId;

/// An IP address without a port.
///
/// ozai keeps this separate from `std.Io.net` on purpose: this module is a
/// pure value layer with no runtime dependency, and the transport seam is
/// where the socket types are allowed to appear.
pub const IpAddress = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

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

    pub fn format(self: IpAddress, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .v4 => |b| try writer.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }),
            .v6 => |b| try writer.writeAll(&std.fmt.bytesToHex(&b, .lower)),
        }
    }
};

pub const SocketAddr = struct {
    ip: IpAddress,
    port: u16,

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

    pub fn order(self: SocketAddr, other: SocketAddr) std.math.Order {
        return switch (self.ip.order(other.ip)) {
            .eq => std.math.order(self.port, other.port),
            else => |ordering| ordering,
        };
    }
};

pub const RelayUrlParseError = error{
    /// Not a URI, or a URI missing the parts a relay needs.
    Malformed,
    /// Only `http` and `https` identify a relay. Anything else is a caller bug
    /// that would otherwise surface much later as a confusing TLS failure.
    UnsupportedScheme,
    /// A relay URL carries no query, fragment or path; something in them
    /// usually means the string is not a relay address at all.
    UnexpectedComponent,
    /// Host empty, or longer than RFC 1035 allows.
    HostTooLong,
    /// Port 0 is never a relay.
    InvalidPort,
};

/// The address of a relay server.
///
/// An owned, fixed-size value: no allocation, no borrowed lifetime, safe to
/// store in a set and hand across threads. The 253-byte host field is RFC 1035's
/// maximum name length, so a longer host is malformed rather than merely long.
///
/// Convention, deliberately not enforced: write relay hosts fully qualified with
/// a trailing dot (`relay.example.com.`). Without it the host resolver may
/// append a local search domain and resolve somewhere other than intended.
pub const RelayUrl = struct {
    /// RFC 1035 §2.3.4 maximum name length.
    pub const max_host_length = 253;
    pub const default_http_port = 80;
    pub const default_https_port = 443;

    pub const Scheme = enum { http, https };

    scheme: Scheme,
    host: [max_host_length]u8,
    host_length: u8,
    port: u16,

    pub fn parse(text: []const u8) RelayUrlParseError!RelayUrl {
        const uri = std.Uri.parse(text) catch return error.Malformed;
        if (uri.query != null or uri.fragment != null) return error.UnexpectedComponent;
        // A `Component` is a union: read either arm as-is. Percent-encoding in
        // a relay path is already a malformed relay URL.
        const path: []const u8 = switch (uri.path) {
            .raw => |value| value,
            .percent_encoded => |value| value,
        };
        if (path.len != 0 and !std.mem.eql(u8, path, "/")) return error.UnexpectedComponent;

        const scheme: Scheme = if (std.mem.eql(u8, uri.scheme, "https"))
            .https
        else if (std.mem.eql(u8, uri.scheme, "http"))
            .http
        else
            return error.UnsupportedScheme;

        const host_component = uri.host orelse return error.Malformed;
        const host: []const u8 = switch (host_component) {
            .raw => |value| value,
            .percent_encoded => |value| value,
        };
        // Narrow to the field's `u8` once, here, so the bound is proved where
        // the cast is; 253 fits a `u8`, so the cast alone admits 254 and 255.
        const host_length: u8 = std.math.cast(u8, host.len) orelse return error.HostTooLong;
        if (host_length == 0 or host_length > max_host_length) return error.HostTooLong;

        const port: u16 = uri.port orelse switch (scheme) {
            .http => default_http_port,
            .https => default_https_port,
        };
        if (port == 0) return error.InvalidPort;

        var result: RelayUrl = .{
            .scheme = scheme,
            .host = undefined,
            .host_length = host_length,
            .port = port,
        };
        @memcpy(result.host[0..host_length], host);
        return result;
    }

    /// The host as a borrowed slice.
    ///
    /// This takes a pointer rather than a value on purpose. `RelayUrl` is a
    /// 258-byte struct, and a method taking it by value can return a slice
    /// pointing into a callee temporary that is dead the moment it returns.
    /// A pointer receiver makes the borrow's lifetime the caller's decision.
    pub fn hostSlice(self: *const RelayUrl) []const u8 {
        return self.host[0..self.host_length];
    }

    /// Canonical text form: scheme, host, the port only when it is not the
    /// scheme default, and a trailing `/`.
    ///
    /// The trailing slash is not decoration. iroh writes relay URLs in exactly
    /// this shape and a ticket carries the URL as bytes, so any other spelling
    /// is a different address as far as a peer is concerned. `parse` also
    /// accepts a URL with no path, because a human writes
    /// `https://relay.example.com` and should not have to know the above.
    pub fn format(self: RelayUrl, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}://{s}", .{ @tagName(self.scheme), self.hostSlice() });
        const default: u16 = switch (self.scheme) {
            .http => default_http_port,
            .https => default_https_port,
        };
        if (self.port != default) try writer.print(":{d}", .{self.port});
        try writer.writeAll("/");
    }

    pub fn order(self: RelayUrl, other: RelayUrl) std.math.Order {
        if (self.scheme != other.scheme) {
            return std.math.order(@intFromEnum(self.scheme), @intFromEnum(other.scheme));
        }
        if (self.port != other.port) return std.math.order(self.port, other.port);
        return std.mem.order(u8, self.hostSlice(), other.hostSlice());
    }
};

pub const custom_id_length = 8;
pub const max_inline_length = 30;

pub const CustomAddrParseError = error{
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
    id: u64,
    data: []const u8,

    /// Binary form: little-endian u64 id, then raw data. Eight bytes minimum.
    /// The result borrows `bytes`; keep them alive for as long as it is read.
    pub fn parseBinary(bytes: []const u8) CustomAddrParseError!CustomAddr {
        if (bytes.len < custom_id_length) return error.Malformed;
        if (bytes.len - custom_id_length > max_inline_length) return error.DataTooLong;
        const id = std.mem.readInt(u64, bytes[0..custom_id_length], .little);
        return .{ .id = id, .data = bytes[custom_id_length..] };
    }

    /// Write the binary form into `out`, which must be
    /// `custom_id_length + self.data.len` long.
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

    pub fn format(self: CustomAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}_", .{self.id});
        for (self.data) |byte| try writer.print("{x:0>2}", .{byte});
    }

    pub fn order(self: CustomAddr, other: CustomAddr) std.math.Order {
        if (self.id != other.id) return std.math.order(self.id, other.id);
        return std.mem.order(u8, self.data, other.data);
    }
};

/// One way to reach a node.
pub const TransportAddr = union(enum) {
    /// A relay server that will forward datagrams for us.
    relay: RelayUrl,
    /// A directly reachable IP socket.
    ip: SocketAddr,
    /// A registered non-IP transport.
    custom: CustomAddr,

    pub fn order(self: TransportAddr, other: TransportAddr) std.math.Order {
        const self_tag = std.meta.activeTag(self);
        const other_tag = std.meta.activeTag(other);
        if (self_tag != other_tag) {
            return std.math.order(@intFromEnum(self_tag), @intFromEnum(other_tag));
        }
        return switch (self) {
            .relay => |url| url.order(other.relay),
            .ip => |addr| addr.order(other.ip),
            .custom => |addr| addr.order(other.custom),
        };
    }

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
pub const NodeAddr = struct {
    node_id: NodeId,
    /// Sorted by `TransportAddr.order`, unique. Mutate only through `insert`.
    addrs: []TransportAddr,

    pub fn init(node_id: NodeId) NodeAddr {
        return .{ .node_id = node_id, .addrs = &.{} };
    }

    /// Insert keeping the slice sorted and unique. Returns false, unchanged, when
    /// the address was already present.
    pub fn insert(
        self: NodeAddr,
        alloc: std.mem.Allocator,
        addr: TransportAddr,
    ) std.mem.Allocator.Error!?NodeAddr {
        const at = std.sort.lowerBound(TransportAddr, self.addrs, addr, orderTransport);
        if (at < self.addrs.len and self.addrs[at].order(addr) == .eq) return null;
        const grown = try alloc.realloc(self.addrs, self.addrs.len + 1);
        // `copyBackwards`, not `copyForwards`: the destination starts one
        // element *after* the source, so each write lands on the element the
        // next step still has to read. `copyForwards` is the forward loop
        // (`lib/std/mem.zig`, `for (dest[0..source.len], source) |*d, s| d.* = s;`)
        // and is only correct when the destination is at or before the source.
        std.mem.copyBackwards(TransportAddr, grown[at + 1 ..], grown[at..self.addrs.len]);
        grown[at] = addr;
        return .{ .node_id = self.node_id, .addrs = grown };
    }

    pub fn withRelay(
        alloc: std.mem.Allocator,
        node_id: NodeId,
        url: RelayUrl,
    ) std.mem.Allocator.Error!NodeAddr {
        const one = try alloc.dupe(TransportAddr, &.{.{ .relay = url }});
        return .{ .node_id = node_id, .addrs = one };
    }

    pub fn deinit(self: NodeAddr, alloc: std.mem.Allocator) void {
        alloc.free(self.addrs);
    }

    pub fn relayCount(self: NodeAddr) usize {
        var count: usize = 0;
        for (self.addrs) |addr| {
            if (addr == .relay) count += 1;
        }
        return count;
    }

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

test "relay url rejects what is not a relay" {
    try t.expectError(error.Malformed, RelayUrl.parse("not a url"));
    try t.expectError(error.UnsupportedScheme, RelayUrl.parse("ftp://example.com./"));
    try t.expectError(error.UnexpectedComponent, RelayUrl.parse("https://example.com./relay"));
    try t.expectError(error.UnexpectedComponent, RelayUrl.parse("https://example.com./?x=1"));
    try t.expectError(error.HostTooLong, RelayUrl.parse("https://" ++ ("a" ** 254) ++ "./"));
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
    try t.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &(IpAddress.parse("127.0.0.1").?.v4));
    try t.expect(IpAddress.parse("::1") != null);
    try t.expectEqual(@as(?IpAddress, null), IpAddress.parse("127.0.0.256"));
    try t.expectEqual(@as(?IpAddress, null), IpAddress.parse("example.com"));
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
    const node_id = (try key.SecretKey.fromSeed([_]u8{2} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;
    var storage: [max_inline_length]u8 = undefined;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);

    addr = (try addr.insert(alloc, .{ .custom = try CustomAddr.parse("2a_abab", &storage) })).?;
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
    const ip: TransportAddr = .{ .ip = .{ .ip = IpAddress.parse("0.0.0.0").?, .port = 1 } };
    const custom: TransportAddr = .{ .custom = .{ .id = 0, .data = &.{} } };

    try t.expectEqual(std.math.Order.lt, relay.order(ip));
    try t.expectEqual(std.math.Order.lt, ip.order(custom));
    try t.expectEqual(std.math.Order.eq, relay.order(relay));
}

test "node addr keeps its address list sorted and unique" {
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);
    try t.expectEqual(@as(usize, 1), addr.addrs.len);

    addr = (try addr.insert(alloc, .{
        .ip = .{ .ip = IpAddress.parse("10.0.0.1").?, .port = 9 },
    })).?;
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // The duplicate must be rejected, and must not have grown the slice.
    try t.expectEqual(@as(?NodeAddr, null), try addr.insert(alloc, .{
        .ip = .{ .ip = IpAddress.parse("10.0.0.1").?, .port = 9 },
    }));
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // Relay sorts before ip by variant, so it stays at index 0.
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(addr.addrs[0]));
    try t.expectEqual(@as(usize, 1), addr.relayCount());

    var index: usize = 1;
    while (index < addr.addrs.len) : (index += 1) {
        try t.expectEqual(std.math.Order.lt, addr.addrs[index - 1].order(addr.addrs[index]));
    }
}
