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

/// Everything a relay URL's text can be refused for.
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

/// Why a relay URL could not be turned into something a dial can use.
pub const RelayUrlResolveError = error{
    /// The host is a name and not an IP literal.
    ///
    /// **Not `Malformed`, and it must not grow into it.** The URL is a
    /// perfectly good relay address; what is missing is a name lookup, and
    /// name lookup belongs to `src/discovery/`, which owns the endpoint
    /// lookups and a `net/probe.zig` that decides which relays to ask — and
    /// not a host resolver, for the reason `socketAddr` gives. `base` has no
    /// `Io`, no allocator and no clock, so it cannot do one and would be
    /// wrong to pretend otherwise. "This is a name" and "this is not an
    /// address" are different facts and they stay different facts.
    NotAnIpLiteral,
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
    /// The port `parse` fills in when the text carries none.
    pub const default_http_port = 80;
    /// The port `parse` fills in when the text carries none.
    pub const default_https_port = 443;

    /// `http` or `https`, and nothing else: `parse` refuses every other
    /// scheme. The declaration order is also the sort order, so `http` is the
    /// lower of the two.
    pub const Scheme = enum { http, https };

    /// Which of the two defaults the port came from when the text gave none.
    scheme: Scheme,
    /// The host, left-padded into a fixed array. Only `host[0..host_length]`
    /// is part of the value; the rest is unspecified padding and two `RelayUrl`
    /// values parsed from the same text may differ there. Compare with `order`
    /// or `hostSlice`, never field by field — `host` as a whole array is not
    /// the host, and a `RelayUrl` built by hand may leave the tail as it
    /// found it.
    host: [max_host_length]u8,
    /// How many bytes of `host` the host occupies. Zero is never a valid
    /// value of this field: `parse` refuses an empty host.
    host_length: u8,
    /// The port. Zero is `error.InvalidPort`, so unlike `SocketAddr.port`
    /// every value of this field names a connectable port.
    port: u16,

    /// The relay URL `text` names, with the scheme's default port filled in
    /// when the text carries none. A path of `/` or none at all is accepted;
    /// anything else, a query or a fragment is `UnexpectedComponent`.
    ///
    /// The host keeps the bytes `text` carried, brackets included for an IPv6
    /// literal, and the padding past `host_length` is left unspecified; see
    /// the `host` field.
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

    /// Scheme, then port, then the host's own bytes. The padding past
    /// `host_length` is not compared, so this is the equality two relay URLs
    /// have as addresses: a field-wise comparison of `host` would disagree
    /// with it.
    pub fn order(self: RelayUrl, other: RelayUrl) std.math.Order {
        if (self.scheme != other.scheme) {
            return std.math.order(@intFromEnum(self.scheme), @intFromEnum(other.scheme));
        }
        if (self.port != other.port) return std.math.order(self.port, other.port);
        return std.mem.order(u8, self.hostSlice(), other.hostSlice());
    }

    /// The socket a dial reaches this relay on, when the host is an IP
    /// literal.
    ///
    /// Upstream does the same thing with the same refusal: `derp` opens its
    /// QUIC connection to `url.host` and parses it as a `SocketAddr`
    /// outright, so a derp URL whose host is a name is not usable by the
    /// client at all. A `RelayUrl` names a relay's *address*, and a dial
    /// needs a `SocketAddr`; this is the whole of the step between them.
    ///
    /// **A name is refused rather than resolved.** `src/discovery/` owns the
    /// endpoint lookups and nothing in `src/` turns a host into an address:
    /// `dns.zig` builds the `_iroh.<z32>.<origin>` TXT query and there is no
    /// A/AAAA path. Its socket seam is real — `discovery/lookup_live.zig`
    /// runs a query on `transport/socket.zig` — and it carries those questions
    /// rather than host lookups, so the half that needs a host resolver stays
    /// open instead of being papered over with a system resolver this module
    /// must not have.
    ///
    /// The port is the URL's, which `parse` has already defaulted from the
    /// scheme, and the scheme itself is not consulted: a relay is reached at
    /// its port either way, and `https`'s default is a port and not a
    /// transport decision this value can make.
    ///
    /// **An IPv6 host keeps its brackets here and they come off now.** RFC
    /// 3986 writes an IP literal as `[addr]` and `std.Uri` hands `parse` the
    /// host with both brackets still on it. They are URL syntax and not part
    /// of the address, so `[::1]` is the literal `::1` and not a name;
    /// calling it a name would drop an address the dial already holds.
    /// `hostSlice` keeps the brackets because a relay URL printed without them
    /// would not be the URL it was parsed from.
    pub fn socketAddr(self: *const RelayUrl) RelayUrlResolveError!SocketAddr {
        const host = self.hostSlice();
        const address = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
            host[1 .. host.len - 1]
        else
            host;
        const ip = IpAddress.parse(address) orelse return error.NotAnIpLiteral;
        return .{ .ip = ip, .port = self.port };
    }
};

/// The id's width in the binary form: a little-endian `u64`.
pub const custom_id_length = 8;
/// The most payload bytes a `CustomAddr` carries inline, and the ceiling a
/// decoded ticket holds one to.
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
    /// `custom_id_length + self.data.len` long. A buffer of any other length
    /// is a caller error the assertion catches; nothing is written and no
    /// error is returned, because there is no partial form to return.
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
            return std.math.order(@intFromEnum(self_tag), @intFromEnum(other_tag));
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
/// **The list is all a `NodeAddr` owns.** One allocation, made by `withRelay`,
/// `init` or `insert` and released by exactly one `deinit`. A `.custom`
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
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
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
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
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
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
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
