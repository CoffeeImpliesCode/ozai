//! Relay server addresses: one owned URL value, its two refusals, and the one
//! step from a URL to the socket a dial reaches.
//!
//! A `RelayUrl` is a fixed-size value that borrows nothing, so it can be
//! stored in a set, put on the wire and handed across threads. It is not a
//! node address: `node_addr.zig` is what pairs one with a node id, and
//! `transport_addr.zig` is what lists it beside the other ways to reach a node.
//! The only foreign types here are the primitives `socketAddr` hands back.

const std = @import("std");
const addr = @import("addr.zig");

const IpAddress = addr.IpAddress;
const SocketAddr = addr.SocketAddr;

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
    pub const default_http_port = 80;
    pub const default_https_port = 443;

    /// `http` or `https`, and nothing else: `parse` refuses every other
    /// scheme. The declaration order is also the sort order, so `http` is the
    /// lower of the two.
    pub const Scheme = enum { http, https };

    /// Which of the two defaults the port came from when the text gave none.
    scheme: Scheme,
    /// The host starts at index zero in a fixed array. Only `host[0..host_length]`
    /// is part of the value; the rest is unspecified padding and two `RelayUrl`
    /// values parsed from the same text may differ there. Compare with `order`
    /// or `hostSlice`, never field by field — `host` as a whole array is not
    /// the host, and a `RelayUrl` built by hand may leave the tail as it
    /// found it.
    host: [max_host_length]u8,
    /// Bytes of `host` in use, in 1..=max_host_length. `parse` enforces this
    /// range; a public literal or field write does not. `hostSlice` assumes
    /// it, so a value above the array bound is a programmer error.
    host_length: u8,
    /// A nonzero relay port. `parse` enforces this precondition; public literals
    /// and field mutation do not. Unlike a local `SocketAddr` bind, zero is not
    /// a valid relay destination. `format` prints a literal zero as `:0`, but
    /// parsing that spelling refuses it. Use `parse` for untrusted URLs.
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

const t = std.testing;

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
