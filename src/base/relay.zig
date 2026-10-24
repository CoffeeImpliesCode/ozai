//! The three address forms a peer is reached at, and the rules that make two
//! spellings of one of them the same value.
//!
//! An IP literal, a socket and a relay URL are what a connection is named by,
//! and `base/addr.zig` names none of them by any other name. They are here
//! because they share the one rule that makes an address comparable at all: a
//! total order over their values, with `RelayUrl`'s scheme and port ahead of
//! its host and `SocketAddr`'s bytes ahead of its port. Sorting an address
//! list is what makes the same node produce the same bytes in a ticket, so the
//! order is part of the wire format and not a convenience.
//!
//! `RelayUrl` is the form that has to be parsed rather than read, and it is the
//! bulk of this file: `std.Uri` hands back the host with its brackets still on
//! it, a host with no port takes a default that depends on the scheme, and a
//! literal behind brackets is an address rather than a name. `IpAddress` and
//! `SocketAddr` are the two forms a relay URL resolves *to*, which is why
//! `RelayUrl.socketAddr` is the only function here that can fail on a host.
//!
//! Nothing in this file allocates or reads a clock. Every value is a fixed-size
//! struct over borrowed bytes or a slice the caller owns.

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
        const uri = std.Uri.parse(text) catch |err| switch (err) {
            error.InvalidHostName => return error.HostTooLong,
            else => return error.Malformed,
        };
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
            return std.math.order(@backingInt(self.scheme), @backingInt(other.scheme));
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
