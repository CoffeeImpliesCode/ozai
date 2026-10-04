//! The values a command-line argument spells, one function per spelling.
//!
//! Pure over bytes. Each function below takes one flag's value and returns the
//! typed value it names, or the refusal for a value that names nothing. No flag
//! is known here, no usage is printed and no combination is checked — that is
//! `cli.zig` — so each of these is on its own the grammar for one `<...>` in
//! the usage text.
//!
//! The types returned are the ones the program hands to `node_lifecycle.create`, so
//! nothing is converted between a command line and the node it asks for: the
//! `Peer` here is `node_config.Peer`, and the datagram ceiling below is the one the
//! node itself refuses over.

const std = @import("std");
const ozai = @import("ozai");

/// What a value that names nothing is refused with.
///
/// `base32`'s and `key`'s refusals are included rather than restated, for the
/// reason `hyparview.zig` gives for the same shape: a varint that does not end
/// and a node id that is not on the curve are both refusals a caller can
/// provoke, and they read better as the seam's own names. `cli.Error` adds the
/// ones that are about a command line rather than about a single value.
pub const ValueError = ozai.base32.DecodeError || ozai.KeyError ||
    ozai.relay_url.RelayUrlParseError || ozai.relay_url.RelayUrlResolveError || error{
    /// An address with no port, a port that is not a number, or a host that is
    /// neither a v4 nor a v6 literal.
    AddressNotReachable,
    /// A peer flag with no `@`, or an address after it that is not one.
    PeerWithoutAddress,
    PeerAddressUnreachable,
    /// A relay flag with no `@`, so no node id beside the URL. The id is what
    /// a client presents to the relay and the URL is where it is: one without
    /// the other names nothing.
    RelayWithoutId,
    /// `--send` with no payload after the node id, or with a colon and nothing
    /// behind it. A datagram of no bytes is a flag that said nothing.
    SendWithoutBytes,
    /// `--send` with a payload longer than `node_config.max_datagram`. A relay
    /// forwards datagrams and that is the length of one, so a longer one is a
    /// flag asking for something this program will not send.
    SendTooLong,
};

/// A relay this process reaches for, in the two spellings that matter: the URL
/// a caller named it by, and the peer that URL resolved to.
///
/// Both are kept because they answer different questions and only one of them
/// is what the dial was told. The URL is the whole of what a peer holds;
/// `peer` is what `RelayUrl.socketAddr` made of it. A command line that named
/// one relay and reached another is invisible if only one of the two is
/// printed, so the banner says the first and the report says the second.
///
/// `url` borrows the argument bytes it was cut from.
pub const RelayPeer = struct {
    url: []const u8,
    peer: ozai.node_config.Peer,
};

/// One datagram to put on the relay wire, and the peer it is for.
///
/// `bytes` borrows the argument bytes it was cut from: the payload is the
/// command line's own bytes rather than a decoded form of them, because a
/// datagram is opaque and a program that cannot spell one cannot send one.
pub const Send = struct {
    peer: ozai.NodeId,
    bytes: []const u8,
};

/// `<nodeid>@<relay-url>`: who a relay is, and where it is, in the spelling a
/// peer is handed one.
///
/// **The URL is the whole of what a peer holds about a relay**, so it is
/// resolved here rather than handed over as a socket: `RelayUrl.socketAddr` is
/// the step, and it refuses a host that is a name outright because nothing in
/// this program resolves one. That refusal is this program's answer on a line,
/// for the reason every other bad value here is.
pub fn relayPeer(text: []const u8) ValueError!RelayPeer {
    const at = std.mem.indexOfScalar(u8, text, '@') orelse
        return error.RelayWithoutId;
    const url = text[at + 1 ..];
    // The URL's own refusals and the step that turns it into an address both
    // keep the names the seam gives them: see `ValueError`.
    const parsed = try ozai.RelayUrl.parse(url);
    return .{
        .url = url,
        .peer = .{
            .id = try ozai.NodeId.parseZ32(text[0..at]),
            .addr = .{ .ip = try parsed.socketAddr() },
        },
    };
}

/// `<nodeid>:<bytes>`: one datagram, and the peer it is for.
///
/// A node id is z-base-32 and carries no colon, so the first one separates the
/// two and everything behind it is the payload — colons included, which is why
/// this splits on the first and not the last.
pub fn send(text: []const u8) ValueError!Send {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse
        return error.SendWithoutBytes;
    if (colon + 1 == text.len) return error.SendWithoutBytes;
    const bytes = text[colon + 1 ..];
    // Refused here rather than becoming a `DatagramTooLarge` out of
    // `sendThrough` on a pass of the loop: same mistake, and only one of them
    // is a line.
    if (bytes.len > ozai.node_config.max_datagram) return error.SendTooLong;
    return .{ .peer = try ozai.NodeId.parseZ32(text[0..colon]), .bytes = bytes };
}

/// `ip:port`, with an IPv6 literal written in brackets.
pub fn socket(text: []const u8) ValueError!ozai.SocketAddr {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
        return error.AddressNotReachable;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
        return error.AddressNotReachable;
    var host = text[0..colon];
    if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]")) {
        host = host[1 .. host.len - 1];
    }
    return .{
        .ip = ozai.IpAddress.parse(host) orelse return error.AddressNotReachable,
        .port = port,
    };
}

/// `nodeid@ip:port`: a z-base-32 node id, and where to reach it.
///
/// The two halves keep their own refusals: a node id that is not on the curve
/// and an address with no port are different mistakes, and one name for both
/// would leave the caller guessing which one it typed.
pub fn peer(text: []const u8) ValueError!ozai.node_config.Peer {
    const at = std.mem.indexOfScalar(u8, text, '@') orelse return error.PeerWithoutAddress;
    const address = socket(text[at + 1 ..]) catch return error.PeerAddressUnreachable;
    return .{ .id = try ozai.NodeId.parseZ32(text[0..at]), .addr = .{ .ip = address } };
}
