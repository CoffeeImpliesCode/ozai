//! The values a flag carries, and the refusals they earn.
//!
//! Every bad value this program is handed is answered with a line and not a
//! stack trace — a program's own refusals are its interface — so each parser
//! here returns a named member of `CliError` and `reject` prints it. `CliError`
//! is the seam's own refusals plus this program's, kept in two rather than
//! restated in one, for the reason `gossip/hyparview.zig` gives for the same
//! shape.

const std = @import("std");

const ozai = @import("ozai");
const node_mod = ozai.node;

const NodeId = ozai.NodeId;
const SocketAddr = ozai.SocketAddr;
const Peer = node_mod.Peer;

/// What this program refuses, over and above the ones `Node` publishes.
///
/// The two that are its own are a value the caller wrote and a flag it does
/// not recognise, and both are answered with a line rather than a stack trace:
/// a program's own refusals are its interface.
/// `base32`'s and `key`'s refusals are included rather than restated, for the
/// reason `hyparview.zig` gives for the same shape: a varint that does not end
/// and a node id that is not on the curve are both refusals a caller can
/// provoke, and they read better as the seam's own names.
pub const CliError = ozai.base32.DecodeError || ozai.KeyError ||
    ozai.addr.RelayUrlParseError || ozai.addr.RelayUrlResolveError || error{
    /// A flag that is not one this program has.
    NotAnOption,
    /// A flag that takes a value, and the command line ended.
    FlagWithoutValue,
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
    /// `--send` with a payload longer than `Node.max_datagram`. A relay
    /// forwards datagrams and that is the length of one, so a longer one is a
    /// flag asking for something this program will not send.
    SendTooLong,
    /// Both relay roles at once. `node.Role` is a union, so this program runs
    /// one half of the relay handshake or the other.
    TwoRelayRoles,
    /// An ALPN beside a relay role. A relay node speaks the relay protocol
    /// because it cannot also gossip, so there is nothing here to choose.
    RelayChoosesTheAlpn,
    /// A peer list beside a relay role. A relay reaches peers through a relay
    /// rather than at their own addresses, so a dial list is a dial to a
    /// protocol that would not answer.
    RelayDialsNobody,
    /// `--send` on a node that is not a relay's client, which is the only node
    /// with a wire to put a datagram on.
    SendNeedsARelayClient,
    /// `--seed` was not a `u64`.
    NotASeed,
    /// `--for` was not a millisecond count.
    NotMilliseconds,
    /// The monotonic clock could not be read, or read a value `Instant` cannot
    /// hold.
    NoClock,
};

/// A relay this process reaches for, in the two spellings that matter: the URL
/// a caller named it by, and the peer that URL resolved to.
///
/// Both are kept because they answer different questions and only one of them
/// is what the dial was told. The URL is the whole of what a peer holds;
/// `peer` is what `RelayUrl.socketAddr` made of it. A command line that named
/// one relay and reached another is invisible if only one of the two is
/// printed, so the banner says the first and the report says the second.
pub const RelayPeer = struct {
    url: []const u8,
    peer: Peer,
};

/// One datagram to put on the relay wire, and the peer it is for.
pub const Send = struct {
    peer: NodeId,
    bytes: []const u8,
};

/// Say what was wrong with a value, and why, on one line.
///
/// The error is one of `CliError`'s and the only way this can fail is the
/// write, so both are named rather than inferred: a refusal whose type is
/// `anyerror` is a refusal that can be handed anything.
pub fn reject(
    out: *std.Io.Writer,
    flag: []const u8,
    value: []const u8,
    err: CliError,
) std.Io.Writer.Error!void {
    try out.print("ozai-node: {s} '{s}': {t}\n", .{ flag, value, err });
}

/// `<nodeid>@<relay-url>`: who a relay is, and where it is, in the spelling a
/// peer is handed one.
///
/// **The URL is the whole of what a peer holds about a relay**, so it is
/// resolved here rather than handed over as a socket: `RelayUrl.socketAddr` is
/// the step, and it refuses a host that is a name outright because nothing in
/// this program resolves one. That refusal is this program's answer on a line,
/// for the reason every other bad value here is.
pub fn parseRelayPeer(text_in: []const u8) CliError!RelayPeer {
    const at = std.mem.indexOfScalar(u8, text_in, '@') orelse
        return error.RelayWithoutId;
    const url = text_in[at + 1 ..];
    // The URL's own refusals and the step that turns it into an address both
    // keep the names the seam gives them: see `CliError`.
    const parsed = try ozai.RelayUrl.parse(url);
    return .{
        .url = url,
        .peer = .{
            .id = try NodeId.parseZ32(text_in[0..at]),
            .addr = .{ .ip = try parsed.socketAddr() },
        },
    };
}

/// `<nodeid>:<bytes>`: one datagram, and the peer it is for.
///
/// A node id is z-base-32 and carries no colon, so the first one separates the
/// two and everything behind it is the payload — colons included, which is why
/// this splits on the first and not the last. The payload is the command line's
/// own bytes rather than a decoded form of them: a datagram is an opaque
/// payload, and a program that cannot spell one cannot send one.
pub fn parseSend(text_in: []const u8) CliError!Send {
    const colon = std.mem.indexOfScalar(u8, text_in, ':') orelse
        return error.SendWithoutBytes;
    if (colon + 1 == text_in.len) return error.SendWithoutBytes;
    const bytes = text_in[colon + 1 ..];
    // A relay forwards datagrams and this is the length of one, so a longer
    // payload is refused here rather than becoming a `DatagramTooLarge` out of
    // `sendThrough` on a pass of the loop: same mistake, one line either way,
    // and only one of them is a line.
    if (bytes.len > node_mod.max_datagram) return error.SendTooLong;
    return .{ .peer = try NodeId.parseZ32(text_in[0..colon]), .bytes = bytes };
}

/// `ip:port`, with an IPv6 literal written in brackets.
pub fn parseSocket(text_in: []const u8) CliError!SocketAddr {
    const colon = std.mem.lastIndexOfScalar(u8, text_in, ':') orelse
        return error.AddressNotReachable;
    const port = std.fmt.parseInt(u16, text_in[colon + 1 ..], 10) catch
        return error.AddressNotReachable;
    var host = text_in[0..colon];
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
pub fn parsePeer(text_in: []const u8) CliError!Peer {
    const at = std.mem.indexOfScalar(u8, text_in, '@') orelse return error.PeerWithoutAddress;
    const socket = parseSocket(text_in[at + 1 ..]) catch return error.PeerAddressUnreachable;
    return .{ .id = try NodeId.parseZ32(text_in[0..at]), .addr = .{ .ip = socket } };
}
