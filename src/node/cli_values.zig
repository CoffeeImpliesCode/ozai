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

const NodeId = ozai.NodeId;

pub const BlobHash = @TypeOf(@as(ozai.blobs_protocol.GetRequest, undefined).hash);
pub const CliError = ozai.base32.DecodeError || ozai.KeyError ||
    ozai.addr.RelayUrlParseError || error{
    NotAnOption,
    FlagWithoutValue,
    AddressNotReachable,
    PeerWithoutAddress,
    PeerAddressUnreachable,
    TwoRelayRoles,
    RelayNeedsHost,
    RelayNeedsServer,
    InvalidRelayHost,
    InvalidTopic,
    TooManyTopics,
    MessageNeedsTopic,
    TopicAlpnMismatch,
    ConflictingProtocols,
    InvalidBlobRole,
    InvalidBlobHash,
    InvalidBlobSize,
    InvalidBlobRange,
    BlobNeedsRole,
    BlobNeedsHash,
    BlobNeedsDirectory,
    BlobAlpnMismatch,
    BlobProviderGetterOptions,
    BlobGetterDirectory,
    EmptyPath,
    TraversalNeedsAddress,
    TooManyTraversalAddresses,
    NotASeed,
    NotMilliseconds,
    LookupNeedsServer,
    LookupNeedsPeer,
    LookupTimingOutOfRange,
    InvalidDnsOrigin,
    NoClock,
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

/// A pinned inner peer reached through a relay, not the relay's identity.
pub fn parseRelayPeer(text: []const u8) CliError!ozai.node.Peer {
    const at = std.mem.indexOfScalar(u8, text, '@') orelse
        return error.PeerWithoutAddress;
    return .{
        .id = try NodeId.parseZ32(text[0..at]),
        .addr = .{ .relay = try ozai.RelayUrl.parse(text[at + 1 ..]) },
    };
}

pub fn parseTopic(text: []const u8) CliError!ozai.gossip_hyparview.TopicId {
    var bytes: [32]u8 = undefined;
    if (text.len != bytes.len * 2) return error.InvalidTopic;
    _ = std.fmt.hexToBytes(&bytes, text) catch return error.InvalidTopic;
    return .fromBytes(bytes);
}

pub fn parseBlobHash(text: []const u8) CliError!BlobHash {
    var hash: BlobHash = undefined;
    if (text.len != hash.len * 2) return error.InvalidBlobHash;
    _ = std.fmt.hexToBytes(&hash, text) catch return error.InvalidBlobHash;
    return hash;
}

/// Null means all chunks; finite ranges are end-exclusive protocol values.
pub fn parseBlobRange(text: []const u8) CliError!?ozai.blobs_protocol.ChunkRange {
    if (std.mem.eql(u8, text, "all")) return null;
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse
        return error.InvalidBlobRange;
    const start = std.fmt.parseInt(u64, text[0..colon], 10) catch
        return error.InvalidBlobRange;
    const end = std.fmt.parseInt(u64, text[colon + 1 ..], 10) catch
        return error.InvalidBlobRange;
    if (start >= end) return error.InvalidBlobRange;
    return .{ .start = start, .end = end };
}

/// `ip:port`, with an IPv6 literal written in brackets.
pub fn parseSocket(text_in: []const u8) CliError!ozai.SocketAddr {
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
pub fn parsePeer(text_in: []const u8) CliError!ozai.node.Peer {
    const at = std.mem.indexOfScalar(u8, text_in, '@') orelse return error.PeerWithoutAddress;
    const socket = parseSocket(text_in[at + 1 ..]) catch return error.PeerAddressUnreachable;
    return .{ .id = try NodeId.parseZ32(text_in[0..at]), .addr = .{ .ip = socket } };
}

/// Milliseconds bounded so conversion to monotonic nanoseconds cannot overflow.
pub const max_lookup_interval_ms: u64 = std.math.maxInt(i64) / std.time.ns_per_ms;

pub fn parseLookupMilliseconds(comptime T: type, text: []const u8, maximum: T) CliError!T {
    const value = std.fmt.parseInt(T, text, 10) catch return error.LookupTimingOutOfRange;
    if (value <= 0 or value > maximum) return error.LookupTimingOutOfRange;
    return value;
}

/// A DNS origin must leave room for `_iroh.<nodeid>` in a wire name.
pub fn parseDnsOrigin(text: []const u8) CliError![]const u8 {
    if (text.len == 0) return error.InvalidDnsOrigin;
    const name = if (text[text.len - 1] == '.') text[0 .. text.len - 1] else text;
    const prefix_length = "_iroh.".len + NodeId.z32_length + 1;
    if (name.len == 0 or name.len + prefix_length + 2 > 255) return error.InvalidDnsOrigin;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidDnsOrigin;
        for (label) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_')
                return error.InvalidDnsOrigin;
        }
    }
    return text;
}

test "lookup timing accepts exact bounds and rejects nonnumeric values" {
    try std.testing.expectEqual(
        @as(i32, 2147483647),
        try parseLookupMilliseconds(i32, "2147483647", std.math.maxInt(i32)),
    );
    try std.testing.expectEqual(
        max_lookup_interval_ms,
        try parseLookupMilliseconds(u64, "9223372036854", max_lookup_interval_ms),
    );
    try std.testing.expectError(
        error.LookupTimingOutOfRange,
        parseLookupMilliseconds(i32, "-1", std.math.maxInt(i32)),
    );
    try std.testing.expectError(
        error.LookupTimingOutOfRange,
        parseLookupMilliseconds(u64, "abc", max_lookup_interval_ms),
    );
}

test "DNS origins preserve absolute spelling and reject oversized labels" {
    try std.testing.expectEqualStrings("dns.iroh.link.", try parseDnsOrigin("dns.iroh.link."));
    try std.testing.expectEqualStrings("test.invalid", try parseDnsOrigin("test.invalid"));
    try std.testing.expectError(error.InvalidDnsOrigin, parseDnsOrigin(&@as([64:0]u8, @splat('a')) ++ ".invalid"));
    try std.testing.expectError(error.InvalidDnsOrigin, parseDnsOrigin("test..invalid"));
}
