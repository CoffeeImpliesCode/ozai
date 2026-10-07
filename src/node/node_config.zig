//! Borrowed application configuration and construction-time validation.

const std = @import("std");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const node_blobs = @import("node_blobs.zig");
const node_relay_runtime = @import("node_relay_runtime.zig");
const addr_map = @import("../transport/addr_map.zig");
const node_native = @import("node_native.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const node_discovery = @import("node_discovery.zig");

pub const gossip_alpn = "/iroh-gossip/1";
pub const blobs_alpn = "/iroh-bytes/4";
pub const max_gossip_topics = 4;

pub const Traversal = struct {
    local_candidates: []const SocketAddr = &.{},
    initiate: bool = false,
};

/// Every allocation goes through a handle the caller handed in: nothing here
/// reaches for a global allocator, which is what `AGENTS.md` §1 asks for by
/// name and what `DECISIONS/0002` buys for every layer above the transport.
pub const Allocator = std.mem.Allocator;

/// One peer this node dials when it starts.
pub const Peer = struct {
    /// Who it is. This is the dialer's pin, and it is the key any synthetic
    /// address for the peer is allocated under, because on a dial the node
    /// being dialled and the node whose key must be presented are the same
    /// fact (`Dialer.dial`'s own doc).
    id: NodeId,
    /// Where to reach it. A direct socket address, a relay, or a registered
    /// non-IP transport: the three ways `base/addr.zig` models reaching a
    /// node, and the three `Dialer.dial` takes.
    addr: base_addr.TransportAddr,
};

/// What a node is told to be, in this project's own vocabulary.
///
/// Every field is a value this project already has. Nothing here is the
/// vendored core's spelling, and `create` is the one place the two are
/// translated.
pub const Config = struct {
    /// This node's identity: the seed the presented certificate is built from
    /// and the id a peer compares it against.
    secret: SecretKey,
    /// Optional pin applied to every accepted inner connection.
    expect_peer: ?NodeId = null,
    /// Where the socket binds. Port zero means the kernel chooses, which is
    /// what makes two nodes in one process both bind.
    listen: SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    },
    /// Who to dial when the node starts. One dial each, at start, and an
    /// attempt is recorded whether it succeeded or not: a peer that was not
    /// listening yet is not dialled again, because the retry policy belongs
    /// with discovery (`src/discovery/dial_source.zig` is the module that
    /// names a lookup as its own missing half).
    ///
    /// A relay target must match the single configured plaintext carrier.
    /// Missing or mismatched carriers fail `start` before the attempt is recorded.
    /// Gossip bootstrap size is checked by `start`, after explicit peer dials.
    peers: []const Peer = &.{},
    /// The protocol to offer and to dispatch. See `max_alpns`.
    alpn: []const u8 = gossip_alpn,
    /// Applied before connection allocation, after core token validation.
    initial_policy: ?incoming_filter.InitialPolicy = null,
    /// Explicit subscriptions; identities and callback/message storage outlive the node.
    gossip_topics: []const hyparview.TopicId = &.{},
    on_gossip: ?*const fn (?*anyopaque, hyparview.TopicId, NodeId, []const u8) void = null,
    on_gossip_context: ?*anyopaque = null,
    gossip_message: ?[]const u8 = null,
    topic: hyparview.TopicConfig = .{},
    blobs: node_blobs.Config = .disabled,
    /// Carrier lifetime is independent of the inner application ALPN.
    /// Only HTTP relay URLs matching the client's Host authority and socket port
    /// are admitted. HTTPS is not implemented by the plaintext TCP carrier.
    relay: node_relay_runtime.Config = .{},
    address_discovery_role: @FieldType(bridge_mod.Config, "address_discovery_role") = .disabled,
    max_remote_nat_traversal_addresses: ?u8 = null,
    initial_max_path_id: ?u32 = null,
    traversal: Traversal = .{},
    /// What this node does about being found, and about finding one peer.
    ///
    /// **`Discovery{}` — the default — publishes nothing and looks nobody
    /// up.** `discovery/preset.zig`'s `Publication.relay_only` is this
    /// project's default and it is kept: the node is reachable through the
    /// relays it already dials and hands no address to a third party. A
    /// caller that wants a pkarr packet names `discovery.relay`; a caller that
    /// wants its peers resolved names `discovery.lookup`.
    ///
    /// **Borrowed, and the same rule as `peers` above**: every slice and every
    /// pointer below must outlive the node, not merely the call. `relay`'s
    /// three buffers and its trust bundle are the caller's storage by
    /// `pkarr_live.Options`' own doc ("the two `[]u8` fields are the caller's
    /// storage and are not copied"), and `lookup.datagram` borrows whatever
    /// `dns_live.Resolver` it came from.
    discovery: node_discovery.Config = .{},
};

/// What one node publishes about itself and where, in this project's vocabulary.
///
/// A group of its own rather than six more fields on `Config`, because every
/// one of them is an I/O dependency the caller owns and a node without any of
/// them is a node that publishes nothing and looks nobody up — the default, and
/// `discovery/preset.zig`'s own answer for a node holding only a relay map.
pub const Discovery = node_discovery.Config;

/// A pkarr relay this node publishes to and resolves from, and the trust that
/// goes with it. See `node_discovery.Config.relay`.
///
/// **Every field is the caller's storage and outlives the node.** The two TLS
/// scratch buffers are `tls_client.buffer_length` bytes each
/// (`pkarr_live.Options`' own rule: "must each be `tls_client.buffer_length`
/// bytes or more"), `response` is `pkarr_live.max_header_length +
/// pkarr_live.max_body_length` bytes or more because the response borrows it,
/// and `bundle` is a `std.crypto.Certificate.Bundle` the caller rescanned
/// with `std.crypto.Certificate.Bundle.rescan`. A node that trusts nothing
/// leaves this null and publishes nothing,
/// which is `Publication.relay_only` reached a second way.
pub const DiscoveryRelay = struct {
    /// The relay's base URL, as `discovery/preset.zig` spells it:
    /// `https://dns.iroh.link/pkarr`. Borrowed text.
    base_url: []const u8,
    /// The address the relay was resolved to, by value. A `SocketAddr` and not
    /// a name, because `base/relay.zig`'s `RelayUrl.socketAddr` refuses a name
    /// and this tree does not resolve hostnames inside a relay client.
    server: SocketAddr,
    /// The name the relay's certificate must carry. `pkarr_live.exchange`
    /// reads the host out of `base_url` itself and never looks here; the field
    /// exists because `tls_client.Options.host` has no default and no
    /// `no_verification` alternative, so something has to be named.
    certificate_host: []const u8,
    /// The trust anchors, and the lock they are read under. Both borrowed, and
    /// both must outlive every publish this node makes.
    bundle: *std.crypto.Certificate.Bundle,
    bundle_lock: *std.Io.RwLock,
    /// The relay's read scratch, `tls_client.buffer_length` bytes or more.
    read_buffer: []u8,
    /// The relay's write scratch, same bound.
    write_buffer: []u8,
    /// Where a whole response is read, `pkarr_live.max_header_length +
    /// pkarr_live.max_body_length` bytes or more. The response borrows this, so
    /// it must be storage that outlives the call rather than a temporary.
    response: []u8,
    /// How long a connect and each read and write wait. Null is
    /// `pkarr_live.default_timeout_ms`, and it is that module's decision.
    timeout_ms: ?i32 = null,
};

/// What this module refuses.
///
/// Everything is a set a seam below already published, so a caller of `step`
/// writes the same error name the seam's own tests write. The two arms that
/// are this module's own are named for what they are.
///
/// One of these arrives only from a `std.Io` that has refused, and it says
/// which refusal: `error.Canceled` is this module or a seam below asking the
/// caller's runtime for cancellation and being told to stop — `Bridge.create`
/// drawing the two transport secrets, and `Socket` around any `recvmsg` or
/// `sendmsg` — while `error.EntropyUnavailable` is that
/// same `Io` saying it cannot produce secure entropy at all. A cancelled
/// runtime is still a runtime; a caller that retries `create` on another `Io`
/// has not learned anything it did not already know.
pub const Error =
    bridge_mod.Error ||
    bridge_mod.CreateError ||
    dial_mod.Error ||
    socket_mod.OpenError ||
    socket_mod.SendError ||
    socket_mod.ReceiveError ||
    router.AcceptError ||
    router.RegisterError ||
    node_blobs.Error ||
    node_relay_runtime.Error ||
    addr_map.GetError ||
    node_native.NativeError ||
    hyparview.Error ||
    plumtree.Error ||
    Allocator.Error ||
    error{
        InvalidDiscoveryConfig,
        /// The `Io`'s monotonic clock reported a value `Instant` — a signed
        /// 64-bit nanosecond count — cannot hold. Unreachable on any machine
        /// this runs on, and refused rather than `@intCast`ed so a clock that
        /// is not what it claims is a named answer instead of a panic.
        InstantOutOfRange,
        TooManyGossipTopics,
        DuplicateGossipTopic,
        UnknownGossipTopic,
        InvalidGossipAlpn,
        InvalidBlobAlpn,
        RelayIdentityMismatch,
        RelayIngressLimit,
        InvalidTraversalConfig,
        UnexpectedRelayPeer,
    };

test "gossip subscriptions reject duplicate identities and more than four topics" {
    const secret = try SecretKey.fromSeed(@splat(7));
    const topics = [_]hyparview.TopicId{
        .fromBytes(@splat(1)), .fromBytes(@splat(2)), .fromBytes(@splat(3)),
        .fromBytes(@splat(4)), .fromBytes(@splat(5)),
    };
    try std.testing.expectError(error.TooManyGossipTopics, validate(.{
        .secret = secret,
        .gossip_topics = &topics,
    }));
    const repeated = [_]hyparview.TopicId{ .fromBytes(@splat(1)), .fromBytes(@splat(1)) };
    try std.testing.expectError(error.DuplicateGossipTopic, validate(.{
        .secret = secret,
        .gossip_topics = &repeated,
    }));
}

test "blob transfer configuration requires its application protocol" {
    const secret = try SecretKey.fromSeed(@splat(8));
    try std.testing.expectError(error.InvalidBlobAlpn, validate(.{
        .secret = secret,
        .blobs = .{ .getter = .{ .hash = @splat(0) } },
    }));
}

test "carrier identity must be the inner endpoint identity" {
    try std.testing.expectError(error.RelayIdentityMismatch, validate(.{
        .secret = try SecretKey.fromSeed(@splat(9)),
        .relay = .{ .client = .{
            .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 },
            .host = "localhost",
            .secret = try SecretKey.fromSeed(@splat(10)),
            .execution = .native,
        } },
    }));
}

test "native traversal cannot initiate without candidates or negotiate nonexistent path slots" {
    const secret = try SecretKey.fromSeed(@splat(11));
    try std.testing.expectError(error.InvalidTraversalConfig, validate(.{
        .secret = secret,
        .traversal = .{ .initiate = true },
        .max_remote_nat_traversal_addresses = 2,
        .initial_max_path_id = 1,
    }));
    try std.testing.expectError(error.InvalidTraversalConfig, validate(.{
        .secret = secret,
        .initial_max_path_id = 2,
    }));
}

pub fn validate(config: Config) Error!void {
    if (config.traversal.local_candidates.len > 32) return error.InvalidTraversalConfig;
    if (config.initial_max_path_id) |maximum| {
        if (maximum > 1) return error.InvalidTraversalConfig;
    }
    if (config.max_remote_nat_traversal_addresses) |maximum| {
        if (maximum == 0 or maximum > 32) return error.InvalidTraversalConfig;
    }
    if (config.traversal.initiate and config.traversal.local_candidates.len == 0) {
        return error.InvalidTraversalConfig;
    }
    if (config.traversal.local_candidates.len != 0 and
        (config.max_remote_nat_traversal_addresses == null or
            config.initial_max_path_id == null))
    {
        return error.InvalidTraversalConfig;
    }
    if (config.gossip_topics.len > max_gossip_topics) return error.TooManyGossipTopics;
    for (config.gossip_topics, 0..) |topic_id, index| {
        for (config.gossip_topics[0..index]) |previous| {
            if (topic_id.eql(previous)) return error.DuplicateGossipTopic;
        }
    }
    if (config.gossip_topics.len != 0 and !std.mem.eql(u8, config.alpn, gossip_alpn)) {
        return error.InvalidGossipAlpn;
    }
    if (config.blobs != .disabled and !std.mem.eql(u8, config.alpn, blobs_alpn)) {
        return error.InvalidBlobAlpn;
    }
    if (config.relay.client) |client| {
        if (client.secret.nodeId().order(config.secret.nodeId()) != .eq) {
            return error.RelayIdentityMismatch;
        }
    }
}
