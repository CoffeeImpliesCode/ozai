//! What a node is told to be, in this project's own vocabulary.
//!
//! `Config` is the only place a caller's spelling of a node is translated into
//! the seams below it, and `Error` is the union of everything those seams
//! refuse. Neither is written anywhere else: `transport/quic_bridge.zig` gives
//! the rule — "a translation nobody can read is a translation nobody can
//! check" — and a second place to translate from would be that rule broken.
//!
//! The relay's own vocabulary is here too — `Relay`, `Role`, `Serve` — because
//! a relay is what a node is configured to be and not a thing it is handed.

const std = @import("std");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_server = @import("../relay/server.zig");
const node_relay_table = @import("node_relay_table.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;

/// The bounds a `Relay` is sized by; they live with the storage they size.
const max_relay_clients = node_relay_table.max_relay_clients;
const default_relay_queue_depth = node_relay_table.default_relay_queue_depth;

/// The gossip protocol's ALPN, which is also the only protocol this node
/// speaks. `docs/PLAN.md` names it at M11.
pub const gossip_alpn = "/iroh-gossip/1";

/// The relay protocol's ALPN, which a node sets as its own when it is a relay
/// or a relay's client. See `node.zig`'s module doc, "The relay, and where
/// it sits in the loop", for why a relay node cannot also gossip.
pub const relay_alpn = "/iroh-relay/1";

/// How many clients a relay admits, how deep their queues are, and how far
/// this node will read and write one connection in a single pass.
///
/// A relay is sized by its operator, and every number here is one they set:
/// admitting more clients than `max_relay_clients` needs the tables `node.zig`
/// allocates to grow, which they are built not to.
pub const Relay = struct {
    /// Which half of the relay handshake this node runs. Upstream's relay is a
    /// process of its own and its client a library call, and the difference
    /// between them is exactly which half of one handshake a node runs.
    role: Role = .off,
};

/// Which half of the relay handshake a node runs, and against whom.
pub const Role = union(enum) {
    /// This node speaks gossip and nothing else, which is every node above
    /// this milestone and every node that is not one of the two below.
    off,
    /// This node admits clients and forwards datagrams between them.
    serve: Serve,
    /// This node dials this relay and speaks to it.
    client: Peer,
};

/// What a relay admits and how much room it gives them.
pub const Serve = struct {
    /// How many clients. `max_relay_clients` is what the tables `node.zig`
    /// allocates are sized for, and `create` refuses a larger one as
    /// `error.TooManyRelayClients` rather than growing them.
    ///
    /// **Fixed at construction.** `create` allocates `clients × queue_depth`
    /// of each queue type and one `queue_depth * max_datagram` datagram ring
    /// per client from these two numbers and reads them again nowhere else, so
    /// a later write changes nothing this node does — it cannot widen a relay
    /// that was built narrower. See `Node.config`.
    clients: usize = max_relay_clients,
    /// How many datagrams one client's queue holds. See
    /// `default_relay_queue_depth`, and `error.RelayQueueDepthZero` for the
    /// refusal `create` makes of zero.
    ///
    /// **This one is read on every pass, and it is the field that makes the
    /// pair construction-fixed rather than merely construction-sized.**
    /// `queueDepth` returns it, and `queuesOf` and `ringOf` re-cut every live
    /// client's two queues and its ring out of storage `initRelay` sized from
    /// the value this node was built with, once, in `create`. So a write to it
    /// after `create` re-points or overruns storage that was never resized: a
    /// larger depth indexes past the end of `packets` and `messages`, and a
    /// smaller one silently hands every live client another client's slots.
    queue_depth: usize = default_relay_queue_depth,
    /// How many queued messages one client may be given in one pass.
    ///
    /// A bound, and the reason the two queues can be seen to be two: a relay
    /// that wrote out everything one client had queued would let that client
    /// starve every other one, and a client this pass will not write for is
    /// exactly the client whose datagram queue fills.
    ///
    /// **This is the one field of the three that may be written after
    /// `create`.** `serve` reads it on every pass and hands it to
    /// `serveQueues`, and it sizes no storage, so a write changes how much one
    /// pass may write out and nothing else — the queues behind it were cut
    /// from `queue_depth`, not from this.
    drain_room: usize = 4,
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
    /// **A list longer than `hyparview.max_bootstrap` is refused, and refused
    /// after the dials rather than before them.** `start` walks this list
    /// first, so every peer in it is attempted and recorded in
    /// `Stats.dials` or `Stats.dials_refused`, and only then does the length
    /// check answer `error.BootstrapListTooLong` — which leaves the gossip
    /// layer unjoined and the node willing rather than latched, so the next
    /// `start` refuses the same way instead of reporting a join that never
    /// happened. `create` accepts any length and this bound is checked at
    /// `start` rather than at construction; the relay's sizing by contrast is
    /// refused by `create` as `error.TooManyRelayClients` or
    /// `error.RelayQueueDepthZero`, which is where an operator's number is
    /// validated before a node exists.
    peers: []const Peer = &.{},
    /// The protocol to offer and to dispatch. See `max_alpns`.
    alpn: []const u8 = gossip_alpn,
    /// Membership and broadcast. The defaults are upstream's, and a test that
    /// wants them faster overrides them here rather than the other way round.
    topic: hyparview.TopicConfig = .{},
    /// What this node is toward relays. Off unless it says otherwise, and see
    /// `node.zig`'s module doc for what a relay node gives up by being one.
    relay: Relay = .{},
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
    relay_frame.Error ||
    relay_server.Queue(relay_server.Packet).PushError ||
    hyparview.Error ||
    plumtree.Error ||
    Allocator.Error ||
    error{
        /// The `Io`'s monotonic clock reported a value `Instant` — a signed
        /// 64-bit nanosecond count — cannot hold. Unreachable on any machine
        /// this runs on, and refused rather than `@intCast`ed so a clock that
        /// is not what it claims is a named answer instead of a panic.
        InstantOutOfRange,
        /// A datagram handed to `sendThrough` is longer than `max_datagram`,
        /// and the slot it would be queued into is that long. A relay
        /// forwards datagrams; this is the length of one.
        DatagramTooLarge,
        /// `sendThrough` was asked of a node that has not reached a relay, so
        /// there is no stream to write it on.
        NoRelay,
        /// A relay was configured to admit more clients than this node's tables
        /// hold. `max_relay_clients` sizes them and they are built not to grow,
        /// so this is the operator's number to lower rather than a relay that
        /// has to shed connections to fit.
        TooManyRelayClients,
        /// A relay was configured with a queue of no room, which can never take
        /// anything and would drop every datagram while reporting that it
        /// forwarded none.
        RelayQueueDepthZero,
    };
