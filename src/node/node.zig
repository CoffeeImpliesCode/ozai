//! The node: everything above the transport, owning its sockets and driving
//! its own loop.
//!
//! Until this file existed, the whole of ozai was a library driven
//! synchronously by a test. `endpoint/endpoint.zig` is a function of
//! `(state, event)` that deliberately takes no `std.Io` and hands the two
//! operations that do need one back to the caller as values — `Action.spawn`
//! and `cancel_accepts` inside `Action.shutdown` — and that caller did not
//! exist. This file is it.
//!
//! # The runtime shape, and why it is this one
//!
//! An accept task here is a value, and `step` runs every task in turn inside
//! one pass. That is the whole runtime: no thread, no scheduler, no
//! `Io.Group`. Two facts in this repository decide it, and neither is a
//! preference.
//!
//! 1. **`Io.Uring` cannot send a UDP datagram.** `netSendUnavailable`
//!    (`lib/std/Io/Uring.zig:5042`) answers `error.NetworkDown` at `:5053`, so
//!    a process whose `Io` is `Io.Evented` — which resolves to `Io.Uring` on
//!    Linux (`lib/std/Io.zig:31-37`) — cannot put a packet on the wire at all.
//!    A node's runtime is therefore chosen by what it can do, and the answer
//!    for this one is `Io.Threaded`: a poll loop over descriptors this node
//!    owns, asking `Io` for nothing but cancellation. That is the position
//!    `transport/socket.zig` already takes, and gives the same reason — a
//!    descriptor opened with `std.c.socket` is a descriptor no `Io` backend
//!    has been told about, so handing it to one would be a claim that only
//!    holds for `Threaded` (see that file's "Where `io` is, and where it is
//!    not").
//! 2. **A scheduler is not on the table.** `DECISIONS/0002` reversed the
//!    dependency on one and names what would reopen the question: "a
//!    connection becomes a task rather than a value". That has not happened
//!    — an accept is still a value in the endpoint's own table — and taking a
//!    runtime for work that does not exist is a dependency every later reader
//!    pays to understand.
//!
//! So `step` is one pass over the kernel, the core, the endpoint's actions and
//! the gossip layer; `run` is `step` in a loop with a clock. Every call into
//! the QUIC core still takes the caller's instant and the caller's generator,
//! as `quic_bridge.zig` demands, which is what lets the test at the bottom of
//! this file drive a whole connection with a counter and no wall clock at all.
//!
//! # `Io` is a parameter and is never stored
//!
//! `docs/DECISIONS/0002` states it as the property the design is for: "a
//! struct holding an `Io` cannot be driven twice with different clocks". So
//! `Node` has no `Io` field, `create` takes one and uses it for the one thing
//! only an `Io` can do — draw the transport secrets `Bridge.create` was not
//! given — and everything after that threads it. `Node.deinit` needs none at
//! all.
//!
//! # What is wired, and the one thing that is not
//!
//! Wired, and proved by the test below: the socket, the bridge, the dialer,
//! the address map, the router's table, the endpoint's accept loop with every
//! `Action` performed, the gossip state machine driven as a long-lived loop
//! with its timers firing, and the shutdown in the order `router.Shutdown`
//! enforces — handlers, then cancel the accepts, then close.
//!
//! Not wired: **the gossip wire format.** `gossip/hyparview.zig` says of
//! itself that it has no codec, and the only encoder in this repository is
//! `test/protocol_loopback_test.zig`'s, which is explicitly not the project's
//! format. So every `send_message` membership asks for is counted, in
//! `gossip_membership_asked` and `gossip_broadcast_asked`, and the peer it
//! names is kept in `Node.named`, and nothing else happens to it. That is
//! the whole of the gap and it is visible in the counters rather than
//! inferred from silence: a node whose counters grow while nothing arrives at
//! its peer is a finding, and the binary prints both halves. The codec belongs
//! in `src/gossip/`, where a codec belongs, and lands with the protocol
//! milestone rather than here.
//! # The relay, and where it sits in the loop
//!
//! `relay/server.zig` was a complete state machine that nothing drove: a
//! registry of the clients a relay has admitted, two bounded queues per
//! connection, and an admission guard whose `deinit` is the only exit. It is
//! driven here, and it is driven from the loop rather than beside it — the
//! relay pass sits **after** `drive` and **before** `drain`, and both ends of
//! that are load-bearing rather than tidy.
//!
//! * **After `drive`,** so a connection whose handshake finished in this pass
//!   is established before anything may name it. Forwarding before the accept
//!   tasks have run would look a client up in a registry it has not reached.
//! * **Before `drain`,** because everything a relay writes goes into a stream
//!   the core owns, and `drain` is where the core's egress is collected. A
//!   relay pass after `drain` would write a frame this pass and put a packet
//!   on the wire for it on the next one: one extra round trip per forwarded
//!   datagram, which is the whole cost a relay exists to avoid.
//! * **After the sweep,** for the reason the sweep is where it is. A
//!   connection that ended during the last pass's timers is already out of
//!   the core's table, so this pass can tell its client is gone rather than
//!   walking a `Conn` into freed memory.
//!
//! The accept path a relay uses is the one this file already had: `admit`
//! offers every server-side connection to the filter and `drive` runs the
//! task, and neither cares whether the connection came from a dial. The relay
//! pass is what runs *after* that, on the connections the accept loop has
//! finished — which is the whole of what "an accept that does not come from a
//! dial" means here.
//!
//! # What the relay needs and the transport did not have
//!
//! **A stream.** `relay/frame.zig` is explicit that one message is one frame
//! with no length prefix, because upstream's carrier is a WebSocket and the
//! message boundary is the WebSocket's. A QUIC stream is a byte pipe with no
//! boundary, so this file writes the one the WebSocket was carrying — a QUIC
//! varint length, then the frame, and `decode` handed exactly the message the
//! length named. The frame bytes themselves are untouched.
//!
//! Opening one is `quic_bridge.Stream`, added to the bridge rather than
//! reached for: a caller going through `Conn.entry.conn.streams` would be a
//! second opinion on the core, which is the thing the bridge exists to
//! prevent, and `vendor/quic` is unchanged. See that declaration.
//!
//! **A protocol of its own.** `relay_alpn` below, and `max_alpns` is one:
//! a node speaks exactly one protocol, so a relay node cannot also gossip.
//! Upstream keeps the two apart by construction — the relay protocol is a
//! WebSocket on a TCP listener beside the quinn socket — and this transport
//! has one socket and one core. That is a `max_alpns` decision and not a relay
//! one, so it is left where it belongs and named here rather than solved.
//!
//! **What the relay forwards** is a relay-protocol datagram: an opaque
//! payload with the node it is for. Putting an *inner* QUIC packet through it
//! additionally needs the send side to rewrite a `.relay` synthetic address
//! onto the relay's real socket address, and `Conn.drain` publishes
//! `Egress.to` from the core's own peer address with no map in between
//! (`quic_bridge.zig:279-324`). That is a transport gap and it is named here
//! rather than patched around.
//!
//! # The configuration is this project's vocabulary, translated once
//!
//! `Config` is a secret key, a listen address, a list of peers to dial and an
//! ALPN. It becomes a `quic_bridge.Config`, a `dial.Config`, a `Router` and a
//! `hyparview.TopicConfig` inside `create` and nowhere else, for the reason
//! `quic_bridge.zig` gives for its own: a translation nobody can read is a
//! translation nobody can check. Nothing of the vendored core's spelling —
//! `TlsConfig`, `ConnectionManager`, `Tls13Handshake` — crosses into `Config`.
//!
//! **The other direction is not a boundary, and it is named here rather than
//! claimed.** `Node` holds `Config` verbatim in `Node.config`, and Zig has no
//! field visibility, so `Config` and every type nested in it — `Peer`, `Relay`,
//! `Role`, `Serve` — are reachable from outside this module. The node binary
//! reads `node.config.relay.role` through the registered `ozai` module today
//! (`src/node/main.zig`), and `Node.clientCount` switches on it for a caller
//! that only has the method. Every rule stated on `Config` is therefore a rule
//! a consumer can read, and one of them a consumer can also break. Which
//! fields are borrowed and which must not be written after `create` is said at
//! `Node.config`, and that is the whole of the protection there is: the
//! language offers none other, and README's blanket line about reachable
//! fields is a disclaimer rather than a rule a caller can follow.

const std = @import("std");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("../transport/addr_map.zig");
const batch = @import("../transport/batch.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_client = @import("../relay/client.zig");
const relay_server = @import("../relay/server.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const Bridge = bridge_mod.Bridge;
const Conn = bridge_mod.Conn;
const Egress = bridge_mod.Egress;
const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine has
/// to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
pub const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small.
pub const max_egress = 8;

/// Room for every datagram one drain may produce.
pub const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: a datagram is copied into its front and a stateless
/// reply is written behind it.
pub const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read. A receive
/// buffer too small for it truncates a coalesced read, which arrives at this
/// seam as `error.MessageTooLarge` rather than as a short datagram.
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How many accept tasks a node can hold.
///
/// A bound, and a node that reaches it **refuses** the connection rather than
/// dropping it: `endpoint.zig`'s `spawn` says why, and the reason is that an
/// attempt accepted and then held nowhere is a peer that believes it is
/// connected and is not.
pub const max_accepts = 64;

/// How many protocols a node registers, which is one.
///
/// The bridge offers one: `quic_bridge.Config.alpn` builds a one-element
/// `alpn_list` and the core negotiates from that list
/// (`quic_bridge.zig:222-225`). A node whose transport offered two while its
/// router dispatched one would have a table and a wire that disagree, so the
/// second protocol arrives with a second bridge field rather than as a list
/// this file fills.
pub const max_alpns = 1;

/// The deepest chain of endpoint events one `feed` can enqueue.
///
/// The shutdown is the longest: `close_requested`, one `handler_finished` per
/// registered handler, `accepts_cancelled`, `endpoint_closed`. With one
/// registered handler that is four, and an arrival is two.
pub const max_pending_events = 8;

/// How long `run` blocks on the socket when a pass moved nothing.
///
/// A poll loop has no timer wheel, so this interval *is* the resolution the
/// QUIC timers and the gossip clocks are served at, and it is also how long a
/// stop signal waits to be seen: `Socket.awaitReadable` retries a signal
/// rather than letting it out. A quarter of a second is coarse for a datagram
/// path and right for the two things this loop is actually waiting on — a
/// peer's handshake and membership's shuffles — and it is the honest ceiling
/// of a loop with no scheduler to hold deadlines (`DECISIONS/0002`) and no
/// send path on `Io.Uring`.
pub const poll_interval_ms = 250;

/// How many peers a gossip action's name is kept for.
///
/// The state machine names a peer for every message it asks to be sent and
/// every disconnect it asks for, and the message itself stops at a counter.
/// A reader that wants to know *who* is being talked about reads this rather
/// than the count, and the two disagreeing is a finding.
pub const named_ring = 8;

/// The pass bound on a close that does not finish in one pass.
///
/// A close is four phases and `finish` takes one iteration per phase, so this
/// is the bound on a close that is resumed from somewhere in the middle. It
/// asserts rather than spinning — `AGENTS.md` §1.
pub const max_close_steps = 8;

/// The gossip protocol's ALPN, which is also the only protocol this node
/// speaks. `docs/PLAN.md` names it at M11.
pub const gossip_alpn = "/iroh-gossip/1";

/// The relay protocol's ALPN, which a node sets as its own when it is a relay
/// or a relay's client. See the module doc's "The relay, and where it sits in
/// the loop" for why a relay node cannot also gossip.
pub const relay_alpn = "/iroh-relay/1";

/// How many clients a relay admits.
///
/// Small, and deliberately: every one of them costs `queue_depth *
/// max_datagram` of fixed storage for the datagrams queued to it, so this is
/// the number an operator picks and `Relay.clients` is the way to pick it.
pub const max_relay_clients = 4;

/// Registry slots for those clients. Open addressing, so twice the clients is
/// never more than half full.
const relay_table_slots = 2 * max_relay_clients;

/// How many connections one node id's later connections may displace.
///
/// Enough for `Registry.Admit.replaced` and `Unregister.promoted` to be
/// reachable, and a comptime parameter of `Registry` because the entry's
/// inactive list is a fixed array rather than something that grows.
const relay_displaced = 4;

/// Upstream's `PER_CLIENT_SEND_QUEUE_DEPTH` (`relay.rs:40`) is 512 and both of
/// its channels get it, and 512 is the number invariant 9 is about: merged, a
/// `Status` sits behind 512 datagrams for a client that has stopped reading.
///
/// This node makes it the operator's number, because the queue is backed by
/// fixed storage this file allocates and 512 datagrams a client is 512 ×
/// `max_datagram` of bytes a client. The test at the bottom of this file sets
/// `Relay.queue_depth` to upstream's number so the property is exercised
/// rather than assumed.
pub const default_relay_queue_depth = 64;

/// Room for the largest message this node reads or writes on a relay stream:
/// a datagram's payload, the frame header around it, and a varint length in
/// front of that.
///
/// **This is a write bound, and `encode` refuses rather than truncates**, so a
/// frame that does not fit is `error.BufferFull` rather than a lie on the wire.
///
/// Eight is the widest a QUIC varint can be, and `DatagramFrame.header_length`
/// is the node id and the codepoint. That makes a datagram the widest frame
/// this node sends, and every other frame narrower — a serving relay writes a
/// challenge, a confirmation, a datagram, an `endpoint_gone`, a `status` and a
/// `pong`; a relay client writes a `client_auth`, a datagram and a `pong`. All
/// but one are bounded by a node id, by eight fixed bytes, or by the datagram.
///
/// **The eighth — `server_denies_auth`, whose payload is a reason string — was
/// the hole, and it is closed in the codec rather than here.** Its length is
/// the one in this protocol a peer can reach: upstream's access control is a
/// trait the operator implements (`handshake.rs:495`, `:524`), so the reason is
/// whatever that trait decided, and a buffer sized for whatever it said is not
/// a bound. `relay_frame.max_text_length` is, and
/// `relay_frame.encode` refuses past it as `error.TextTooLong` before writing a
/// byte. So the widest denial this node can be handed is a number —
/// `relay_frame.ServerDeniesAuth.max_frame_length` — and the assertion below is
/// what says it fits here. **Reserving worst-case room instead would have been
/// the wrong answer:** it is unbounded, so "worst case" is not a number, and
/// sizing a buffer for an unbounded string is the same mistake with a bigger
/// constant.
pub const relay_frame_room = relay_frame.DatagramFrame.header_length + max_datagram + 8;

comptime {
    // The reason a relay sends is bounded by the codec, so this is arithmetic
    // rather than a hope: if the bound or the datagram moves, this stops the
    // build instead of letting a relay discover at run time that it has no room
    // for the denial it just decided to send.
    if (relay_frame.ServerDeniesAuth.max_frame_length > relay_frame_room) {
        @compileError("the relay's frame room is narrower than the denial it may send");
    }
}

/// How many clients a relay admits, how deep their queues are, and how far
/// this node will read and write one connection in a single pass.
///
/// A relay is sized by its operator, and every number here is one they set:
/// admitting more clients than `max_relay_clients` needs the tables this file
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
    /// How many clients. `max_relay_clients` is what the tables this file
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
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
    /// the module doc for what a relay node gives up by being one.
    relay: Relay = .{},
};

/// One datagram a relay handed this node, and the node it came from.
///
/// `data` is a copy this node allocated from its own `gpa`, not a view of the
/// bytes the relay frame was read from: a relay frame borrows its datagrams out
/// of its inbox and that inbox is reused by the next read, so a payload handed
/// out has to be a copy or it is a view of a buffer that has moved on.
///
/// **Two lifetimes, and they are not the same one.** The payload is owned by
/// the node until `clearDelivered` gives it back — or until `deinit`, which
/// frees whatever is still listed — and the node's allocator is the one that
/// frees it. The list it sits in does not survive the next delivery: appending
/// to it may move it. `Node.delivered` says which is which from the outside.
pub const Delivered = struct {
    /// The node id the relay says this datagram came from. Copied, and so
    /// independent of the payload and of every other item on the list.
    src: NodeId,
    /// The datagram bytes this node copied. Empty is a datagram of no bytes,
    /// which the relay protocol permits and which is not an absence.
    data: []u8,
};

/// What this file refuses.
///
/// Everything is a set a seam below already published, so a caller of `step`
/// writes the same error name the seam's own tests write. The two arms that
/// are this file's own are named for what they are.
///
/// One of these arrives only from a `std.Io` that has refused, and it says
/// which refusal: `error.Canceled` is this file or a seam below asking the
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

/// The loop's stop signal: a flag a signal handler can set, and a deadline the
/// loop checks against the clock it already reads.
///
/// `request` is async-signal-safe — one atomic store and nothing else — which
/// is why `src/node/main.zig` may call it from a `SIGINT` handler while the
/// loop is inside `poll`.
///
/// It is a parameter of `run` and not a field of `Node` for the same reason
/// `Io` is: the thing being asked to stop should be a value the caller holds,
/// so a caller can hold two of them and stop them independently.
///
/// Only `request` may run concurrently with `run`. Set the deadline before
/// starting the loop; `due` is not atomic. A request is not a join and does not
/// release the node. Wait for `run` to return before releasing either value.
/// Copies hold separate latches and deadlines.
pub const Stop = struct {
    /// Whether anybody has asked. Atomic because `request` may be called from
    /// a signal handler while the loop is inside `poll`, and one store is the
    /// whole of what a handler is allowed to do.
    flag: std.atomic.Value(bool) = .init(false),
    /// The instant this becomes due, in the loop's own clock, or null for
    /// never. It lives here so a caller that wants a bounded run needs neither
    /// a second clock nor a thread; the loop reads one every pass and checks
    /// this against it.
    ///
    /// A deadline is not a stop *signal*, and this file does not pretend it is.
    /// The signal path is `request`; the binary's `--for` sets `due` and is a
    /// convenience over the same loop exit.
    due: ?Instant = null,

    /// A signal nobody has raised and no deadline set.
    pub fn init() Stop {
        return .{};
    }

    /// Ask the loop to wind down.
    pub fn request(self: *Stop) void {
        self.flag.store(true, .release);
    }

    /// Whether anything has asked the loop to wind down, from a signal handler
    /// or from the caller's own code. The flag records no provenance, because
    /// `request` is public and either is a legitimate reason.
    pub fn requested(self: *const Stop) bool {
        return self.flag.load(.acquire);
    }

    /// Stop at `at`. This is the caller saying when, not the loop asking.
    /// Set this before the loop starts, not from a concurrent thread or handler.
    pub fn expireAt(self: *Stop, at: Instant) void {
        self.due = at;
    }

    /// Whether the loop should end, from a signal or from the deadline.
    pub fn expired(self: *const Stop, at: Instant) bool {
        if (self.requested()) return true;
        const due = self.due orelse return false;
        return at >= due;
    }
};

/// A timer the gossip layers asked for, and the instant it comes due.
const Pending = struct {
    due: hyparview.Nanos,
    timer: hyparview.Timer,
};

/// What one action the endpoint owes is answered with.
///
/// One action can owe more than one report: `shutdown_handlers` owes one
/// `handler_finished` per registered handler, and every one of them is the
/// same event. So the answer is a counted event rather than a list, because a
/// list would be storage this function does not own, and the router's machine
/// consumes nothing else.
const Answer = struct {
    event: endpoint.Event,
    count: usize = 1,
};

/// What the node did, counted.
///
/// Every arm here is something a caller would otherwise have to ask the stack
/// about and get no answer to. The two gossip counters that stop at a count
/// are the module doc's named gap.
pub const Stats = struct {
    /// Passes of `step` this node has run.
    steps: u64 = 0,
    /// Datagrams the kernel handed over, and datagrams put on the wire.
    datagrams_in: u64 = 0,
    datagrams_out: u64 = 0,
    /// Sends the socket could not batch, and sends that lost a codepoint.
    sends_degraded: u64 = 0,
    ecn_lost: u64 = 0,
    /// Peers `start` dialled, and peers it could not reach.
    dials: u64 = 0,
    dials_refused: u64 = 0,
    /// Accept-loop actions performed. `attempts` is an `Event.arrived` fed,
    /// and the rest are the actions that answered it.
    attempts: u64 = 0,
    spawned: u64 = 0,
    handler_connections: u64 = 0,
    handler_shutdowns: u64 = 0,
    accepts_cancelled: u64 = 0,
    refusals: u64 = 0,
    ignores: u64 = 0,
    /// Connections the core finished with.
    connections_finished: u64 = 0,
    /// Events handed to the gossip layer, and timers it asked for and saw.
    gossip_events: u64 = 0,
    gossip_timers_scheduled: u64 = 0,
    gossip_timers_fired: u64 = 0,
    /// Messages membership asked to be sent, split by layer. **Nothing is
    /// done with them**: see the module doc.
    gossip_membership_asked: u64 = 0,
    gossip_broadcast_asked: u64 = 0,
    /// Peers membership asked to be disconnected, for the same reason.
    gossip_disconnects_asked: u64 = 0,
    /// What membership reported upwards.
    neighbor_up: u64 = 0,
    neighbor_down: u64 = 0,
    broadcasts_received: u64 = 0,
    peer_data_seen: u64 = 0,
    /// What the relay did, counted.
    ///
    /// Split by what was asked of it rather than folded together, because a
    /// relay that forwards nothing and a relay that forwards nothing *useful*
    /// produce the same counter and need not produce the same log.
    relay_admitted: u64 = 0,
    relay_replaced: u64 = 0,
    relay_promoted: u64 = 0,
    /// Accepted connections this relay had no room for. Upstream refuses
    /// rather than drops, for the reason `endpoint.zig` gives.
    relay_refused: u64 = 0,
    /// Connections this pass could not be admitted **although a client slot was
    /// free**, because the peer had granted no more bidi streams than this end
    /// has already opened on that connection. **Not a refusal** — the
    /// connection is re-offered on the next pass, and `MAX_STREAMS` raises the
    /// grant — and it is counted apart from `relay_refused` because the two
    /// answer opposite questions: that one is a client this relay has no room
    /// for, this one is a client it had room for and no stream to speak on. A
    /// counter that added them together could not say which relay it had.
    relay_stream_deferred: u64 = 0,
    /// Streams a peer finished in the middle of a frame, and the partial frame
    /// dropped with them. See `discardTail`.
    relay_stream_truncated: u64 = 0,
    /// Datagrams forwarded, read off clients, and handed to this node's own
    /// relay client.
    relay_forwarded: u64 = 0,
    relay_datagrams_in: u64 = 0,
    relay_datagrams_out: u64 = 0,
    relay_sent: u64 = 0,
    /// Disconnects reported, and connections that had already been displaced.
    /// The sum is what access control was told, and it is once per connection.
    relay_disconnects: u64 = 0,
    relay_duplicates: u64 = 0,
    /// Queues that were full when something had to go on one, split by what
    /// the full queue could not take: a datagram for a client, a message for
    /// anybody.
    relay_queue_full: u64 = 0,
    relay_unknown_target: u64 = 0,
    /// Datagrams too long for the slot they would be queued into.
    relay_oversized: u64 = 0,
    /// Dials of a relay, and relays that were not there.
    relay_dials: u64 = 0,
    relay_dials_refused: u64 = 0,
    /// The client half: where its handshake got to.
    relay_auth_sent: u64 = 0,
    relay_established: u64 = 0,
    /// `endpoint_gone` frames this node's relay client was handed: the peer it
    /// tried to reach is not at the relay.
    relay_peer_gone: u64 = 0,
    /// A relay told this client it had been displaced by a later connection
    /// for its own node id.
    relay_displaced: u64 = 0,
    relay_closed: u64 = 0,
    /// Reports that found nothing to report. A registry holds a connection once
    /// and `unregister` answers only for one it still holds, so this is the
    /// counter a double report would move.
    relay_double_reports: u64 = 0,
    /// Connections a later one displaced, and that this node managed to tell
    /// over a control queue.
    relay_told_displaced: u64 = 0,
};

/// One client this node serves.
///
/// The registry holds connection ids and not these, because a registry that
/// held queues would allocate and `relay/server.zig`'s does not — it is a table
/// over storage the caller owns, and this is where the caller put the rest.
const Served = struct {
    /// Whether this slot holds a client.
    live: bool = false,
    /// The core connection this client is spoken on, which is the id the
    /// registry holds for it.
    conn: u64 = 0,
    /// The relay half of the handshake, from the moment the connection is
    /// established. `.admitted` is where a client stops being a handshake and
    /// starts being a client.
    handshake: relay_server.State = .opened,
    /// The handle that ends this client, and the only way out of the registry.
    /// Null is a client that has not been admitted, and must not be reported
    /// as gone: `Registry.unregister` is not public, so a client with no
    /// handle has no exit at all.
    guard: ?relay_server.Registry(relay_displaced).OnDisconnectGuard = null,
    /// The node id the handshake proved, or null until it has.
    node_id: ?NodeId = null,
    /// The two queues, over storage this node owns.
    queues: relay_server.Connection = undefined,
    /// The bytes a queued datagram borrows: one fixed slot per queue position,
    /// so a `Packet` points at the slot its own ring position names and the
    /// slot is free the moment it is popped.
    ///
    /// Fixed rather than an arena that grows, because a growing arena moves
    /// the bytes every queued `Packet` points at.
    ring: []u8 = &.{},
    /// The stream this relay writes to the client on: one it opened itself.
    ///
    /// **Two streams per client, and they are not interchangeable.** A QUIC
    /// stream is read by whichever end opened it, so the client's half of the
    /// protocol can only be read from the stream the *client* opened — which
    /// this connection does not hold until the client has written something.
    /// That is why the relay opens one of its own to speak on: a relay that
    /// waited for the client's stream could not send the challenge that makes
    /// the client write on it. `serveRead` finds the other half each pass.
    out: bridge_mod.Stream = undefined,
    /// What has been read off that stream and is not yet a whole message.
    inbox: std.ArrayList(u8) = .empty,
    /// Whether the client has been told there is nothing more.
    ended: bool = false,
};

/// The relay this node spoke to, and what it has handed back.
const Spoke = struct {
    /// The core connection the relay is on.
    conn: u64,
    /// The stream the relay protocol runs on, once there is one.
    ///
    /// **Not at the dial.** `StreamsMap.openBidiStream` refuses while the
    /// peer's stream limit is still zero (`stream.zig:1385-1389`), and a
    /// dialled connection has not read a peer's transport parameters until its
    /// handshake is through. So the stream is opened on the first pass where
    /// the connection is established, which is also the first pass where
    /// anything could be written on it.
    stream: ?bridge_mod.Stream,
    /// The client half of the handshake, from the dial.
    handshake: relay_client.State,
    /// What has been read and is not yet a whole message.
    inbox: std.ArrayList(u8),
    /// Everything the relay has handed this node, owned until cleared.
    delivered: std.ArrayList(Delivered),
};

// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

/// A node: an identity, a socket, a bridge over it, a dialer, the endpoint's
/// accept loop over that bridge, and one topic of gossip.
///
/// Heap-allocated, and the reason is the endpoint's own: `Loop.acquire` hands
/// back a lease that reads through `&loop.shutdown`, and the handler the
/// router calls is handed this struct's address as its context. A node that
/// moved after either of those was taken would invalidate both, so `create` is
/// the only way to build one and the pointer it returns is the node.
///
/// **The address is the node's whole identity, and it stays put.** Two things
/// hold it and both are taken once, in `create`: the lease `Loop.acquire`
/// hands back reads through `&self.accept.shutdown`, and the handler context
/// the router is given is `@ptrCast(self)`. A value copied out of `create`'s
/// result would be a second node sharing one lease and one handler context, so
/// the pointer is what every other call on this type takes and `Node` is never
/// copied by value.
///
/// **One thread owns a node, and one call at a time.** Nothing in this struct
/// is locked and the only atomic is `Stop.flag`, so `start`, `step`, `wait`,
/// `run`, `close`, `delivered`, `clearDelivered` and `sendThrough` are
/// single-threaded operations on a node one thread owns. The one call that may
/// come from another thread while `run` is inside `poll` is `Stop.request`,
/// which is one atomic store and is documented as async-signal-safe for
/// exactly that reason.
///
/// **Not reentrant either**, and this is a property of where the callbacks sit
/// rather than of their signatures. Every call this file makes into a
/// `ProtocolHandler` or an `IncomingFilter` is made from inside a pass, so a
/// handler that called `step`, `run` or `close` would re-enter the pass that
/// called it with the connection table and the accept-task table mid-walk.
/// `shutdown` is the one that looks harmless and is not: it runs inside
/// `performShutdown`, before the machine has advanced past the handlers, and
/// the ordering upstream's shutdown is *about* is that a handler's resources
/// are released while the accepts that might still be using them are running
/// and never after. `shutdownHandler` is the discipline to copy — it gives up
/// the handler's own state and touches nothing else.
pub const Node = struct {
    gpa: Allocator,

    /// The configuration as it was given, held verbatim, and **four kinds of
    /// field with four different rules.** Zig gives a consumer write access to
    /// every one of them, so what follows is the contract rather than a
    /// suggestion.
    ///
    /// *Borrowed.* `alpn` and `peers` are not copied; the bytes they name must
    /// outlive the node, not merely the call. `create` states the same for the
    /// caller holding them, and `Config.peers` for each `addr` inside.
    ///
    /// *Construction-fixed, and one of them read on every pass.* `relay.role`
    /// chose what `initRelay` allocated and is what every role check in this
    /// file reads; `Serve.queue_depth` is what `queueDepth` returns on every
    /// pass, out of this field, to re-cut each live client's queues and ring
    /// from storage sized once from the value `create` was given. **Do not
    /// write `relay.role`, `Serve.clients` or `Serve.queue_depth` after
    /// `create`:** a `queue_depth` above the built one indexes past the end of
    /// `packets` and `messages`, one below it hands every live client another
    /// client's slots, and a different role has the relay pass admitting,
    /// forwarding or dialling as something this node was not built to be.
    /// `Serve.drain_room` is the exception and is safe to write: it sizes no
    /// storage, so a change bounds one pass and nothing else.
    ///
    /// *Consumed by `create`, read by nothing after it.* `listen` is the
    /// address the socket now holds and `topic` was translated into
    /// `Node.topic`. `peers` is walked by `start` and by nothing else, so a
    /// caller driving passes itself may change the list before its first
    /// `start` and gets nothing from a change made after it.
    ///
    /// *Copied, with one later reader.* `create` copied `secret` and the core
    /// holds a copy of its own, so a write reaches exactly one reader: the
    /// relay client's handshake, which signs the relay's challenge with it in
    /// `converseMessage`. It is the only field here whose mutation is silently
    /// wrong rather than unsafe or inert.
    config: Config,

    /// The transport, in the order `Wire.deinit` unwinds it.
    socket: Socket,
    bridge: *Bridge,
    dialer: *Dialer,
    map: addr_map.MappedAddrs,
    socket_open: bool,

    /// Whether the endpoint step of the shutdown has been performed. The
    /// machine emits `close_endpoint` once, on the event before it, so a close
    /// resumed at `closing_endpoint` has to know whether the step it owes
    /// already ran or is the one that failed. See `finish`.
    endpoint_closed: bool,

    /// The router's table and the accept loop over it. `entries` is the
    /// storage `Builder` writes into and `table` is the frozen view of it, so
    /// the loop's `*const Router` points into this struct.
    entries: [max_alpns]router.Entry,
    table: router.Router,
    tasks: [max_accepts]endpoint.Task,
    accept: endpoint.Loop,
    lease: router.Lease,

    /// The gossip layer, its timers, and the peers it named.
    topic: hyparview.TopicState,
    timers: std.ArrayList(Pending),
    named: [named_ring]NodeId,
    named_len: usize,

    /// The generator, and the buffers the socket and the drain seams need.
    /// They are on the heap because the receive buffer is
    /// `receive_room` bytes: a stack frame that overflows fails for a reason
    /// that has nothing to do with QUIC.
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,
    /// A datagram `wait` took and `take` has not handed to the core yet.
    held: ?socket_mod.Received,

    /// Connections already offered to the filter. The core's connection ids
    /// are never reused (`quic_bridge.zig:230-233`), so this only has to
    /// answer "has this one been offered", and a set is the whole question.
    offered: std.AutoHashMapUnmanaged(u64, void),
    /// Peers `start` has dialled, whether or not the dial worked.
    dialled: std.AutoArrayHashMapUnmanaged(NodeId, void),
    /// Whether the gossip layer has been told to join. Set once the join
    /// command has actually been fed, so a `start` that was refused feeds it
    /// on the next call rather than reporting success over nothing. See
    /// `start`'s own rule.
    joined: bool,

    /// The relay's tables, its clients' queues and the buffers a relay frame
    /// passes through. **The slots, the registry, the clients and their three
    /// allocations are built for a `.serve` and are not initialised for any
    /// other role** — `initRelay` returns before it reaches them — so they are
    /// not "empty" elsewhere, they are unwritten, and every reader of them is
    /// gated on the role instead of trusting a table nobody filled. `.off`
    /// builds none of them, and `.client` builds no registry, no queues and no
    /// clients.
    ///
    /// **The two frame buffers below are the exception, and they are every
    /// node's.** `initRelay` allocates `relay_out` and `relay_scratch` before
    /// it looks at the role at all, and `freeRelay` frees both whatever the
    /// role was, so a `.off` node holds and returns two relay allocations it
    /// never writes a byte into — `relay_frame_room + varint_max` and
    /// `relay_frame_room`. An ownership audit that reads this group as "no
    /// relay storage off a relay node" misses both, on every gossip node in the
    /// tree.
    slots: [relay_table_slots]relay_server.Registry(relay_displaced).Slot,
    registry: relay_server.Registry(relay_displaced),
    clients: []Served,
    /// The two queues' storage for every client, laid out back to back and
    /// cut into one client's depth apiece. One allocation for all of them,
    /// because a per-client allocation is a pointer chase on the hot path and
    /// the sizes are all the same.
    packets: []relay_server.Packet,
    messages: []relay_server.Control,
    ring: []u8,
    /// The relay this node spoke to, when it is a client of one.
    spoke: ?Spoke,
    /// Whether that dial has been attempted, whatever it answered. `start`
    /// records a peer the same way, and for the same reason: a relay that was
    /// not there is a fact about the network and not a reason to retry.
    relay_dialled: bool,
    /// Where a relay frame is encoded — the varint length first, then the
    /// frame behind it. **The only relay buffer sized by `relay_frame_room`.**
    /// A read used to have one too, and that conflation was the defect: a read
    /// is a run of whatever arrived, not a frame, so sizing it by the frame
    /// bound refused the run after the core had already handed the bytes over.
    /// See `Stream.drain`.
    relay_out: []u8,
    /// What a decoded relay frame borrows out of. See `peekFrame`.
    relay_scratch: []u8,

    stats: Stats,

    /// Build a node from `config`, with `seed` as the root of every generator
    /// it draws from.
    ///
    /// **`gpa` is this node's allocator for its whole life.** Every allocation
    /// made after this call — the egress list, the three scratch buffers, the
    /// relay's tables and queues, every payload a relay hands this node — is
    /// made from it, and `deinit` returns every one to it. So `gpa` has to
    /// outlive the node: a caller that frees it first has a `deinit` writing to
    /// memory it no longer owns.
    ///
    /// **`config` is taken by value, so everything in it is copied, except
    /// what it points at.** The secret is copied and the copy is zeroed by
    /// `deinit`, so the caller keeps the one it passed and should zero it in
    /// its own turn; there is no move here to observe and nothing to give up.
    /// Two fields are borrowed instead, because copying either would be an
    /// allocation this constructor has no reason to make: `alpn`, which is
    /// registered with the router here and read for as long as the node lives,
    /// and `peers`, which `start` walks on a later pass. **Both must outlive
    /// the node, not merely the call.**
    ///
    /// A `Peer.addr` is borrowed twice over and the second borrow outlives the
    /// first. `start` hands it to the dialer, and the dialer copies it into
    /// this node's address map — but `NodeAddr` owns only the outer list it
    /// allocates, and a `.custom` address inside it keeps pointing at the
    /// caller's own bytes (`base/addr.zig`'s `CustomAddr`). So the outer
    /// address storage belongs to `gpa` and is freed by `deinit`, while the
    /// payload inside it is the caller's and has to outlive the node.
    ///
    /// **A cancelled `io` is `error.Canceled`, not `error.EntropyUnavailable`.**
    /// The two transport secrets are drawn from `io.randomSecure` here and
    /// nowhere else, so an `Io` that is cancelled while they are being drawn
    /// answers `error.Canceled` and one that has no secure entropy answers
    /// `error.EntropyUnavailable`. Nothing is left behind either way: every
    /// line below this one is under an `errdefer`, so a failed `create` frees
    /// the socket, the bridge, the dialer and every buffer it had taken.
    ///
    /// `io` is used for exactly one thing: the two transport secrets
    /// `Bridge.create` was not given. It is null-drawn from `io.randomSecure`
    /// rather than from a process CSPRNG because a global generator is what
    /// `AGENTS.md` §2 forbids and an `Io` the caller handed over is not a
    /// global — and it is read here and nowhere else, because `Node` stores no
    /// `Io`.
    ///
    /// That includes the relay's admission challenge: it is drawn from the
    /// `random` this node is driven with, not from `io`, because a challenge
    /// that differs between two runs of the same node is what makes a test
    /// reproducible and `Io` is not drivable. What that costs is stated where
    /// the challenge is drawn — `serveAdmit`.
    ///
    /// Everything after `Bridge.create` is the configuration translation, and
    /// it happens here once rather than at the call sites that would otherwise
    /// have to know both vocabularies. `quic_bridge.zig` gives the rule: "a
    /// translation nobody can read is a translation nobody can check".
    pub fn create(gpa: Allocator, io: std.Io, config: Config, seed: u64) Error!*Node {
        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .config = config,
            .socket = undefined,
            .bridge = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .socket_open = true,
            .endpoint_closed = false,
            .entries = undefined,
            .table = undefined,
            .tasks = undefined,
            .accept = undefined,
            .lease = undefined,
            .topic = undefined,
            .timers = .empty,
            .named = [_]NodeId{undefined} ** named_ring,
            .named_len = 0,
            .engine = Prng.init(seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
            .held = null,
            .offered = .empty,
            .dialled = .empty,
            .joined = false,
            .slots = undefined,
            .registry = undefined,
            .clients = &.{},
            .packets = &.{},
            .messages = &.{},
            .ring = &.{},
            .spoke = null,
            .relay_dialled = false,
            .relay_out = &.{},
            .relay_scratch = &.{},
            .stats = .{},
        };
        errdefer self.map.deinit(gpa);
        errdefer self.offered.deinit(gpa);
        errdefer self.dialled.deinit(gpa);
        errdefer self.timers.deinit(gpa);

        self.socket = try Socket.create(config.listen, .{});
        errdefer self.shutdownSocket();
        self.bridge = try Bridge.create(gpa, io, .{
            // Null on purpose: one pin cannot name every peer, and the pin
            // that is enforced on this node's accepted connections is the
            // per-dial one the dialer carries.
            .expect_peer = null,
            .secret = config.secret,
            .alpn = config.alpn,
        }, self.generator());
        errdefer self.bridge.destroy();
        self.dialer = try Dialer.create(gpa, self.bridge, .{
            .secret = config.secret,
            .alpn = config.alpn,
        });
        // `destroy` refuses only while a dialled connection is live, and this
        // errdefer cannot meet one: the bridge above was created with an empty
        // table, and every call between there and a failure here allocates,
        // prints an address or builds a table — none of them dials. Asserted
        // rather than assumed, and the arm below says so out loud instead of
        // returning with the dialer's seed un-zeroed.
        errdefer {
            std.debug.assert(self.bridge.manager.entries.items.len == 0);
            self.dialer.destroy() catch |err| switch (err) {
                error.DialedConnectionsLive => std.debug.panic(
                    "a dialled connection is live while building a node: {t}",
                    .{err},
                ),
            };
        }
        self.egress = try gpa.alloc(Egress, max_egress);
        errdefer gpa.free(self.egress);
        self.out = try gpa.alloc(u8, send_room);
        errdefer gpa.free(self.out);
        self.scratch = try gpa.alloc(u8, scratch_room);
        errdefer gpa.free(self.scratch);
        self.buf = try gpa.alloc(u8, receive_room);
        errdefer gpa.free(self.buf);

        // The relay's storage, and only for a node that is one. Every failure
        // here unwinds what it took, so the struct this leaves behind is the
        // one `deinit` will find.
        try self.initRelay();
        errdefer self.freeRelay();

        // What this node advertises as its own contact data: the address it
        // is reachable at. Upstream carries opaque bytes and this is the one
        // that is true of every node in it.
        //
        // The buffer is `SocketAddr.max_text_length` and not a byte more, so
        // the only way `bufPrint` refuses is a bound that is wrong; the arm
        // below is the statement that it is, made loud rather than silent.
        var addr_text: [SocketAddr.max_text_length]u8 = undefined;
        const advertised = std.fmt.bufPrint(&addr_text, "{f}", .{
            self.socket.address,
        }) catch |err| switch (err) {
            error.NoSpaceLeft => std.debug.panic(
                "address text needs more than {d} bytes: max_text_length is wrong",
                .{SocketAddr.max_text_length},
            ),
        };
        self.topic = try hyparview.TopicState.init(
            self.bridge.nodeId(),
            try hyparview.PeerData.fromBytes(advertised),
            config.topic,
            hyparview.Rng.init(seed),
        );

        // Last, because the two values below read through this struct and a
        // failure after this point would have to unwind a lease that nothing
        // else holds.
        var builder = router.Builder.init(&self.entries);
        const registered = try builder.accept(config.alpn, self.handler());
        // `.fresh` is the only answer here: the table was built a line ago and
        // holds no ALPN, so a `.replaced` would be a second registration for
        // the one protocol this node speaks, which `max_alpns` rules out.
        std.debug.assert(registered == .fresh);
        self.table = builder.build();
        self.accept = endpoint.Loop.init(&self.table, null, &self.tasks);
        self.lease = self.accept.acquire();
        return self;
    }

    /// Free everything the node owns.
    ///
    /// The endpoint lease is given up first, and what it reports is this
    /// node's misuse or not: upstream logs an error from `EndpointInner`'s
    /// `Drop` when `close()` was never called — "Endpoint dropped without
    /// calling `Endpoint::close`. Aborting ungracefully"
    /// (`iroh/src/socket.rs:220-230`) — so dropping a node whose accept loop
    /// is still serving is a misuse and not a cleanup. The report is at error
    /// level on purpose: it is a finding, and `zig build test`'s runner fails an
    /// artifact that logged one.
    ///
    /// **It is the only exit, and it takes the node with it.** The pointer
    /// `create` returned is dead afterwards, so every `Delivered.data`, every
    /// `Peer` address the map still holds and the node's own copy of the
    /// secret all end here rather than at a second call. Nothing may outlive
    /// this call except what `create` borrowed and the caller still owns.
    ///
    /// **It may not run under a `run` or a `step` that is still on the
    /// stack.** `run` closes the node on its way out precisely so that the
    /// caller reaches this call with the shutdown already run out; a caller
    /// that destroys a node whose loop is still passing it frees the buffers
    /// the pass is writing into. Single-threaded, like everything else here.
    ///
    /// What it gives back, in the order it gives it: the endpoint lease, every
    /// dialled connection and the core's sweep, the relay's clients and
    /// whatever the relay handed over, the dialer, the bridge, the four heap
    /// buffers, the address map, the three bookkeeping tables, the socket, and
    /// finally the node itself. The address map's own storage goes with it; the
    /// payloads inside a `.custom` address are the caller's and are untouched,
    /// because `NodeAddr` never owned them.
    pub fn deinit(self: *Node) void {
        switch (self.lease.deinit()) {
            .closed => {},
            .abandoned => |phase| std.log.err(
                "node {f} was dropped in phase {t} without close()",
                .{ self.bridge.nodeId(), phase },
            ),
            .already_gone => {},
        }
        // `Dialer.destroy`'s order, and for its reason: a dialled connection's
        // handshake points at the dialer's own seed, so every connection this
        // dialer opened has to leave the manager before the dialer goes, and
        // the manager has to outlive both. Backwards, because
        // `removeConnection` swap-removes and a forward walk would skip an
        // entry.
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        // Before the dialer's connections leave and before the bridge goes: a
        // guard reaches into this struct's own registry and a client slot
        // points at a connection the core is about to free. An orderly
        // shutdown has already released every client, so this is the backstop
        // for the node that was dropped without one.
        self.freeRelay();
        // The walk above already applied `destroy`'s own test — every entry
        // with `!entry.conn.is_server` — to every entry there was, and
        // `removeConnection` swap-removes the entry it is handed
        // (`vendor/quic/src/quic/connection_manager.zig:447`), so there is
        // nothing left for `destroy` to refuse on. Checked rather than
        // assumed: an entry that survived the walk would have the bridge
        // freed and the seed zeroed under a live handshake.
        for (self.bridge.manager.entries.items) |entry| {
            std.debug.assert(entry.conn.is_server);
        }
        self.dialer.destroy() catch |err| switch (err) {
            error.DialedConnectionsLive => std.debug.panic(
                "a dialled connection is live at teardown: {t}",
                .{err},
            ),
        };
        self.bridge.destroy();
        self.gpa.free(self.egress);
        self.gpa.free(self.out);
        self.gpa.free(self.scratch);
        self.gpa.free(self.buf);
        self.map.deinit(self.gpa);
        self.offered.deinit(self.gpa);
        self.dialled.deinit(self.gpa);
        self.timers.deinit(self.gpa);
        self.shutdownSocket();
        self.config.secret.deinit();
        self.gpa.destroy(self);
    }

    /// The node id this node presents, which is the id a peer dials it by.
    pub fn nodeId(self: *const Node) NodeId {
        return self.bridge.nodeId();
    }

    /// Where the node's socket is bound, with the ephemeral port the kernel
    /// wrote in. A peer is dialed at this address.
    pub fn address(self: *const Node) SocketAddr {
        return self.socket.address;
    }

    /// A borrowed generator valid until `deinit`. Copies advance the same engine.
    ///
    /// Named for what it is and not `random`, because every seam below takes
    /// its generator as a parameter called `random` and a declaration by that
    /// name would shadow all of them.
    pub fn generator(self: *Node) std.Random {
        return self.engine.random();
    }

    /// How many connections the core holds that have finished a handshake.
    ///
    /// Read rather than counted, because "the handshake completed" is a fact
    /// about the core and counting it here would be a second answer to a
    /// question `Conn.established` already answers.
    pub fn establishedCount(self: *const Node) usize {
        var count: usize = 0;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.established()) count += 1;
        }
        return count;
    }

    /// The peers the gossip layer named in its most recent actions, oldest
    /// first. See `named_ring`.
    /// The slice borrows this node and changes when later actions name peers.
    pub fn namedPeers(self: *const Node) []const NodeId {
        return self.named[0..self.named_len];
    }

    /// Dial every peer the configuration names, once, and tell the gossip
    /// layer to join them.
    ///
    /// Not part of `create`: a dial needs an instant and a generator, and
    /// `create` has a seed rather than either. Upstream dials from
    /// `Endpoint::connect`, after the endpoint exists; this draws the line
    /// where the instant is available, which is the same line.
    ///
    /// Idempotent, so `run` may call it every pass: a peer already attempted
    /// is skipped, whether the dial worked or not, and the join command is fed
    /// once.
    ///
    /// **A `start` that failed has not joined, and the next one tries again.**
    /// The latch is set once the command has been fed, so a refusal — the
    /// length check, a clock this node cannot use, or an allocator that gave
    /// out inside `feedGossip` — leaves a node willing rather than latched into
    /// a success that joined nothing. Re-arming says the caller *may* try, not
    /// that a retry is safe: what a failed `feedGossip` left in the gossip
    /// layer is not promised to be replayable (`step`'s own rule), and `run`
    /// and the binary's own loop both answer a failed `start` by leaving the
    /// loop rather than by calling it again. A caller driving `start` itself
    /// owns that choice — try once more, or close the node and throw it away.
    pub fn start(self: *Node, at: Instant, random: std.Random) Error!void {
        for (self.config.peers) |peer| {
            if (self.dialled.contains(peer.id)) continue;
            try self.dialled.put(self.gpa, peer.id, {});
            const reached = self.dialer.dial(
                peer.addr,
                peer.id,
                self.socket.address,
                &self.map,
                at,
                random,
            ) catch |err| {
                // A peer that cannot be reached is a fact about the network and
                // not a refusal to start: the node keeps running with the peers
                // it did reach, and the count is what a caller reads. The dial
                // is recorded as attempted either way, which is why this node
                // does not retry it — see `Config.peers`.
                self.stats.dials_refused += 1;
                std.log.warn("node: {f} was not reached: {t}", .{ peer.id, err });
                continue;
            };
            // On a direct dial the address the core was told is the target's
            // own, and a relay or a custom target resolves to a synthetic RFC
            // 4193 address — which is the whole of what `resolveRoute` does
            // (`dial.zig`'s module doc), and a node that remembered the
            // target's own address here would be remembering a fact nothing
            // downstream holds.
            switch (peer.addr) {
                .ip => |target| std.debug.assert(reached.route.socket.order(target) == .eq),
                .relay, .custom => {},
            }
            self.stats.dials += 1;
        }
        if (self.joined) return;
        // Checked before the list is built rather than left to `Peers.init`,
        // which would refuse the same length one line later with the list
        // already half filled.
        if (self.config.peers.len > hyparview.max_bootstrap) {
            return error.BootstrapListTooLong;
        }
        // The command is fed even when no peer was named: an empty list means
        // "be ready to be asked", which is how upstream's bootstrap node starts
        // (`hyparview.Command`'s own doc).
        var ids: [hyparview.max_bootstrap]NodeId = undefined;
        for (self.config.peers, 0..) |peer, index| {
            ids[index] = peer.id;
        }
        try self.feedGossip(.{
            .command = .{ .join = try hyparview.Peers.init(ids[0..self.config.peers.len]) },
        }, try gossipNow(at));
        // Set after the feed and not before it: a latch set here is what made
        // a refused `start` a success on the next call, over a node that had
        // joined nothing and would never be told otherwise.
        self.joined = true;
    }

    /// One pass, and the whole of the loop short of a clock.
    ///
    /// Receive input, free earlier dead entries, admit and drive accepts, run
    /// the relay, send output, expire connections, and run gossip timers.
    /// Connections that expire remain allocated until the next sweep.
    ///
    /// `at` and `random` are the caller's, for `quic_bridge.zig`'s reason: the
    /// same node driven twice at two instants with two generators is two
    /// nodes' worth of answers, and that is what lets the test below drive a
    /// whole connection without a clock.
    ///
    /// **A failed pass is a node to be closed, not a pass to be replayed.**
    /// Each seam consumes before it can fail. A datagram `take` took is gone
    /// from the socket whether the core took it or refused it, and a gossip
    /// timer `gossip` has already taken out of `self.timers` by the time
    /// `feedGossip` propagates the failure that produced it. So a caller that
    /// answers a failed `step` by running the same pass again is replaying an
    /// event this node has already acted on, and nothing here promises that is
    /// safe. The two honest answers are `close` — which is what `run` does on
    /// its own error path, and which abandons the gossip layer rather than
    /// rewinding it — and throwing the node away.
    ///
    /// `error.Canceled` is forwarded from the runtime. Like other failed
    /// passes, cancellation requires the caller to close the node.
    ///
    /// **A pass on a node whose `close` returned fails in `take`.** `close` shuts
    /// the descriptor without resetting it, so the read `take` opens with is on
    /// a handle this node no longer owns: `Socket.tryReceive` answers
    /// `error.Unexpected`, which is what it maps every errno it does not name,
    /// and `take` propagates it. A pass *between* a close that stopped in
    /// `closing_endpoint` and the close that finishes it is a different case
    /// and an ordinary call — the machine is mid-shutdown and the descriptor is
    /// open — and either way the relay pass belongs to a node that is going
    /// away, so both halves of it refuse the pass outright on the shutdown
    /// phase (`serve` and `converse`).
    pub fn step(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        self.stats.steps += 1;
        var moved = try self.take(io, at, random);
        // The sweep sits between the drain and the intake, and where it sits is
        // load-bearing rather than tidy. A connection that ended during this
        // pass's timers is already out of the core's table, so its `ConnEntry`
        // is dead — and `admit` walks that table by index, so a sweep after it
        // would leave the walk reading an entry the core had already taken out.
        // Sweeping here frees the dead entries and hands back a dense table,
        // which is what `Conn.drain` documents as the contract for a handle.
        // The relay sits here for the reasons the module doc gives: after the
        // accepts so a connection that only just handshaked may be named, and
        // before `drain` so a frame written now goes on the wire now.
        self.bridge.sweep();
        moved = try self.admit(io, at, random) or moved;
        moved = try self.drive(io, at, random) or moved;
        moved = try self.relay(at, random) or moved;
        moved = try self.drain(io, at, random) or moved;
        moved = try self.expire(io, at, random) or moved;
        moved = try self.gossip(at) or moved;
        return moved;
    }

    /// Block until the socket has something, or `timeout_ms` passes.
    ///
    /// A datagram this takes is parked in `held` rather than dropped, because
    /// the kernel has already handed it over and `take` cannot ask for it
    /// again. The timeout is what wakes the loop for gossip timers on an idle
    /// socket, and it also bounds how long a stop signal waits to be seen:
    /// `Socket.awaitReadable` retries a signal rather than letting it out, so
    /// a stop is acted on at the next timeout and not at the next datagram.
    ///
    /// `error.Canceled` is forwarded. The socket checks `io` before its
    /// syscalls, but runtime cancellation alone does not wake its raw poll.
    /// `Socket.stop` wakes it; a finite timeout bounds the next check.
    /// `run` closes the node on cancellation. A caller driving passes itself
    /// must do the same.
    pub fn wait(self: *Node, io: std.Io, timeout_ms: i32) Error!void {
        if (self.held != null) return;
        const got = self.socket.receive(
            io,
            self.buf,
            &self.control,
            timeout_ms,
        ) catch |err| switch (err) {
            // A poll that timed out is not a failure: the loop's own tick is
            // the only reason to wake with nothing.
            error.WouldBlock => return,
            else => return err,
        };
        self.held = got;
    }

    /// Wind the node down, in the order `router.Shutdown` enforces.
    ///
    /// Every step of that machine answers the event that drove it, so a close
    /// from `.serving` is one pass; `finish` is what the rest of it looks like.
    ///
    /// **It resumes rather than refusing.** A close that stopped part way — a
    /// send that failed in `close_endpoint`, the one step that needs a runtime —
    /// leaves the machine in `.closing_endpoint` with the descriptor open, and
    /// the next `close` picks that phase up and finishes it. So a caller that
    /// gets an error out of a close knows two things: which send failed, and
    /// that a later close with a working socket will complete the shutdown.
    /// `run` does not rely on that — its error path ends in `dispose`, which
    /// cannot fail.
    ///
    /// **What it guarantees on return is the machine at `.closed`**: the
    /// handler's own state released, every accept task cancelled, the
    /// descriptor shut. A return is only reached there, because every other
    /// exit is an error the caller has been handed.
    ///
    /// **This is `run`'s close, and a caller picks one or the other.**
    /// `run` closes on its way out, so a `close` after it is the no-op the
    /// `.closed` phase makes it. Calling `close` on a node a `run` is passing
    /// right now is a re-entry into the pass driving the machine; `Node` says
    /// what that means.
    ///
    /// **`error.Canceled` leaves the phase it reached, not a lost node.** The
    /// resume above is what a later `close` picks up, so an `Io` that cancels
    /// one close does not need to cancel the next; `run` is the caller that
    /// turns either answer into a disposal before it returns.
    pub fn close(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!void {
        if (self.accept.shutdown.phase == .closed) return;
        try self.finish(io, at, random);
    }

    /// Drive the shutdown out of whatever phase it is in, feeding each phase
    /// what it is waiting for until it reaches `closed`.
    ///
    /// **`close` resumes rather than refusing, and this is why.** A close that
    /// stopped part way — a send that failed in `close_endpoint` — leaves the
    /// machine in `closing_endpoint` with the descriptor open, and returning
    /// there because the phase is no longer `serving` would leave a node nothing
    /// could ever finish. So one iteration per phase, each feeding that phase
    /// its own event, which is what `max_close_steps` bounds.
    ///
    /// One phase is different: the machine emits `close_endpoint` on the event
    /// before it and never twice, so a close resumed at `closing_endpoint` is
    /// performing the action that failed rather than being told it is owed.
    fn finish(self: *Node, io: ?std.Io, at: ?Instant, random: std.Random) Error!void {
        var steps: usize = 0;
        while (self.accept.shutdown.phase != .closed) {
            std.debug.assert(steps < max_close_steps);
            steps += 1;
            switch (self.accept.shutdown.phase) {
                .serving => try self.feed(io, .close_requested, at, random),
                .draining_handlers => try self.feed(io, .handler_finished, at, random),
                .cancelling_accepts => try self.feed(io, .accepts_cancelled, at, random),
                .closing_endpoint => {
                    // The one phase whose action can have failed. The machine
                    // emits `close_endpoint` on the event before this phase and
                    // never emits it twice, so it is performed again here
                    // unless the flag says it already completed — which is the
                    // difference between a close that is progressing and one
                    // that is being resumed.
                    if (!self.endpoint_closed) {
                        const owed = try self.performShutdown(
                            io,
                            .{ .action = .close_endpoint, .panicked = null },
                            at,
                            random,
                        );
                        // The one answer this action has. Asserted rather than
                        // read: a second one would mean the machine and this
                        // loop disagree about what advances the phase.
                        std.debug.assert(owed != null);
                        std.debug.assert(std.meta.activeTag(owed.?.event) == .endpoint_closed);
                    }
                    try self.feed(io, .endpoint_closed, at, random);
                },
                .closed => unreachable,
            }
        }
    }

    /// The shutdown with nothing graceful left to do: no runtime, no instant,
    /// and so no connection closes — the handler released, every accept reaped,
    /// the descriptor shut, the machine at `closed`.
    ///
    /// **This is the backstop behind `run`'s promise**, and `run` reaches it
    /// two ways: a clock it never read, and a graceful close it could not
    /// perform. What it gives up is not reportable — it sends nothing, so there
    /// is no error and no count — and what it does not give up is local:
    /// `deinit` finds a closed endpoint, a lease that reports it, and the core
    /// connections its own walk already handles.
    ///
    /// It cannot fail. With no `Io` to ask and no instant to stamp, every step
    /// is a counter or a call into this node's own state, so an error here would
    /// be a claim this file cannot make. It panics rather than leave a
    /// half-disposed node behind a swallowed error.
    fn dispose(self: *Node) void {
        self.finish(null, null, self.generator()) catch |err| std.debug.panic(
            "a shutdown with no runtime and no instant failed: {t}",
            .{err},
        );
        std.debug.assert(self.accept.shutdown.phase == .closed);
        std.debug.assert(!self.socket_open);
    }

    /// The loop, with a clock. `stop` ends it, and the node is closed either
    /// way.
    ///
    /// **The node is closed on every exit, and the promise covers the exits
    /// this loop did not choose.** A pass can fail — a socket write the `Io`
    /// refuses, a bridge that would not allocate, a `checkCancel` answered with
    /// `error.Canceled` — and the `errdefer` below is what closes the node then.
    /// It is registered *before* the first clock read, because `create` has
    /// already opened the descriptor and a clock this node cannot use is an exit
    /// like any other.
    ///
    /// **The error the loop failed with is what `run` returns.** A close that
    /// fails as well is reported at error level beside it and never in place of
    /// it: a caller that asked to be cancelled has to hear `error.Canceled` and
    /// not the residue of cleaning up after it. `windDown` is that close and
    /// `dispose` is the backstop behind it.
    ///
    /// **The instant this loop reads is the instant the close is stamped
    /// with.** A peer driven on a clock of its own — a test's virtual one —
    /// reads close times from a timeline this loop is not on, and waits out its
    /// own retransmit timeout to believe one. Two ends of a connection on two
    /// clocks are two nodes' worth of answers, which is `step`'s rule and this
    /// loop's.
    ///
    /// The stop is checked once per pass, before the pass rather than after it,
    /// so a signal that lands while `wait` is inside `poll` costs at most
    /// `poll_interval_ms` — the same bound `Socket.awaitReadable` names.
    ///
    /// One thread, one `run`, and never from a signal handler. See `Node`.
    pub fn run(self: *Node, io: std.Io, stop: *const Stop) Error!void {
        // The instant of the pass being run, and null until one has been read.
        // A close needs an instant to stamp a connection close with and a
        // disposal does not, which is what makes this the right type for the
        // register below rather than a plain `Instant`.
        var at: ?Instant = null;
        errdefer self.windDown(io, at);
        var dialled = false;
        while (true) {
            const now = try instantOf(io);
            at = now;
            if (stop.expired(now)) {
                // The break is taken on a pass that read a clock, so this close
                // carries the instant it stamps its connection closes with.
                try self.close(io, now, self.generator());
                break;
            }
            // The dials happen on the first pass rather than in the caller, so
            // that a stop raised before the loop is entered closes a node that
            // never dialled anything — which is what `start` is idempotent
            // for. A caller that dials before `run` reaches the same state, and
            // this line costs nothing.
            if (!dialled) {
                dialled = true;
                try self.start(now, self.generator());
            }
            // The pass's own answer is not read here. A poll loop has one tick,
            // and whether the tick moved anything changes what the caller may
            // do next rather than how long this loop waits; `step`'s `bool` is
            // for a caller driving passes itself, which is what the test at the
            // bottom of this file is.
            _ = try self.step(io, now, self.generator());
            try self.wait(io, poll_interval_ms);
        }
    }

    /// The close a failed `run` owes: a graceful one where there is an instant
    /// to stamp it with, and the disposal behind it in every case.
    ///
    /// **The graceful half runs with cancellation protection switched on**
    /// (`std.Io.CancelProtection`), which is the runtime's own answer to
    /// "finish this": every `Io` call inside it stops being a cancellation
    /// point, so this file does not have to guess which of its calls a backend
    /// consults. The previous setting is restored on the way out.
    ///
    /// It is bounded — one step per shutdown phase, one pass over the
    /// connection table, one `sendmsg` per egress run, no wait — and it runs
    /// after the error that ended the loop has already been decided. Whatever
    /// it cannot finish is handed to `dispose`, which is the only part of this
    /// that cannot fail.
    fn windDown(self: *Node, io: std.Io, at: ?Instant) void {
        if (at) |stamp| {
            const protection = io.swapCancelProtection(.blocked);
            defer _ = io.swapCancelProtection(protection);
            self.close(io, stamp, self.generator()) catch |err| std.log.err(
                "node {f} could not be closed gracefully after its loop ended: {t}",
                .{ self.bridge.nodeId(), err },
            );
        }
        if (self.accept.shutdown.phase != .closed) self.dispose();
    }

    // -- the transport ------------------------------------------------------

    /// Take everything the kernel has queued and hand it to the core.
    fn take(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        // The datagram `wait` took goes first: the kernel gave it over and
        // `tryReceive` will never see it again.
        if (self.held) |got| {
            self.held = null;
            try self.deliver(io, got, at, random);
            moved = true;
        }
        while (true) {
            const got = self.socket.tryReceive(
                io,
                self.buf,
                &self.control,
            ) catch |err| switch (err) {
                // Non-blocking from the moment the socket existed, so an empty
                // queue is a fact the loop acts on rather than a stall.
                error.WouldBlock => break,
                else => return err,
            };
            try self.deliver(io, got, at, random);
            moved = true;
        }
        return moved;
    }

    /// One read, which may be a burst coalesced by `UDP_GRO`, through the core.
    fn deliver(
        self: *Node,
        io: std.Io,
        got: socket_mod.Received,
        at: Instant,
        random: std.Random,
    ) Error!void {
        // A read is not one datagram: `UDP_GRO` may have coalesced a burst into
        // one buffer, so the stride is what says how many packets there are and
        // the core is handed them one at a time. `Bridge.recv` takes a single
        // datagram because the core's reply borrows the buffer it was written
        // into.
        const recv = try got.toRecv();
        self.stats.datagrams_in += recv.datagramCount();
        // The walk ends where `datagram` answers null, which is the same place
        // `datagramCount` would have ended it: the accessor goes null at
        // `divCeil(len, stride)` and that is what the count is. One fact about
        // the buffer, asked once, and no assertion that the accessor and the
        // count still agree.
        var position: usize = 0;
        while (recv.datagram(position)) |datagram| : (position += 1) {
            const ingress = try self.bridge.recv(&self.map, .{
                .bytes = datagram,
                .from = got.from,
                .local = self.socket.address,
                .ecn = recv.ecn,
            }, self.scratch, at, random);
            switch (ingress.outcome) {
                // A connection this datagram made or advanced is in the core's
                // table, and `admit` and `drive` both walk that table.
                .processed => {},
                // A stateless reply is a send, back out of the same socket to
                // the address the datagram came from.
                .reply => |reply| {
                    self.stats.datagrams_out += reply.datagramCount();
                    self.note(try self.socket.send(io, ingress.source.socket, reply));
                },
                .dropped, .foreign => {},
            }
        }
    }

    /// Give the endpoint every accepted connection it has not been told about.
    ///
    /// A dialled connection is not an attempt: this node asked for it and
    /// already knows who the peer is, which is what `Endpoint::accept` never
    /// returns. So the walk is over server-side connections only, and the
    /// filter sees exactly what a remote peer sent.
    fn admit(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (!conn.entry.conn.is_server) continue;
            if (self.offered.contains(conn.id())) continue;
            try self.offered.put(self.gpa, conn.id(), {});
            const peer = conn.peer() orelse continue;
            self.stats.attempts += 1;
            try self.feed(io, .{
                .arrived = .{
                    .id = conn.id(),
                    .remote = peer,
                    .local = self.socket.address,
                    .classification = base_ula.classify(peer),
                    // Unproved, and the honest value: the bridge reports no
                    // per-flow address validation, and a flow that had proved its
                    // address is the one the core's own `require_retry` already
                    // knows about. With no filter registered every attempt is
                    // accepted anyway (`incoming_filter.ask` on a null filter), so
                    // this field is read only by a caller that registers one.
                    .validation = .unvalidated,
                },
            }, at, random);
            moved = true;
        }
        return moved;
    }

    /// Walk every accept task, and run each one as far as it can go.
    ///
    /// Upstream spawns a task per accept (`protocol.rs:601-603`) and the loop
    /// reads them off a `JoinSet`. Here the table is the endpoint's own and
    /// this is the walk: a task is a value, so driving it is one
    /// `router.dispatchStep` and one report, in this pass rather than in a
    /// thread of its own.
    fn drive(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        var index: usize = 0;
        while (index < self.accept.live) {
            const id = self.accept.tasks[index].id;
            const conn = self.connFor(id) orelse {
                // The core took it out of its table, so the future this task was
                // running for has returned: upstream's `join_next` arm for a
                // connection that ended (`protocol.rs:558-560`). `forget` frees
                // the slot and moves the last task into the hole, so `index`
                // must not advance.
                try self.feed(io, .{
                    .reaped = .{ .id = id, .ended = .finished },
                }, at, random);
                moved = true;
                continue;
            };
            if (!self.runTask(&self.accept.tasks[index], conn)) {
                index += 1;
                continue;
            }
            try self.feed(io, .{
                .reaped = .{ .id = id, .ended = .finished },
            }, at, random);
            moved = true;
        }
        return moved;
    }

    /// Move one accept task as far as it can go, and say whether it is done.
    ///
    /// A task's steps are the handshake producing an ALPN, the handler's
    /// `on_accepting`, and the handler's `accept`. Every one of them is a call
    /// this node makes itself, so the whole of a task runs inside one pass;
    /// the only thing it waits for between passes is the handshake, and that is
    /// `conn.established()`.
    fn runTask(self: *Node, task: *endpoint.Task, conn: Conn) bool {
        if (!conn.established()) return false;
        var event: router.ConnEvent = .{
            .outcome = .{ .alpn = conn.entry.conn.negotiatedAlpn() },
        };
        while (true) {
            const stepped = router.dispatchStep(&self.table, task.state, event);
            task.state = stepped.state;
            switch (stepped.action) {
                .await_handshake => {
                    // The handshake is done, which is all this action awaited;
                    // reporting the connection is what moves the machine on.
                    event = .{ .outcome = .{ .connection = .{ .ptr = @ptrCast(self) } } };
                },
                // Unreachable for this node: its handler registers no
                // `on_accepting`, so `negotiatingStep` answers `.alpn` with
                // `.await_handshake` instead. The arm is here because the
                // switch is exhaustive over a public union and a second
                // protocol would land in it.
                .on_accepting => |chosen| {
                    // The action carries a handler that has one — that is the
                    // only way `negotiatingStep` emits it.
                    const call = chosen.on_accepting orelse unreachable;
                    event = .{ .outcome = if (call(
                        chosen.ptr,
                        .{ .ptr = @ptrCast(self) },
                    )) |connection|
                        .{ .connection = connection }
                    else |err|
                        .{ .failed = .{ .accepting = err } } };
                },
                .accept => |chosen| {
                    event = .{ .outcome = if (chosen.accept(
                        chosen.ptr,
                        .{ .ptr = @ptrCast(self) },
                    )) |_|
                        .finished
                    else |err|
                        .{ .failed = .{ .accept = err } } };
                },
                // Terminal: the handler is done or the connection is gone, and
                // the caller reaps the task.
                .release, .drop => return true,
                // A state this walk cannot be in. `runTask` is entered from
                // `.negotiating` and runs a task to one of the terminal arms
                // above inside the call, so an action from any other state
                // means the loop handed over a task it had already driven.
                .negotiate_alpn, .send_retry, .refuse, .ignore, .none => return false,
            }
        }
    }

    /// Write out everything the core wants sent, then run its timers.
    fn drain(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, random)) |egress| {
                self.stats.datagrams_out += egress.send.datagramCount();
                self.note(try self.socket.send(io, egress.to, egress.send));
                moved = true;
            }
        }
        return moved;
    }

    /// Run the core's timers, and report every connection they finished.
    ///
    /// A connection that ended is two things: a `join_next` upstream's loop
    /// reads for a task it holds, and a `peer_disconnected` for the gossip
    /// layer, which is how membership hears about it at all.
    fn expire(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| {
            if (self.bridge.tick(conn, at, random) == .live) {
                index += 1;
                continue;
            }
            // `tickEntry` swap-removed the entry it was given
            // (`connection_manager.zig:711-713`), so whatever was last is now
            // at `index` and the walk must not step past it.
            self.stats.connections_finished += 1;
            moved = true;
            if (self.accept.task(conn.id()) != null) {
                try self.feed(io, .{
                    .reaped = .{ .id = conn.id(), .ended = .finished },
                }, at, random);
            }
            // Which peer this was. A synthetic address names the node it stands
            // for and the map remembers which, while a direct path names nobody
            // (`dial_mod.ownerOf`'s own doc), so a relayed peer reaches the
            // gossip layer as `peer_disconnected` and a direct one does not.
            // That is a limit on what this file knows and not a claim about
            // what membership needs.
            const peer = conn.peer() orelse continue;
            const key = dial_mod.ownerOf(&self.map, peer) orelse continue;
            const owner: NodeId = switch (key) {
                .any_path => |node| node,
                .relay => |via| via.node,
                // A custom key is a node id and its own bytes, and the map
                // allocates it from the node it belongs to
                // (`addr_map.CustomKey`'s own doc) — but the id is not stored,
                // so the owner is not recoverable from it.
                .custom => continue,
            };
            try self.peerGone(owner, at);
        }
        return moved;
    }

    /// One turn of the gossip layer.
    ///
    /// This is the long-lived loop the milestone is about. The wire test
    /// converges in a bounded number of rounds because it is a test
    /// (`test/protocol_loopback_test.zig`, `max_rounds = 512`), and a node
    /// keeps going: nothing here counts rounds, and the timers membership
    /// asked for are the only thing that decides when this runs again.
    fn gossip(self: *Node, at: Instant) Error!bool {
        var moved = false;
        const now = try gossipNow(at);
        // In the order they were asked for, so a node that has been idle wakes
        // up on the same schedule every time.
        var position: usize = 0;
        while (position < self.timers.items.len) {
            if (self.timers.items[position].due > now) {
                position += 1;
                continue;
            }
            const due = self.timers.orderedRemove(position);
            self.stats.gossip_timers_fired += 1;
            moved = true;
            try self.feedGossip(.{ .timer_expired = due.timer }, now);
        }
        return moved;
    }

    /// Hand one event to the gossip layer and do what it asks for.
    fn feedGossip(self: *Node, event: hyparview.InEvent, now: hyparview.Nanos) Error!void {
        var out: hyparview.Actions(hyparview.OutEvent) = .init(self.gpa);
        defer out.deinit();
        try self.topic.handle(event, now, &out);
        self.stats.gossip_events += 1;
        for (out.slice()) |produced| switch (produced) {
            // **Not wired.** The gossip wire format does not exist in this
            // project — `gossip/hyparview.zig` says of itself that it has no
            // codec, and the only encoder here is a test's. So the request is
            // counted, split by the layer that asked, and the peer is named;
            // nothing is sent. See the module doc.
            .send_message => |send| {
                self.noteNamed(send.to);
                switch (send.message) {
                    .swarm => self.stats.gossip_membership_asked += 1,
                    .gossip => self.stats.gossip_broadcast_asked += 1,
                }
            },
            .schedule_timer => |schedule| {
                self.stats.gossip_timers_scheduled += 1;
                try self.timers.append(self.gpa, .{
                    .due = now + schedule.after,
                    .timer = schedule.timer,
                });
            },
            // Also not wired, for the same reason: a `disconnect_peer` names a
            // node, and this node finds a connection by an address the map or
            // the dialer holds, never by an id. Counting it is the honest
            // report; tearing a connection down by node id belongs with the
            // codec, which is what would have carried the message the state
            // machine is asking to be believed about.
            .disconnect_peer => |peer| {
                self.stats.gossip_disconnects_asked += 1;
                self.noteNamed(peer);
            },
            .emit_event => switch (produced.emit_event) {
                .neighbor_up => self.stats.neighbor_up += 1,
                .neighbor_down => self.stats.neighbor_down += 1,
                .received => self.stats.broadcasts_received += 1,
            },
            .peer_data => self.stats.peer_data_seen += 1,
        };
    }

    /// Tell the gossip layer a peer went away, which is how membership is told
    /// anything at all in this project: there is no `Disconnect` message on the
    /// wire, because there is no wire.
    fn peerGone(self: *Node, peer: NodeId, at: Instant) Error!void {
        try self.feedGossip(.{ .peer_disconnected = peer }, try gossipNow(at));
    }

    // -- the accept loop, performed ----------------------------------------

    /// Feed one event to the accept loop and perform everything it answers
    /// with.
    ///
    /// The loop is a function of `(state, event)` and answers with one action,
    /// so the caller performs the action and reports the event the action is
    /// answered with. Some actions owe more than one report, which is what
    /// `Answer.count` is for.
    fn feed(
        self: *Node,
        io: ?std.Io,
        first: endpoint.Event,
        at: ?Instant,
        random: std.Random,
    ) Error!void {
        var pending: [max_pending_events]endpoint.Event = undefined;
        var count: usize = 1;
        var head: usize = 0;
        pending[0] = first;
        while (head < count) : (head += 1) {
            const stepped = self.accept.step(pending[head]);
            self.accept = stepped.loop;
            const owed = (try self.perform(io, stepped.action, at, random)) orelse continue;
            var index: usize = 0;
            while (index < owed.count) : (index += 1) {
                std.debug.assert(count < pending.len);
                pending[count] = owed.event;
                count += 1;
            }
        }
    }

    /// Perform one action the endpoint owes, and say what it is answered with.
    ///
    /// This is the caller `endpoint.zig` says it is waiting for, and the two
    /// operations it deliberately leaves out of its own signature are here:
    /// `spawn` and `cancel_accepts`.
    fn perform(
        self: *Node,
        io: ?std.Io,
        action: endpoint.Action,
        at: ?Instant,
        random: std.Random,
    ) Error!?Answer {
        switch (action) {
            // Two datagrams' worth of steps for one arrival: ask the filter, and
            // report its answer as `Event.filtered` (`protocol.rs:568-574`).
            .offer => |incoming| {
                // No filter, which is upstream's `Option<IncomingFilter>` set
                // to `None`: `incoming_filter.ask` answers `.accept` for every
                // attempt (`connection.rs:148`). A caller that wants one
                // registers it on the `Loop`.
                return .{ .event = .{
                    .filtered = incoming_filter.ask(null, incoming),
                } };
            },
            .spawn => |task| {
                // Upstream `join_set.spawn` (`protocol.rs:601-603`). The slot
                // is the endpoint's own — `spawn` wrote it before handing the
                // action over — so what is performed is the drive, which
                // `drive` does on the next pass, or this one if the handshake is
                // already through.
                self.stats.spawned += 1;
                std.debug.assert(self.accept.task(task.id) != null);
                return null;
            },
            // Upstream's `incoming.retry()` (`protocol.rs:583`) has no call in
            // this stack to reach: the vendored core decides Retry from two
            // manager-wide fields inside the call that accepts the connection
            // (`vendor/quic/src/quic/connection_manager.zig:606-647`), so a
            // verdict made by application code arrives after the point at which
            // RFC 9000 §17.2.5 permits one. `endpoint.zig` refuses every retry
            // for that reason and maps `.send_retry` to `.refuse`, so the arm
            // that recorded this node's half of a retry that was never sent is
            // gone with it rather than left reading zero.
            .refuse => {
                self.stats.refusals += 1;
                return null;
            },
            .ignore => {
                self.stats.ignores += 1;
                return null;
            },
            .shutdown => |owed| return try self.performShutdown(io, owed, at, random),
            .none => return null,
        }
    }

    /// The shutdown, in the order `router.Shutdown` enforces: the handlers,
    /// then the cancel, then the close.
    ///
    /// Each phase is performed and then reported, so the ordering is not a
    /// comment but a sequence this function has to get right — a cancel issued
    /// while a handler is still shutting down is a use-after-free
    /// (`router.zig:642-650`).
    fn performShutdown(
        self: *Node,
        io: ?std.Io,
        owed: endpoint.ShutdownStep,
        at: ?Instant,
        random: std.Random,
    ) Error!?Answer {
        if (owed.panicked) |reaped| std.log.err(
            "node: accept task {d} failed and started the shutdown",
            .{reaped.id},
        );
        switch (owed.action) {
            // Upstream awaits one future per registered handler
            // (`protocol.rs:404-407`) before anything is cancelled. None of them
            // is a future here, so they are called in one pass and each is
            // reported: the machine counts handlers, and it only emits the
            // cancel when the count reaches zero.
            .shutdown_handlers => |count| {
                var distinct: usize = 0;
                for (self.table.entries, 0..) |entry, index| {
                    if (namedBefore(self.table.entries[0..index], entry.alpn)) continue;
                    distinct += 1;
                    const shut = entry.handler.shutdown orelse continue;
                    shut(entry.handler.ptr);
                }
                std.debug.assert(distinct == count);
                return .{ .event = .handler_finished, .count = count };
            },
            // Upstream `handler_cancel_token.cancel()` (`protocol.rs:611`).
            // An accept here is a value in the loop's own table and the thing
            // that would have been cancelled is the handler state on that
            // connection, so cancelling means reaping every task — and every
            // task has already been driven to its end by `drive`, which is why
            // there is nothing running here to interrupt.
            .cancel_accepts => {
                var index = self.accept.live;
                while (index > 0) {
                    index -= 1;
                    const id = self.accept.tasks[index].id;
                    const stepped = self.accept.step(.{
                        .reaped = .{ .id = id, .ended = .cancelled },
                    });
                    self.accept = stepped.loop;
                    // A reap in this phase is the live count going down and
                    // never advances the machine. Asserted rather than ignored,
                    // because an advance here would skip the close.
                    std.debug.assert(stepped.action == .none);
                    std.debug.assert(self.offered.remove(id));
                    self.stats.accepts_cancelled += 1;
                }
                return .{ .event = .accepts_cancelled };
            },
            // Upstream `endpoint.close()` (`protocol.rs:613`), which
            // force-closes whatever the accepts left. This node's endpoint is
            // its socket and the connections the core holds, so both go:
            // `closeConnections` stamps and writes, and `shutdownSocket`
            // releases the descriptor.
            //
            // **The descriptor is released on every path and the connections
            // only where there is an instant to stamp them with.** A null
            // instant is the disposal path — `dispose` is its only caller — and
            // a connection close is the one thing here that needs a clock
            // reading. Those connections are then left to `deinit`'s own walk.
            // Releasing the descriptor is the part that cannot be deferred to
            // anything, so it is not.
            .close_endpoint => {
                if (io) |runtime| {
                    if (at) |stamp| try self.closeConnections(runtime, stamp, random);
                }
                self.endpoint_closed = true;
                self.shutdownSocket();
                return .{ .event = .endpoint_closed };
            },
            .none => return null,
        }
    }

    /// Stamp a close on every connection the core holds and write it out, so
    /// each peer is told rather than left to time out.
    ///
    /// **A failure here leaves the machine in `closing_endpoint` and the
    /// descriptor open**, and that is reported rather than papered over:
    /// `finish` re-performs this step on the next close, and `dispose` is the
    /// backstop behind both.
    fn closeConnections(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!void {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            conn.entry.conn.close(0, "", at);
            for (try conn.drain(self.egress, self.out, at, random)) |egress| {
                self.stats.datagrams_out += egress.send.datagramCount();
                self.note(try self.socket.send(io, egress.to, egress.send));
            }
        }
    }

    /// The handler the router dispatches to. One handler, registered under the
    /// one ALPN the bridge offers; see `max_alpns`.
    fn handler(self: *Node) router.ProtocolHandler {
        return .{
            .ptr = @ptrCast(self),
            // Null is upstream's default body: the router awaits the handshake
            // itself and reports the same two outcomes under the same log line
            // (`router.zig`'s `ProtocolHandler.on_accepting`).
            .on_accepting = null,
            .accept = acceptConnection,
            .shutdown = shutdownHandler,
        };
    }

    // -- the relay ----------------------------------------------------------

    /// One turn of the relay.
    ///
    /// Two roles and nothing else. Upstream's relay is a process and its client
    /// is a library call, and the difference between them is which half of one
    /// handshake a node runs. `.off` is every other node and touches nothing.
    ///
    /// Where this sits in `step` is the module doc's subject and the reason
    /// for every ordering inside it: the accept path a relay uses is the one
    /// this file already had, and none of it comes from a dial.
    fn relay(self: *Node, at: Instant, random: std.Random) Error!bool {
        return switch (self.config.relay.role) {
            .off => false,
            .serve => try self.serve(at, random),
            .client => try self.converse(at, random),
        };
    }

    /// A serving relay's pass, in the order its own work is ordered.
    fn serve(self: *Node, at: Instant, random: std.Random) Error!bool {
        const role = switch (self.config.relay.role) {
            .serve => |role| role,
            else => return false,
        };
        // A relay that is winding down admits nobody. Without this the
        // shutdown's own passes would re-admit the connections the next phase
        // is about to close, and every one of those would be reported as a
        // client arriving after the relay had already said it was going.
        if (self.accept.shutdown.phase != .serving) return false;
        var moved = try self.serveAdmit(at, random);
        moved = self.serveRelease() or moved;
        moved = try self.serveRead() or moved;
        moved = try self.serveQueues(role.drain_room) or moved;
        return moved;
    }

    /// Give every accepted connection the relay has not been told about a
    /// client, and start its handshake.
    ///
    /// The credential offered is `.none`, and that is not a shortcut. This
    /// transport has no TLS exporter for a peer whose certificate is a bare
    /// ed25519 key, so `relay/server.zig`'s key-material path cannot be taken
    /// and the challenge is the only way in — which is upstream's browser path,
    /// reached here for the same reason it is the honest one.
    ///
    /// **The challenge comes from `random`**, the generator this node is being
    /// driven with, and not from `Io.randomSecure`. A node that drew one
    /// admission challenge differently from the last could not be driven twice
    /// and compared, and that is the property this whole loop is built for.
    /// What it costs is real and is not hidden: a relay serving clients it has
    /// not met seeds its engine from `Io.randomSecure` when it is created, and
    /// a relay whose seed is known admits anyone who can guess it.
    fn serveAdmit(self: *Node, at: Instant, random: std.Random) Error!bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            // Server-side only, and established: this is the accept path, so a
            // connection this node asked for is never a client of it.
            if (!conn.entry.conn.is_server) continue;
            if (!conn.established()) continue;
            if (self.servedFor(conn.id()) != null) continue;
            // The relay opens the stream it speaks on and reads the one the
            // client opened. See `Served.out` for why they are two.
            //
            // **The slot is taken before the stream is opened, and that order
            // is what the refusal below survives on.** The core keeps every
            // stream this end opens in `conn.streams` (`stream.zig:1396-1404`)
            // and counts it against the peer's `initial_max_streams_bidi`
            // (`stream.zig:1387`). A credit comes back only from a stream whose
            // receive side the peer has closed (`connection.zig:2940-2946`),
            // and a stream opened for a client this relay then refuses is one
            // nothing will ever close. It is spent for good, and once a
            // connection has spent its peer's whole grant — a hundred
            // (`connection.zig:539`) — it refuses every open for the rest of
            // its life, with nothing but this arm's own counter to say so.
            // Asking for the slot first makes that unreachable: a stream is
            // opened exactly when there is somewhere to put it, so the open
            // streams and the occupied slots are one count and neither can
            // outrun the other.
            //
            // **A refusal that still arrives costs this connection and not the
            // pass.** The peer granted less than this end has used, and
            // `MAX_STREAMS` raises that grant (`connection.zig:2146`), so a
            // later pass gets a different answer. Failing the pass would take
            // down every *other* connection in the table over one that is out
            // of credit, and a relay that stopped serving for that would not
            // be a relay.
            //
            // Everything else is `error.CoreRefused` — an allocator that will
            // not make the core's send ledger above all — and it is propagated
            // rather than caught, because that is a fault in *this node* and a
            // relay that swallowed it would go on serving as though it had
            // admitted a client it never admitted. The split is the whole of
            // this arm; `error.NoStreamRoom` is named for it.
            const slot = self.freeClient() orelse {
                // Upstream refuses rather than drops, for the reason
                // `endpoint.zig` gives: an attempt accepted and then held
                // nowhere is a client that believes it is connected.
                self.stats.relay_refused += 1;
                continue;
            };
            const stream = bridge_mod.Stream.open(conn) catch |err| switch (err) {
                error.NoStreamRoom => {
                    self.stats.relay_stream_deferred += 1;
                    continue;
                },
                else => return err,
            };
            const owned = self.indexOf(slot);
            slot.* = .{
                .live = true,
                .conn = conn.id(),
                .queues = self.queuesOf(owned),
                .ring = self.ringOf(owned),
                .out = stream,
            };
            var challenge: [relay_frame.ServerChallenge.challenge_length]u8 = undefined;
            random.bytes(&challenge);
            _ = try self.serveHandshake(at, slot, .{ .offered = .{
                .credential = .none,
                .material = null,
                .challenge = .{ .challenge = challenge },
            } });
            moved = true;
        }
        return moved;
    }

    /// Run one client's handshake as far as that event lets it, and register
    /// it if the handshake is over.
    fn serveHandshake(
        self: *Node,
        at: Instant,
        slot: *Served,
        event: relay_server.Event,
    ) Error!bool {
        const stepped = relay_server.step(slot.handshake, event);
        slot.handshake = stepped.state;
        // Access control is this node's own answer and there is none to ask.
        // `.allow` means "the client proved it owns the node id it claims",
        // which is what the challenge's signature says; `Access` exists so an
        // operator can narrow that, and this node has no configuration field
        // for one yet. Named here rather than invented.
        const proved = switch (slot.handshake) {
            .authenticated => true,
            else => false,
        };
        if (proved) {
            const allowed = relay_server.step(slot.handshake, .{ .access = .allow });
            slot.handshake = allowed.state;
            _ = try self.serveAction(at, slot, allowed.action);
            self.serveRegister(slot);
            return true;
        }
        const served = try self.serveAction(at, slot, stepped.action);
        return served;
    }

    /// Write the one thing a relay handshake step asked for.
    fn serveAction(
        self: *Node,
        at: Instant,
        slot: *Served,
        action: ?relay_server.Action,
    ) Error!bool {
        const asked = action orelse return false;
        switch (asked) {
            .write => |message| {
                var stream: bridge_mod.Stream = slot.out;
                try writeRelay(&stream, self.relay_out, message);
                return true;
            },
            // Upstream drops the connection without writing. The connection is
            // closed at the core instead, which is what drops it: the relay
            // protocol's silence is the signal, and a CONNECTION_CLOSE is how
            // a QUIC peer is told there will be none.
            .close => {
                slot.ended = true;
                if (self.connFor(slot.conn)) |conn| conn.entry.conn.close(0, "", at);
                return true;
            },
        }
    }

    /// Put an authenticated client in the registry and take the handle that
    /// ends it.
    ///
    /// `Registry.admit` is the only way into the table and it hands the handle
    /// back, so a client cannot be admitted without one. That is invariant 10
    /// restated as a type, and it is why the guard is stored here and nowhere
    /// else.
    fn serveRegister(self: *Node, slot: *Served) void {
        const proof = switch (slot.handshake) {
            .admitted => |proof| proof,
            else => return,
        };
        slot.node_id = proof.node_id;
        const admitted = self.registry.admit(proof.node_id, slot.conn) catch |err| {
            // A registry with no slot left is a relay that has to shed
            // connections, and this is where it finds out.
            std.log.warn("node: the relay could not admit a client: {t}", .{err});
            self.stats.relay_refused += 1;
            return;
        };
        slot.guard = admitted.guard;
        self.stats.relay_admitted += 1;
        const replaced = switch (admitted.admit) {
            .fresh => return,
            .replaced => |id| id,
        };
        self.stats.relay_replaced += 1;
        // The displaced connection is told over its *control* queue, and that
        // is the whole reason there are two: a client whose datagram queue is
        // full is exactly the client that most needs to be told.
        const other = self.servedFor(replaced) orelse return;
        other.queues.control.push(.{ .status = .same_endpoint_id_connected }) catch {
            self.stats.relay_queue_full += 1;
            return;
        };
        self.stats.relay_told_displaced += 1;
    }

    /// Take everything the clients have sent, and act on it.
    fn serveRead(self: *Node) Error!bool {
        var moved = false;
        for (self.clients) |*slot| {
            if (!slot.live) continue;
            const conn = self.connFor(slot.conn) orelse continue;
            // The client's half arrives on the stream the *client* opened,
            // which this connection does not hold until the client has written
            // something on it — so it is looked up afresh every pass, and a
            // client that has not spoken yet is a client with nothing to read.
            //
            // Straight onto the inbox, with no buffer in between: the bytes go
            // there once instead of twice, and a read has no length to size a
            // buffer against. See `Stream.drain`.
            //
            // **`drain`'s answer is not "this stream is empty".** It says
            // whether it appended bytes and nothing about what came before
            // them, so a stream the peer ended on a frame boundary and one it
            // ended in the middle of a frame read the same. `discardTail` asks
            // the other half, and it is asked *after* the whole messages are
            // taken, because before that a full inbox is a message this relay
            // has not acted on yet.
            var incoming = conn.peerStream() orelse continue;
            moved = try incoming.drain(self.gpa, &slot.inbox) or moved;
            moved = try self.serveMessages(slot) or moved;
            if (discardTail(&slot.inbox, incoming.finished())) {
                self.stats.relay_stream_truncated += 1;
            }
        }
        return moved;
    }

    /// Every whole message in a client's inbox, acted on in turn.
    fn serveMessages(self: *Node, slot: *Served) Error!bool {
        var moved = false;
        var consumed: usize = 0;
        // Dropping what the walk has been over is one decision, taken on the
        // way out and on the fault alike. The `try` in the condition below
        // leaves this function without ever reaching the drop, so a walk that
        // only dropped on success would hand back every frame it had already
        // served for the next pass to serve again — the poison in front of a
        // datagram being the worst of it, because it refuses first.
        errdefer dropInbox(&slot.inbox, consumed);
        while (try peekFrame(slot.inbox.items, consumed, self.relay_scratch)) |found| {
            // The end before the meaning: `decode` is what can fail, and the
            // frame it fails on arrived whole, so it is spent either way.
            consumed = found.end;
            const message = try relay_frame.decode(found.frame, .v2);
            try self.serveMessage(slot, message);
            moved = true;
        }
        dropInbox(&slot.inbox, consumed);
        return moved;
    }

    /// One relay frame from a client.
    fn serveMessage(
        self: *Node,
        slot: *Served,
        message: relay_frame.Message,
    ) Error!void {
        switch (slot.handshake) {
            .opened, .challenged => {
                _ = try self.serveHandshake(0, slot, .{ .frame = message });
                return;
            },
            // Past admission the frames belong to the connection rather than to
            // the handshake, and `server.step` folds them in as nothing — so
            // they are read here rather than handed to a machine that has
            // already returned.
            else => {},
        }
        switch (message) {
            .client_to_relay_datagram, .client_to_relay_datagram_batch => |frame| {
                self.stats.relay_datagrams_in += 1;
                try self.forward(slot, frame);
            },
            .ping => |data| {
                var out: bridge_mod.Stream = slot.out;
                try writeRelay(&out, self.relay_out, .{ .pong = data });
            },
            // Everything else is a frame this relay has no use for, and the
            // reason is the direction rather than the message: a `.status` and
            // a `.health` are the relay's own one-way declarations about the
            // connection, and this end of the protocol has no frame in which to
            // declare anything — the two this relay sends are the
            // `.same_endpoint_id_connected` it queues for a displaced client
            // and the `.healthy` it queues for one that took over. A
            // `.restarting` names a wait before reconnecting, which is advice
            // to a client and not to the relay. And `.health` cannot arrive at
            // all: it is v1 only and `decode` is called with `.v2`.
            else => {},
        }
    }

    /// One datagram from a client, onto the queue of the client it names.
    fn forward(self: *Node, from: *Served, frame: relay_frame.DatagramFrame) Error!void {
        const src = from.node_id orelse return;
        const payload = frame.datagrams.contents;
        const destination = self.registry.activeConnectionId(frame.node_id);
        if (destination == null) {
            // Nobody holds that node id, and the frame that says so goes on the
            // *control* queue. See `serveRegister`.
            from.queues.control.push(.{ .peer_gone = frame.node_id }) catch {
                self.stats.relay_queue_full += 1;
                return;
            };
            self.stats.relay_unknown_target += 1;
            return;
        }
        const to = self.servedFor(destination.?) orelse return;
        // A relay forwards datagrams, and this is the length of one. A frame
        // that claims more is refused rather than truncated, because a
        // truncated QUIC packet is a packet the peer cannot use.
        if (payload.len > max_datagram) {
            self.stats.relay_oversized += 1;
            return;
        }
        if (to.queues.data.isFull()) {
            self.stats.relay_queue_full += 1;
            return;
        }
        // `Queue` is a ring over `storage[(head + count) % len]` and `ring` is a
        // ring over the same index, so the slot a queued `Packet` borrows is
        // the one its own position names, and it is free the moment it is
        // popped. Copying here is what makes that possible at all: the bytes
        // arrived in the read buffer and are gone by the next read.
        const depth = to.queues.data.capacity();
        const at = (to.queues.data.head + to.queues.data.count) % depth;
        const bytes = to.ring[at * max_datagram ..][0..payload.len];
        @memcpy(bytes, payload);
        to.queues.data.push(.{ .src = src, .data = bytes }) catch {
            self.stats.relay_queue_full += 1;
            return;
        };
        self.stats.relay_forwarded += 1;
    }

    /// Write out what is queued for each client, a bounded number each.
    fn serveQueues(self: *Node, drain_room: usize) Error!bool {
        var moved = false;
        var room = drain_room;
        for (self.clients) |*slot| {
            if (!slot.live) continue;
            var stream: bridge_mod.Stream = slot.out;
            // Control first, and not as a courtesy: a client that has stopped
            // reading is the one that most needs to be told, and the queue it
            // would otherwise be behind is exactly the one that is full.
            while (room > 0) {
                const control = slot.queues.control.pop() orelse break;
                try writeRelay(&stream, self.relay_out, controlFrame(control));
                moved = true;
                room -= 1;
            }
            while (room > 0) {
                const packet = slot.queues.data.pop() orelse break;
                try writeRelay(&stream, self.relay_out, .{
                    .relay_to_client_datagram = .{
                        .node_id = packet.src,
                        .datagrams = .{
                            .ecn = null,
                            .segment_size = null,
                            .contents = packet.data,
                        },
                    },
                });
                moved = true;
                room -= 1;
            }
        }
        return moved;
    }

    /// End every client whose connection the core has finished with.
    ///
    /// The core has taken it out of its table and `sweep` has already run,
    /// which is the reason this pass sits where it does: the connection is
    /// gone rather than half gone.
    fn serveRelease(self: *Node) bool {
        var moved = false;
        for (self.clients) |*slot| {
            if (!slot.live) continue;
            if (self.connFor(slot.conn) != null) continue;
            self.release(slot);
            moved = true;
        }
        return moved;
    }

    /// End one client, reporting it exactly once.
    ///
    /// The guard is *taken* and not merely deinited, so nothing is left on the
    /// slot for a second call. That spends the type's own guarantee rather
    /// than relying on it: a second `deinit` answers `.already_gone` without
    /// reaching the registry, and taking the handle means there is no second
    /// call to make.
    ///
    /// Nothing is written to the client here. Either its connection is gone,
    /// which is the case that got here, or the whole endpoint is closing and
    /// `close_endpoint` covers it — and a stream written to after `sweep` would
    /// be a write into freed memory.
    fn release(self: *Node, slot: *Served) void {
        if (slot.guard) |*guard| self.reportDisconnection(guard);
        slot.inbox.deinit(self.gpa);
        slot.* = .{};
    }

    /// Tell access control, once, that a client has gone, and act on whatever
    /// the registry did about it.
    fn reportDisconnection(
        self: *Node,
        guard: *relay_server.Registry(relay_displaced).OnDisconnectGuard,
    ) void {
        switch (guard.deinit()) {
            .disconnected => self.stats.relay_disconnects += 1,
            // A connection that had already been displaced ends too, and the
            // entry survives with its active connection untouched.
            .duplicate => self.stats.relay_duplicates += 1,
            .promoted => |promotion| {
                self.stats.relay_disconnects += 1;
                self.stats.relay_promoted += 1;
                // Upstream tells the connection that took over that it is
                // healthy (`server/clients.rs:122-129`), and it goes on that
                // client's control queue like every other control message.
                const took_over = self.servedFor(promotion.took_over) orelse return;
                // Queue saturation drops the notification, not the promoted client.
                took_over.queues.control.push(.{ .status = .healthy }) catch |err| switch (err) {
                    error.QueueFull => self.stats.relay_queue_full += 1,
                };
            },
            // The registry holds no such connection, which is what a second
            // exit finds. Counting it is how a double report would show up.
            .already_gone => self.stats.relay_double_reports += 1,
        }
    }

    /// End every client, at once, in the phase the handler's shutdown runs in.
    fn relayClose(self: *Node) void {
        for (self.clients) |*slot| {
            if (!slot.live) continue;
            self.release(slot);
        }
    }

    // -- the relay client ----------------------------------------------------

    /// A relay client's pass: the handshake, then what the relay hands back.
    ///
    /// **A client that is winding down dials nobody and opens no stream**, and
    /// this is `serve`'s guard in the same place for the same reason. `close`
    /// resumes rather than refusing, so a close that stopped in
    /// `closing_endpoint` leaves this node mid-shutdown with its descriptor
    /// open, and a pass in between is a call the surface permits. Dialing here
    /// would take a new core connection and spend a credit from the relay's
    /// stream grant on a node whose every other connection `close_endpoint`
    /// has closed, and `relay_dialled` is latched — a node driven on after an
    /// abandoned shutdown could never reach that relay again.
    fn converse(self: *Node, at: Instant, random: std.Random) Error!bool {
        if (self.accept.shutdown.phase != .serving) return false;
        // The stream opened below must be retained in the node, not a Spoke copy.
        const spoke = if (self.spoke) |*held| held else {
            const dialed = try self.converseOpen(at, random);
            return dialed;
        };
        const conn = self.connFor(spoke.conn) orelse return false;
        var stream = if (spoke.stream) |open| open else open_stream: {
            if (!conn.established()) return false;
            // `Spoke.stream`'s own note says the open is deferred past the
            // dial, and it is deferred on the `try` rather than on a question:
            // **by the time this runs the core has the peer's stream grant or
            // it will not have it ever.** The grant is applied in the same call
            // that marks the connection established — `setMaxStreams` at
            // `connection.zig:2650`, and `isEstablished` is that state
            // (`:4079`) — so an established connection has always had one, and
            // the open below can only be refused for being out of credit. This
            // node opens one stream in a connection's life and `sendThrough`
            // reuses it, so a refusal here means the relay advertised none,
            // and `MAX_STREAMS` raises a grant already made rather than
            // granting from nothing. There is nothing to wait for and nothing
            // to retry, and the pass says so by failing instead of answering
            // `false` on every pass from here on with nothing to show for it.
            const opened = try bridge_mod.Stream.open(conn);
            spoke.stream = opened;
            break :open_stream opened;
        };
        var moved = false;
        // The relay's half arrives on the stream the *relay* opened, which is
        // the mirror of `Served.out` and for the same reason. Straight onto the
        // inbox, as `serveRead` does it and for the same reason, and asking
        // `Stream.drain`'s second half for the same reason: what it appended is
        // not what came before it. See `discardTail`.
        var finished = false;
        var inbound = conn.peerStream();
        if (inbound) |*incoming| {
            moved = try incoming.drain(self.gpa, &spoke.inbox) or moved;
            finished = incoming.finished();
        }
        var consumed: usize = 0;
        // The walk `serveMessages` does, down to why the two drops are one
        // decision: a frame this node cannot decode is refused once rather
        // than on every pass after it, and the frame in front of it is acted
        // on once rather than once per pass.
        errdefer dropInbox(&spoke.inbox, consumed);
        while (try peekFrame(spoke.inbox.items, consumed, self.relay_scratch)) |found| {
            consumed = found.end;
            const message = try relay_frame.decode(found.frame, .v2);
            try self.converseMessage(spoke, &stream, message);
            moved = true;
        }
        dropInbox(&spoke.inbox, consumed);
        if (discardTail(&spoke.inbox, finished)) {
            self.stats.relay_stream_truncated += 1;
        }
        return moved;
    }

    /// Dial the relay, once, and start the client handshake on it.
    ///
    /// The path offered is `.signed_challenge` for the reason the server half
    /// offers no credential: this transport has no key-material exporter, so a
    /// challenge is the only way a relay can tell who is calling.
    fn converseOpen(self: *Node, at: Instant, random: std.Random) Error!bool {
        const peer = switch (self.config.relay.role) {
            .client => |peer| peer,
            else => return false,
        };
        if (self.relay_dialled) return false;
        self.relay_dialled = true;
        const reached = self.dialer.dial(
            peer.addr,
            peer.id,
            self.socket.address,
            &self.map,
            at,
            random,
        ) catch |err| {
            // A relay that cannot be reached is a fact about the network and
            // not a reason to retry, for the reason `Config.peers` gives: the
            // retry policy belongs with discovery.
            self.stats.relay_dials_refused += 1;
            std.log.warn("node: the relay was not reached: {t}", .{err});
            return false;
        };
        self.stats.relay_dials += 1;
        self.spoke = .{
            .conn = reached.conn.id(),
            .stream = null,
            .handshake = relay_client.start(.signed_challenge),
            .inbox = .empty,
            .delivered = .empty,
        };
        return true;
    }

    /// One relay frame, to this node's relay client.
    fn converseMessage(
        self: *Node,
        spoke: *Spoke,
        stream: *bridge_mod.Stream,
        message: relay_frame.Message,
    ) Error!void {
        switch (spoke.handshake) {
            .awaiting_relay, .awaiting_verdict => {
                const stepped = relay_client.step(
                    spoke.handshake,
                    .{ .frame = message },
                    &self.config.secret,
                );
                spoke.handshake = stepped.state;
                if (stepped.action) |action| switch (action) {
                    .send_client_auth => |auth| {
                        try writeRelay(stream, self.relay_out, .{ .client_auth = auth });
                        self.stats.relay_auth_sent += 1;
                    },
                    .close => {
                        stream.close();
                        self.stats.relay_closed += 1;
                    },
                };
                switch (spoke.handshake) {
                    .established => self.stats.relay_established += 1,
                    else => {},
                }
                return;
            },
            else => {},
        }
        switch (message) {
            .relay_to_client_datagram, .relay_to_client_datagram_batch => |frame| {
                try self.retain(spoke, frame);
            },
            .endpoint_gone => {
                self.stats.relay_peer_gone += 1;
            },
            // **One status is a fact about this node and the other three are
            // information it has nowhere to put.** A
            // `.same_endpoint_id_connected` means a later connection took this
            // node's id at the relay, which is the one thing a caller of
            // `sendThrough` has to be told, so it is counted. `.healthy`
            // reports a recovery from trouble this transport never reported,
            // `.rate_limited` is advice about a send queue this protocol does
            // not have, and `.unknown` is a discriminant this build has no
            // name for. None of them changes what this node does next, so they
            // are dropped rather than counted; `relay_frame.Status` is where
            // the four are defined and why `.unknown` is kept at all.
            .status => |status| switch (status) {
                .same_endpoint_id_connected => self.stats.relay_displaced += 1,
                else => {},
            },
            .ping => |data| try writeRelay(stream, self.relay_out, .{ .pong = data }),
            // Two groups reach here and neither is acted on. The handshake's
            // own frames — `.server_challenge`, `.server_confirms_auth`,
            // `.server_denies_auth` — cannot: `relay_client.step` above folds
            // any frame its state does not name into `.failed`, so a relay that
            // sent one out of order has been closed by it and this node is no
            // longer reading that stream. What is left is `.restarting`, and
            // it is valid, decoded, and dropped: this client dials a relay
            // once in its life and `relay_dialled` is latched, so there is no
            // reconnect to schedule and the frame's wait and budget have
            // nothing here to bound. `.health` cannot reach this arm at all —
            // it is v1 only and `decode` is called with `.v2`. Nothing is
            // counted for either, because nothing happened.
            else => {},
        }
    }

    /// Retain one datagram the relay handed this node, and count it.
    ///
    /// **The copy is the node's, and the guard for it is taken before the list
    /// is.** `relay_frame.decode` borrows a frame's datagrams out of the bytes
    /// that frame was read from, and those bytes are reused by the next read,
    /// so a payload handed to a caller has to be copied rather than pointed
    /// at. Copying makes it an allocation this node owns from that line on,
    /// and the append that publishes it can still fail — so the `errdefer`
    /// sits between the two: an append that cannot be given the copy releases
    /// it rather than leaving one payload behind for every frame refused on
    /// the way to the list.
    ///
    /// Nothing bounds the list. `delivered` hands out what is on it and
    /// `clearDelivered` is what gives the payloads back, so a relay that keeps
    /// answering grows it until a caller clears it — which is the same
    /// contract `Delivered` states from the outside.
    fn retain(self: *Node, spoke: *Spoke, frame: relay_frame.DatagramFrame) Error!void {
        const owned = try self.gpa.dupe(u8, frame.datagrams.contents);
        errdefer self.gpa.free(owned);
        try spoke.delivered.append(self.gpa, .{
            .src = frame.node_id,
            .data = owned,
        });
        self.stats.relay_datagrams_out += 1;
    }

    // -- the relay's public face --------------------------------------------

    /// What this node's relay has handed back, oldest first. A node that has
    /// not reached a relay answers an empty slice, and so does one that has
    /// called `clearDelivered`: both are "nothing is waiting", not "no relay".
    ///
    /// **The slice is a descriptor into a list that grows, and the payloads in
    /// it are not.** Two different lifetimes, and a caller has to know which
    /// one it is holding:
    ///
    /// - *The returned slice* points into `spoke.delivered`, an `ArrayList`
    ///   this node appends to in `retain`. The next datagram a relay hands
    ///   over may reallocate that list, and the slice this call returned
    ///   describes the old storage. Take the items — or `data.len`, or the
    ///   count — before driving another pass, and take the slice again if you
    ///   need it after one.
    /// - *Each `Delivered.data`* is a copy this node allocated, and it stays
    ///   valid across every later delivery. What ends it is `clearDelivered`,
    ///   or `deinit` if the caller never got there.
    ///
    /// `delivered` takes `*const Node` and mutates nothing, so reading the
    /// list is safe from a caller holding only a shared borrow; it is not safe
    /// from another thread while a pass is running.
    pub fn delivered(self: *const Node) []const Delivered {
        const spoke = self.spoke orelse return &.{};
        return spoke.delivered.items;
    }

    /// Forget everything the relay has handed back, and free the payloads.
    ///
    /// Each `data` is freed here and nowhere else, and the list is emptied in
    /// the same pass, so a second call finds nothing to free and `deinit`
    /// finds nothing to give back. A caller holding a slice from `delivered`
    /// holds freed memory afterwards; a caller holding one `data` holds it
    /// until this call and not one pass longer.
    ///
    /// The list's capacity is kept, so a caller that clears every pass pays
    /// for one growth rather than one per pass. A caller that never clears
    /// grows the list for as long as the relay keeps answering — the copy in
    /// `retain` is the price of handing a caller bytes it can keep.
    pub fn clearDelivered(self: *Node) void {
        const spoke = &(self.spoke orelse return);
        for (spoke.delivered.items) |item| self.gpa.free(item.data);
        spoke.delivered.clearRetainingCapacity();
    }

    /// Send one datagram to `peer` through this node's relay.
    ///
    /// The relay forwards it to the client holding `peer`'s node id, and when
    /// nobody holds it the datagram is dropped and a `peer_gone` comes back
    /// here. That is the whole of what a relay is for, and the drop is
    /// upstream's (`server/clients.rs:218-224`).
    ///
    /// This only queues bytes in memory; it performs no I/O or cancellation
    /// check. `CoreRefused` can report a refused stream allocation.
    pub fn sendThrough(self: *Node, peer: NodeId, bytes: []const u8) Error!void {
        // Two refusals, asked in the order they are asked below: a node with no
        // relay answers `NoRelay` whatever it was handed, and the payload bound
        // is about the caller's bytes, which only matter once there is a relay
        // to refuse them to.
        const spoke = self.spoke orelse return error.NoRelay;
        if (bytes.len > max_datagram) return error.DatagramTooLarge;
        const held = spoke.stream orelse return error.NoRelay;
        var stream: bridge_mod.Stream = held;
        try writeRelay(&stream, self.relay_out, .{
            .client_to_relay_datagram = .{
                .node_id = peer,
                .datagrams = .{
                    .ecn = null,
                    .segment_size = null,
                    .contents = bytes,
                },
            },
        });
        self.stats.relay_sent += 1;
    }

    /// How many node ids this relay holds, which is the registry's own answer
    /// and not a count kept beside it.
    ///
    /// **Zero for a node that does not serve, and the role is what says so.**
    /// `initRelay` builds a registry for a `.serve` and for nothing else, so
    /// the table under a `.off` or `.client` node is never initialised at all —
    /// reading it would answer from bytes `create` never wrote, which is a
    /// different number on every run and under every allocator. Such a node
    /// admits nobody, so zero is its count; the switch is the same rule
    /// `queueDepth` applies, and like it costs nothing but a read of the role.
    pub fn clientCount(self: *const Node) usize {
        return switch (self.config.relay.role) {
            .serve => self.registry.nodeCount(),
            else => 0,
        };
    }

    // -- the relay's storage ------------------------------------------------

    /// Build the relay's storage, once, from the role `create` was given.
    ///
    /// **Two of these allocations belong to every role and four to `.serve`.**
    /// `relay_out` and `relay_scratch` are taken before the role is read at
    /// all, so a `.off` node holds them and `freeRelay` returns them without a
    /// byte of either ever having been written: `serve`, `converse` and
    /// `sendThrough` reach `writeRelay`; `serve` and `converse` reach `peekFrame`.
    /// The registry, client slots and three queue allocations follow the `.serve` return; they
    /// are the storage `Serve.clients` and `Serve.queue_depth` size, once,
    /// here. That is why those two fields must not be written after `create`
    /// (`Node.config`), and why `queueDepth` reads the same live field the
    /// cuts are made from.
    fn initRelay(self: *Node) Error!void {
        const gpa = self.gpa;
        self.relay_out = try gpa.alloc(u8, relay_frame_room + varint_max);
        errdefer gpa.free(self.relay_out);
        self.relay_scratch = try gpa.alloc(u8, relay_frame_room);
        errdefer gpa.free(self.relay_scratch);
        const role = switch (self.config.relay.role) {
            .serve => |role| role,
            // A client needs no registry and no queues. It needs the two
            // buffers and one stream, and the buffers are all it allocates.
            else => return,
        };
        // The tables here are sized by `max_relay_clients` and are built not to
        // grow, so a relay that admitted more would probe a table the registry
        // would answer `NoFreeSlot` to long before it was actually full.
        if (role.clients > max_relay_clients) return error.TooManyRelayClients;
        // A queue with no room can never take anything, and a relay with one
        // drops every datagram while reporting that it forwarded none.
        if (role.queue_depth == 0) return error.RelayQueueDepthZero;
        const per_client = role.clients * role.queue_depth;
        self.registry = relay_server.Registry(relay_displaced).init(&self.slots);
        self.clients = try gpa.alloc(Served, role.clients);
        errdefer gpa.free(self.clients);
        self.packets = try gpa.alloc(relay_server.Packet, per_client);
        errdefer gpa.free(self.packets);
        self.messages = try gpa.alloc(relay_server.Control, per_client);
        errdefer gpa.free(self.messages);
        self.ring = try gpa.alloc(u8, per_client * max_datagram);
        errdefer gpa.free(self.ring);
        for (self.clients, 0..) |*client, index| {
            client.* = .{ .queues = self.queuesOf(index), .ring = self.ringOf(index) };
        }
    }

    /// One client's two queues, cut out of this node's storage.
    ///
    /// **The cut is redone from `config` on every call rather than kept beside
    /// the storage it describes**, so `depth` is the value the field holds now
    /// and not the one `initRelay` sized these allocations from. That is the
    /// whole of the rule `Node.config` states: the relay's sizing is fixed at
    /// construction because this call re-reads it, not because anything here
    /// copied it.
    fn queuesOf(self: *const Node, index: usize) relay_server.Connection {
        const depth = self.queueDepth();
        const base = index * depth;
        return relay_server.Connection.init(
            self.packets[base..][0..depth],
            self.messages[base..][0..depth],
        );
    }

    /// One client's datagram ring: a fixed slot per queue position.
    fn ringOf(self: *const Node, index: usize) []u8 {
        const depth = self.queueDepth();
        return self.ring[index * depth * max_datagram ..][0 .. depth * max_datagram];
    }

    /// One client's depth, read from the live configuration rather than kept
    /// beside it. See `queuesOf` for why that is the same number on every pass
    /// and what a write to it costs.
    fn queueDepth(self: *const Node) usize {
        return switch (self.config.relay.role) {
            .serve => |role| role.queue_depth,
            else => 0,
        };
    }

    /// Give back everything the relay took, for whatever role it took it for.
    ///
    /// Before the bridge goes: a guard reaches into this struct's own registry,
    /// and a client slot points at a connection the core frees. The two frame
    /// buffers are the other half of `initRelay`'s unconditional pair and are
    /// freed whatever the role was, which is what leaves a `.off` node holding
    /// no relay storage after this returns.
    fn freeRelay(self: *Node) void {
        self.relayClose();
        if (self.spoke) |*spoke| {
            spoke.inbox.deinit(self.gpa);
            for (spoke.delivered.items) |item| self.gpa.free(item.data);
            spoke.delivered.deinit(self.gpa);
        }
        self.spoke = null;
        self.gpa.free(self.relay_out);
        self.gpa.free(self.relay_scratch);
        self.gpa.free(self.ring);
        self.gpa.free(self.messages);
        self.gpa.free(self.packets);
        self.gpa.free(self.clients);
    }

    /// The client on connection `conn`, or null when there is none.
    fn servedFor(self: *const Node, conn: u64) ?*Served {
        for (self.clients) |*slot| {
            if (slot.live and slot.conn == conn) return slot;
        }
        return null;
    }

    /// A free client slot, or null when every one holds a client.
    fn freeClient(self: *Node) ?*Served {
        for (self.clients) |*slot| {
            if (!slot.live) return slot;
        }
        return null;
    }

    /// Which slot this is, for the storage cuts `queuesOf` and `ringOf` make.
    fn indexOf(self: *const Node, slot: *const Served) usize {
        const at = @intFromPtr(slot) - @intFromPtr(self.clients.ptr);
        return at / @sizeOf(Served);
    }

    // -- small helpers ------------------------------------------------------

    /// The connection the core holds for `id`, or null when it has finished
    /// with it. Found by the same index walk an accepted connection is found
    /// by, which is what makes the accept path and the dial path the same
    /// machinery rather than two of them.
    fn connFor(self: *Node, id: u64) ?Conn {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.id() == id) return conn;
        }
        return null;
    }

    /// Record what a send cost. A `Report` is the socket's own account of the
    /// codepoint and of whether a batch went out as one `sendmsg`, and reading
    /// it is what keeps a degradation from being silent.
    fn note(self: *Node, report: batch.Report) void {
        if (report.degraded) self.stats.sends_degraded += 1;
        if (!report.ecnSurvived()) self.stats.ecn_lost += 1;
    }

    /// Keep the peer an action named, for the report and for nothing else.
    fn noteNamed(self: *Node, peer: NodeId) void {
        if (self.named_len == named_ring) {
            @memmove(self.named[0 .. named_ring - 1], self.named[1..]);
            self.named_len -= 1;
        }
        self.named[self.named_len] = peer;
        self.named_len += 1;
    }

    /// Close the descriptor, once.
    ///
    /// `close_endpoint` and `deinit` both owe it and only the first of them
    /// reaches it in an orderly shutdown. A second `close` on a descriptor the
    /// kernel has already released closes whatever took its number in between,
    /// so the flag is the whole of the guarantee.
    fn shutdownSocket(self: *Node) void {
        if (!self.socket_open) return;
        self.socket_open = false;
        self.socket.close();
    }
};

/// One relay frame onto a stream, with the message boundary a WebSocket would
/// have carried.
///
/// `relay/frame.zig` has no length prefix and says why twice: upstream's
/// carrier is a WebSocket, and one message *is* one frame. A QUIC stream is a
/// byte pipe with no boundary of its own, so this writes the one the WebSocket
/// was carrying — a QUIC varint length, then the frame — and the frame bytes
/// themselves are untouched, because `decode` is handed exactly the message
/// the length named.
fn writeRelay(
    stream: *bridge_mod.Stream,
    out: []u8,
    message: relay_frame.Message,
) Error!void {
    const written = try relay_frame.encode(message, .v2, out[varint_max..]);
    const prefix = try writeVarint(out[0..varint_max], written.len);
    // The frame was written at `varint_max` because the length had to go in
    // front of it and its own width is not known until it has been written.
    // It is moved down over the gap the length did not use, so what goes on the
    // wire is the length and then the frame and nothing between them.
    @memmove(out[prefix..][0..written.len], written);
    try stream.write(out[0 .. prefix + written.len]);
}

/// The next whole frame at or after `from` in `bytes`, copied into `scratch`,
/// and where it ended — or null when there is not one yet.
///
/// **This delimits a frame and does not decode one.** The length alone says
/// where the frame ends, and that end is a fact about the bytes rather than
/// about what they mean. How many bytes a frame was is therefore known before
/// anyone asks what it says, and the caller records that end before it asks:
/// a frame `decode` refuses has still arrived whole, so it has to be walked
/// over rather than met again on the next pass, and so has everything in
/// front of it. A helper that answered both questions in one return could not
/// hand back the end of a frame whose meaning turned out to be a fault.
///
/// **Copied into `scratch`, and that is the whole of what makes the borrow
/// sound.** `frame.decode` borrows its two variable-length payloads out of the
/// bytes it is handed, so those bytes must outlive the message. They cannot be
/// the inbox's, because taking a message off the inbox's front moves every byte
/// behind it — a borrow into a buffer that is compacted under it is a borrow of
/// nothing. One copy per message, into a buffer the caller owns, is the price
/// of a borrow that points at something.
///
/// **A walk, and the caller compacts once.** A take that shrank the inbox per
/// message moved everything behind that message every time, which is quadratic
/// in the inbox: cheap while a read buffer capped the inbox at one frame, which
/// is all it ever held, and a whole burst's worth of memmove now that a read
/// goes straight onto the inbox. So this hands back an end offset and leaves
/// the bytes where they are, and `dropInbox` moves what is left exactly once —
/// on the way out of the walk and on the fault that ends it alike, because the
/// two are one decision taken twice rather than two decisions.
///
/// `scratch` has to be as long as the largest frame this node admits, which is
/// `relay_frame_room`. One scratch serves a whole node because a pass takes at
/// most one direction of the protocol: a serving relay reads its clients, and a
/// client reads its relay.
fn peekFrame(
    bytes: []const u8,
    from: usize,
    scratch: []u8,
) Error!?struct { frame: []const u8, end: usize } {
    const head = readVarint(bytes[from..]) orelse return null;
    const whole = std.math.cast(usize, head.value) orelse return error.FrameTooLarge;
    const end = from +| head.len +| whole;
    if (bytes.len < end) return null;
    if (whole > scratch.len) return error.FrameTooLarge;
    @memcpy(scratch[0..whole], bytes[from + head.len ..][0..whole]);
    return .{ .frame = scratch[0..whole], .end = end };
}

/// Drop the first `used` bytes of `inbox`, in one move.
fn dropInbox(inbox: *std.ArrayList(u8), used: usize) void {
    if (used == 0) return;
    const rest = inbox.items[used..];
    @memmove(inbox.items[0..rest.len], rest);
    inbox.shrinkRetainingCapacity(rest.len);
}

/// Drop the frame a finished stream left half-written, and say whether it left
/// one.
///
/// **This is the half of `Stream.drain`'s answer its caller has to ask for.**
/// `drain` returns whether it appended bytes and says nothing about what came
/// before them, so a stream the peer ended on a frame boundary and one it ended
/// in the middle of a frame read the same, and only `Stream.finished` tells
/// them apart. What is left in `inbox` after that is a frame that will never
/// arrive, so it is dropped and counted rather than kept for a message that is
/// not coming.
///
/// Asked after `dropInbox`, never before: until the whole messages are taken,
/// an inbox with bytes in it is this node behind rather than a peer that
/// stopped early.
fn discardTail(inbox: *std.ArrayList(u8), finished: bool) bool {
    if (!finished or inbox.items.len == 0) return false;
    inbox.clearRetainingCapacity();
    return true;
}

/// A queued control message as the frame that carries it.
fn controlFrame(control: relay_server.Control) relay_frame.Message {
    return switch (control) {
        .peer_gone => |node_id| .{ .endpoint_gone = node_id },
        .status => |status| .{ .status = status },
    };
}

/// The widest a QUIC variable-length integer is, which is also the headroom a
/// message leaves in front of its frame. The same encoding `relay/frame.zig`
/// writes a frame type with, because that is what a peer will read it as.
const varint_max = 8;

/// A QUIC variable-length integer: two prefix bits say the width, and the
/// value is what is left of it.
const Varint = struct {
    value: u64,
    len: usize,
};

fn writeVarint(out: []u8, value: u64) Error!usize {
    if (value < 64) {
        if (out.len < 1) return error.NoRoom;
        out[0] = @intCast(value);
        return 1;
    }
    if (value < 16384) {
        if (out.len < 2) return error.NoRoom;
        putInt(u16, out[0..2], @intCast(value | (0b01 << 14)));
        return 2;
    }
    if (value < 1 << 30) {
        if (out.len < 4) return error.NoRoom;
        putInt(u32, out[0..4], @intCast(value | (0b10 << 30)));
        return 4;
    }
    if (out.len < varint_max) return error.NoRoom;
    putInt(u64, out[0..varint_max], value | (0b11 << 62));
    return varint_max;
}

fn readVarint(bytes: []const u8) ?Varint {
    if (bytes.len == 0) return null;
    const len = @as(usize, 1) << @as(u2, @truncate(bytes[0] >> 6));
    if (bytes.len < len) return null;
    const wide: u64 = switch (len) {
        1 => bytes[0],
        2 => getInt(u16, bytes[0..2]),
        4 => getInt(u32, bytes[0..4]),
        else => getInt(u64, bytes[0..varint_max]),
    };
    const bits: u6 = @intCast(@as(u32, @intCast(len)) * 8 - 2);
    return .{ .value = wide & ((@as(u64, 1) << bits) - 1), .len = len };
}

/// Write `value` big-endian into the front of `out`, which the caller has
/// already sized for `T`'s width.
fn putInt(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, @ptrCast(out.ptr), value, .big);
}

/// Read a big-endian `T` off the front of `bytes`, which the caller has
/// already checked is long enough.
fn getInt(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, @ptrCast(bytes.ptr), .big);
}

/// `ProtocolHandler::accept`: one connection handed to this node's protocol.
///
/// Upstream's runs until the connection ends (`protocol.rs:258-261`), which is
/// what makes the shutdown ordering load-bearing — a handler's `shutdown`
/// closes connections its own `accept` is still using. There is nothing to run
/// here: the gossip wire format does not exist yet (see the module doc), so a
/// body that looped would be a lie about what this node serves. It counts the
/// connection and returns, and `Stats.handler_connections` is what a caller
/// reads.
fn acceptConnection(ptr: *anyopaque, connection: router.Connection) router.AcceptError!void {
    // The handle a handler is given is the node itself, and asserting it is
    // what turns "the endpoint mints the handle" into a checked claim.
    std.debug.assert(connection.ptr == ptr);
    const self: *Node = @ptrCast(@alignCast(ptr));
    self.stats.handler_connections += 1;
}

/// `ProtocolHandler::shutdown`: called once per close, before any accept is
/// cancelled (`router.zig`'s `ProtocolHandler.shutdown`).
///
/// The gossip layer's timers are dropped here rather than in `deinit`, because
/// this is the point upstream's ordering is about: a handler is given its
/// shutdown while the accepts that might still be using it are still running,
/// and never after.
fn shutdownHandler(ptr: *anyopaque) void {
    const self: *Node = @ptrCast(@alignCast(ptr));
    self.stats.handler_shutdowns += 1;
    self.timers.clearRetainingCapacity();
    // The relay is this handler's own state, and it is given up here rather
    // than in `deinit`: this is the phase upstream gives a handler's resources
    // in — while the accepts that might still be using them are running, and
    // never after. `close_endpoint` closes the connections the clients were
    // on, so every disconnect is reported before a single socket write.
    self.relayClose();
}

/// This node's instant, in the unit the core is driven at.
///
/// `Clock.awake` rather than `.real`: a QUIC timer must not jump because NTP
/// moved the wall clock, and every seam below takes its instant as an argument
/// precisely so that nothing reads one itself.
fn instantOf(io: std.Io) Error!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.InstantOutOfRange;
}

/// The loop's instant in the gossip clocks' own unit.
///
/// `Instant` is signed because the QUIC core's is — the transport treats an
/// instant before its own epoch as a legitimate one — and `Nanos` is unsigned
/// because a timer duration cannot be negative. The cast is the whole of the
/// translation, and it is refused rather than wrapped: a clock that went
/// backwards past zero has no answer here, and `Error.InstantOutOfRange` is
/// what a caller would have to handle either way.
fn gossipNow(at: Instant) Error!hyparview.Nanos {
    return std.math.cast(hyparview.Nanos, at) orelse error.InstantOutOfRange;
}

/// Whether one of these ALPNs was registered before this one.
///
/// `router.Builder.push` displaces an older registration and keeps the newer
/// one, so the shutdown owes one `shutdown` per *distinct* ALPN and not one
/// per entry. `endpoint.handlerCount` counts the same thing; this is the same
/// rule at the same place, spelled out because `performShutdown` needs both
/// halves and reading the count from two functions would be a second answer.
fn namedBefore(earlier: []const router.Entry, alpn: []const u8) bool {
    for (earlier) |entry| {
        if (std.mem.eql(u8, entry.alpn, alpn)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

/// Where a test node binds, with port zero: the kernel picks, so two nodes in
/// one process both bind and a socket left over from the last run cannot
/// collide with this one.
const loopback: SocketAddr = .{
    .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
    .port = 0,
};

/// Where virtual time starts. It moves only because this test says so — see
/// `test/protocol_loopback_test.zig`'s module doc, which is the discipline
/// this file borrows.
const start_ns: Instant = 1_000 * std.time.ns_per_s;

/// How far the clock moves per pass. A pass is a handful of syscalls, so this
/// is a clock and not a delay: nothing in this file waits for it to elapse, and
/// the total stays far below the core's 30 s idle timeout so a connection is
/// never reaped by the clock.
const time_quantum: Instant = hyparview.nanos_per_milli;

/// How many passes the loop runs. Generous, because a pass is a few syscalls
/// and nothing here can block: the bound is a backstop against a run that
/// never converges, not a timer. It is also the claim the milestone is
/// about — a node does not stop here, and this number is only a backstop.
const max_passes = 256;

/// A fixed identity per test node, so both ends present the same certificate
/// on every run and a failure reproduces rather than has to be
/// re-diagnosed.
fn identityOf(tag: u8) base_key.KeyError!SecretKey {
    return SecretKey.fromSeed(@splat(tag));
}

/// Membership and broadcast with the paper's defaults and short clocks, so
/// the `shuffle` and `pending_neighbor_request` paths are on the wire inside
/// the pass bound rather than sitting on a timer the run never reaches. The
/// capacities and the walk lengths are left alone: this test is about the
/// loop and not about the paper.
fn briskTopic() hyparview.TopicConfig {
    return .{ .membership = .{
        .shuffle_interval = 4 * hyparview.nanos_per_milli,
        .neighbor_request_timeout = 2 * hyparview.nanos_per_milli,
    } };
}

/// Close before release even when a test assertion fails.
fn closedOnExit(node: *Node) void {
    defer node.deinit();
    node.close(t.io, start_ns, node.generator()) catch |err|
        std.debug.panic("node close failed during test teardown: {t}", .{err});
}
test "a node dials a peer, both ends finish a handshake, and every action is performed" {
    // The listener first: its ephemeral port is only known once the socket
    // exists, and the dialer is given that address rather than one made up.
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x1111);
    defer listener.deinit();

    const peers = [_]Peer{.{
        .id = listener.nodeId(),
        .addr = .{ .ip = listener.address() },
    }};
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0x2222);
    defer dialer.deinit();

    // Two different identities: a node that dialled itself would be told its
    // own certificate, which proves nothing about a pin.
    try t.expect(dialer.nodeId().order(listener.nodeId()) != .eq);

    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());

    // One round loop over both nodes, which is `Mesh.round` in
    // `test/protocol_loopback_test.zig` with two nodes in it instead of four.
    var passes: usize = 0;
    var moved: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        if (try dialer.step(t.io, at, dialer.generator())) moved += 1;
        if (try listener.step(t.io, at, listener.generator())) moved += 1;
    }

    // More than one pass ran, and the loop kept going rather than stopping at
    // convergence: the pass count is the whole claim, and the bound above it
    // never fired.
    try t.expect(passes > 1);
    try t.expect(passes == max_passes);
    try t.expectEqual(@as(u64, max_passes), dialer.stats.steps);
    try t.expectEqual(@as(u64, max_passes), listener.stats.steps);
    try t.expect(moved > 0);

    // The handshake completed on both sides, over real sockets, with the
    // dialling side's pin enforced.
    try t.expectEqual(@as(usize, 1), dialer.establishedCount());
    try t.expectEqual(@as(usize, 1), listener.establishedCount());
    try t.expectEqual(@as(u64, 1), dialer.stats.dials);
    try t.expectEqual(@as(u64, 0), dialer.stats.dials_refused);
    try t.expect(dialer.stats.datagrams_out > 0);
    try t.expect(listener.stats.datagrams_in > 0);

    // The listening node performed every action the endpoint owed: the
    // arrival was offered to the filter, the filter accepted it, the loop
    // spawned a task, the task ran the handler's `accept`, and the task was
    // reaped when the handler finished.
    try t.expectEqual(@as(u64, 1), listener.stats.attempts);
    try t.expectEqual(@as(u64, 1), listener.stats.spawned);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_connections);
    // The dialling node is not an accept: it asked for the connection and
    // already knew who the peer was, which is what `Endpoint::accept` never
    // returns.
    try t.expectEqual(@as(u64, 0), dialer.stats.attempts);

    // The gossip loop is a loop. It was fed the join, it scheduled a timer,
    // the timer fired, and the state machine asked to be told something — and
    // nothing was sent, which is the module doc's named gap and is asserted
    // here as the positive fact it is rather than left to be inferred from the
    // silence that follows it.
    try t.expect(dialer.stats.gossip_events > 0);
    try t.expect(dialer.stats.gossip_timers_scheduled > 0);
    try t.expect(dialer.stats.gossip_timers_fired > 0);
    try t.expect(dialer.stats.gossip_membership_asked > 0);
    // Every peer the state machine named is the peer this node dialled, and
    // there is at least one: a counter that grew with an empty ring would say
    // the two halves disagree about what happened.
    try t.expect(dialer.namedPeers().len > 0);
    for (dialer.namedPeers()) |named| {
        try t.expectEqual(listener.nodeId(), named);
    }

    // The shutdown, in the order `router.Shutdown` enforces: the handlers, then
    // the cancel, then the close.
    try t.expectEqual(router.Shutdown.Phase.serving, dialer.accept.shutdown.phase);
    try dialer.close(t.io, at, dialer.generator());
    try listener.close(t.io, at, listener.generator());
    for ([_]*Node{ dialer, listener }) |node| {
        try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
        try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
        try t.expectEqual(@as(usize, 0), node.accept.live);
        try t.expect(!node.socket_open);
    }
    // `deinit` is a `defer` above and it gave up a lease the loop had driven
    // to `closed`; an abandoned one is logged at error level, which fails the
    // artifact, so reaching here is itself part of what is asserted.
}

test "a node that dials two peers reaches both of them" {
    // The shape one node dialling one peer cannot see. Two dials out of one
    // process are two connections with connection ids minted from one
    // generator, two peers on one socket, and two accepts that each owe the
    // endpoint an arrival — so this is the only shape in which a datagram can
    // be written for one peer and go to the other.
    const gate = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x33),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x3333);
    defer gate.deinit();
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x1111);
    defer listener.deinit();

    const peers = [_]Peer{
        .{ .id = gate.nodeId(), .addr = .{ .ip = gate.address() } },
        .{ .id = listener.nodeId(), .addr = .{ .ip = listener.address() } },
    };
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0x2222);
    defer dialer.deinit();

    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());

    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
        _ = try gate.step(t.io, at, gate.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }

    // Both dials went out and neither was refused, which is a count of what
    // `start` did rather than of what the wire did.
    try t.expectEqual(@as(u64, 2), dialer.stats.dials);
    try t.expectEqual(@as(u64, 0), dialer.stats.dials_refused);

    // And the wire: both handshakes completed, and each peer admitted exactly
    // one arrival. A peer that saw no byte has no attempt and no handler
    // connection, which is the whole of what "the dial found nobody" is.
    try t.expectEqual(@as(usize, 2), dialer.establishedCount());
    try t.expectEqual(@as(usize, 1), gate.establishedCount());
    try t.expectEqual(@as(usize, 1), listener.establishedCount());
    try t.expectEqual(@as(u64, 1), gate.stats.attempts);
    try t.expectEqual(@as(u64, 1), gate.stats.handler_connections);
    try t.expectEqual(@as(u64, 1), listener.stats.attempts);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_connections);
    // Closed rather than abandoned: an abandoned node is logged at error level
    // by `deinit`, which fails the artifact on its own.
    try dialer.close(t.io, at, dialer.generator());
    try gate.close(t.io, at, gate.generator());
    try listener.close(t.io, at, listener.generator());
}
test "a node that dialled two peers notices both of them close" {
    // The shape one peer cannot show. Two dials out of one process are two
    // connections on one socket, and this is the claim that has to hold for
    // both: a peer that shuts down says so with a CONNECTION_CLOSE, and a node
    // still running has to finish that connection rather than sit on it until
    // the core's idle timeout — thirty seconds, six times the window
    // `test/two_process_test.zig` gives a survivor.
    const gate = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x33),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x3333);
    defer gate.deinit();
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x1111);
    defer listener.deinit();
    const peers = [_]Peer{
        .{ .id = gate.nodeId(), .addr = .{ .ip = gate.address() } },
        .{ .id = listener.nodeId(), .addr = .{ .ip = listener.address() } },
    };
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0x2222);
    defer dialer.deinit();

    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
        _ = try gate.step(t.io, at, gate.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }
    // Both dials reached a peer before either peer is taken away: a run that
    // never got here would be asserting about a handshake that did not happen.
    try t.expectEqual(@as(usize, 2), dialer.establishedCount());

    // Both peers close, as a process whose `--for` expired does.
    try gate.close(t.io, at, gate.generator());
    try listener.close(t.io, at, listener.generator());

    // The dialer keeps running. Two passes is the floor — the close arrives in
    // one pass and the core needs a later instant to leave the draining period
    // — and the bound is generous because the claim is that the connections
    // finish at all, not how many passes that took.
    passes = 0;
    while (passes < max_passes and dialer.stats.connections_finished < 2) : (passes += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
    }
    try t.expectEqual(@as(u64, 2), dialer.stats.connections_finished);
    try t.expectEqual(@as(usize, 0), dialer.establishedCount());

    try dialer.close(t.io, at, dialer.generator());
}

test "a close cancels an accept that is still running before it closes the endpoint" {
    // The branch the ordering exists for. `router.zig:642-650` says why: a
    // handler's `shutdown` closes connections its own `accept` is still using,
    // so cancelling the accepts first cuts a graceful close in half, and
    // closing the endpoint first does the same damage a step later. A test
    // that only ever closes an idle node cannot tell the three steps apart, so
    // this one closes a node that still holds an accept.
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
    }, 0x1111);
    defer listener.deinit();

    const peers = [_]Peer{.{
        .id = listener.nodeId(),
        .addr = .{ .ip = listener.address() },
    }};
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
    }, 0x2222);
    defer dialer.deinit();

    // The dialling side runs twice and the listening side once. One pass on
    // the listener is exactly enough to take the first flight, offer it, spawn
    // the task and find the handshake unfinished — so the task is live and its
    // connection is still in the core's table, which is the state a cancel has
    // to account for.
    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());
    var pass: usize = 0;
    while (pass < 2) : (pass += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
    }
    at += time_quantum;
    _ = try listener.step(t.io, at, listener.generator());

    // The precondition, stated positively: an accept task is live, the handler
    // has not run, and the handshake is not through. A connection that had
    // finished would have been reaped by `drive` in the same pass.
    try t.expectEqual(@as(usize, 1), listener.accept.live);
    try t.expectEqual(@as(u64, 0), listener.stats.handler_connections);
    try t.expectEqual(@as(usize, 0), listener.establishedCount());

    try listener.close(t.io, at, listener.generator());

    // The cancel ran, on the task that was live, and the close came after it.
    try t.expectEqual(@as(u64, 1), listener.stats.accepts_cancelled);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_shutdowns);
    try t.expectEqual(@as(u64, 0), listener.stats.handler_connections);
    try t.expectEqual(@as(usize, 0), listener.accept.live);
    try t.expectEqual(router.Shutdown.Phase.closed, listener.accept.shutdown.phase);
    try t.expect(!listener.socket_open);

    // The dialling side closes too: a `defer deinit` that reported an abandoned
    // endpoint would log at error level and fail the artifact, which is the
    // point of the report and not a reason to leave a node open.
    try dialer.close(t.io, at, dialer.generator());
    try t.expectEqual(router.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
}

test "a stop asked for before the loop is entered ends it and closes the node" {
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x7a),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x3333);
    defer node.deinit();

    var stop = Stop.init();
    try t.expect(!stop.requested());
    try t.expect(!stop.expired(start_ns));
    try t.expectEqual(router.Shutdown.Phase.serving, node.accept.shutdown.phase);

    // Raised before `run` is entered, which is what a signal handler reaching
    // the loop between two passes looks like.
    stop.request();
    try t.expect(stop.requested());
    try t.expect(stop.expired(start_ns));
    try node.run(t.io, &stop);

    // No pass ran, and the node closed anyway: the exit is not a consequence of
    // the work, and neither is the dial `run` would have done on its first.
    try t.expectEqual(@as(u64, 0), node.stats.steps);
    try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), node.accept.live);
    try t.expect(!node.socket_open);

    // A second `run` on a closed node is the no-op it looks like: the close
    // only runs out of `serving`, so nothing is shut down twice.
    try node.run(t.io, &stop);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(u64, 0), node.stats.steps);
}

/// A runtime that is cancelled the way a real backend is: it answers
/// `checkCancel` with `error.Canceled` until the task blocks cancellation, and
/// it honours `swapCancelProtection` to know when that is.
///
/// Two vtable fields and one double, so every other answer stays the live
/// backend's and the close these tests watch afterwards is a real write rather
/// than a stub. A `checkCancel` that always answered `error.Canceled` would
/// describe a runtime no backend is: the protection `run` relies on to write
/// its CONNECTION_CLOSEs is exactly what such a double ignores.
/// Kept on the thread that asked for it: the vtable slot receives only the
/// backend's own userdata, so a per-test struct could not reach it without
/// taking every other slot's userdata with it and breaking the live backend.
threadlocal var cancel_protection: std.Io.CancelProtection = .unblocked;

/// The two slots of an otherwise untouched vtable, and the whole of the double.
fn cancelledCheck(userdata: ?*anyopaque) std.Io.Cancelable!void {
    _ = userdata;
    if (cancel_protection == .blocked) return;
    return error.Canceled;
}

fn cancelledSwap(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
    _ = userdata;
    const previous = cancel_protection;
    cancel_protection = new;
    return previous;
}

test "a cancelled Io ends the loop, and the node is closed with its closes written" {
    // Two nodes, because the half of the promise that can fail is the one with
    // something to release: `close` writes a CONNECTION_CLOSE per connection
    // before it shuts the descriptor, and that write is the only work the
    // shutdown asks of a runtime at all.
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x61),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x6161);
    defer listener.deinit();

    const peers = [_]Peer{.{
        .id = listener.nodeId(),
        .addr = .{ .ip = listener.address() },
    }};
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0xa1a1);
    defer dialer.deinit();

    // A live connection, established over real sockets exactly as the test
    // above establishes one.
    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }
    try t.expectEqual(@as(usize, 1), dialer.establishedCount());
    try t.expectEqual(@as(usize, 1), listener.establishedCount());

    // A runtime that refuses. Every other answer stays the live backend's, so
    // the close this test watches afterwards is a real write and not a stub.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;

    var stop = Stop.init();
    const steps_before = dialer.stats.steps;
    const written_before = dialer.stats.datagrams_out;
    try t.expectError(error.Canceled, dialer.run(cancelled, &stop));

    // The exit is the cancellation and not the work: one pass ran and stopped at
    // the socket's first question.
    try t.expectEqual(steps_before + 1, dialer.stats.steps);

    // The node is closed. This is the promise, and it is a promise about the
    // exits the loop did not choose: whatever ended `run`, a caller left
    // holding this node holds a closed one — the shutdown out of `serving`, the
    // accepts reaped, the descriptor gone.
    try t.expectEqual(router.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), dialer.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), dialer.accept.live);
    try t.expect(!dialer.socket_open);

    // And the peer was told rather than left to time out, which is the half
    // that needs cancellation protection: `run` answers the cancellation it was
    // given, not the one the close would have hit on the same `Io`.
    try t.expect(dialer.stats.datagrams_out > written_before);

    // The listener closes too, or its `defer deinit` reports an endpoint
    // dropped without a close and the error-level log fails the artifact.
    try listener.close(t.io, at, listener.generator());
}

/// A clock whose answer `Instant` — a signed 64-bit nanosecond count — cannot
/// hold, which is what `error.InstantOutOfRange` is for. One field of an
/// otherwise untouched vtable again, and this time the refusal is the clock
/// rather than the runtime.
fn unusableClock(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
    return .{ .nanoseconds = std.math.maxInt(i96) };
}

test "a clock this node cannot use still closes the node" {
    // The exit before the loop body, and the reason the cleanup is registered
    // before the first clock read rather than after it: `create` has already
    // opened the descriptor, so a caller that gets this error back and then
    // calls `deinit` must not be left holding an endpoint that was never shut.
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x7c),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x3737);
    defer node.deinit();

    var vtable = t.io.vtable.*;
    vtable.now = unusableClock;
    const broken: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };

    var stop = Stop.init();
    try t.expectError(error.InstantOutOfRange, node.run(broken, &stop));

    // Nothing ran, and the node is closed anyway. With no instant to stamp a
    // connection close with there is nothing graceful left to do, so this is the
    // disposal path: the handler released, the descriptor shut, the machine at
    // `closed`.
    try t.expectEqual(@as(u64, 0), node.stats.steps);
    try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), node.accept.live);
    try t.expect(!node.socket_open);
}

test "a close that cannot write is finished by the close after it" {
    // The residue a failed send leaves, and what has to be able to clear it.
    // `close_endpoint` is the only step that touches a runtime, so a socket that
    // refuses its sends stops the machine in `closing_endpoint` with the
    // descriptor open — and a close that refuses to resume there would leave a
    // node nothing can ever finish.
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x62),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0x6262);
    defer listener.deinit();

    const peers = [_]Peer{.{
        .id = listener.nodeId(),
        .addr = .{ .ip = listener.address() },
    }};
    const dialer = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa2),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0xa2a2);
    defer dialer.deinit();

    var at: Instant = start_ns;
    try dialer.start(at, dialer.generator());
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at += time_quantum;
        _ = try dialer.step(t.io, at, dialer.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }
    try t.expectEqual(@as(usize, 1), dialer.establishedCount());

    // A runtime that refuses, and a close that therefore stops on the first
    // send it cannot make.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;
    try t.expectError(error.Canceled, dialer.close(cancelled, at, dialer.generator()));

    // Mid-shutdown, with the descriptor still open: the state this test is for.
    try t.expectEqual(router.Shutdown.Phase.closing_endpoint, dialer.accept.shutdown.phase);
    try t.expect(dialer.socket_open);

    // And the next close finishes it rather than refusing, which means
    // re-performing the step that failed and then reporting it — the machine
    // will not emit `close_endpoint` twice on its own.
    try dialer.close(t.io, at, dialer.generator());
    try t.expectEqual(router.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
    try t.expect(!dialer.socket_open);

    try listener.close(t.io, at, listener.generator());
}

test "a stop becomes due at the instant it was given and not before" {
    var stop = Stop.init();
    try t.expect(!stop.expired(start_ns));
    stop.expireAt(start_ns + time_quantum);
    // One nanosecond short of the deadline is not the deadline.
    try t.expect(!stop.expired(start_ns + time_quantum - 1));
    try t.expect(stop.expired(start_ns + time_quantum));
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// Drive `nodes` in lockstep until `want` says the state has arrived.
///
/// Virtual time moves one quantum a pass and nothing here sleeps, so the bound
/// is on passes and not on a clock — the same discipline the rest of this
/// section runs on.
fn driveUntil(
    nodes: []const *Node,
    at: *Instant,
    want: fn (nodes: []const *Node) bool,
) Error!bool {
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at.* += time_quantum;
        for (nodes) |node| _ = try node.step(t.io, at.*, node.generator());
        if (want(nodes)) return true;
    }
    return false;
}

/// Both clients are established and the relay holds two node ids.
fn bothAdmitted(nodes: []const *Node) bool {
    return nodes[0].clientCount() == 2 and
        nodes[1].stats.relay_established == 1 and
        nodes[2].stats.relay_established == 1;
}

/// The first client has been told that a peer is not at the relay.
fn toldPeerGone(nodes: []const *Node) bool {
    return nodes[1].stats.relay_peer_gone == 1;
}

/// The second client has been handed both of the datagrams queued for it.
fn twoDelivered(nodes: []const *Node) bool {
    return nodes[2].delivered().len >= 2;
}

/// The first client has been handed one datagram.
fn oneDelivered(nodes: []const *Node) bool {
    return nodes[1].delivered().len >= 1;
}

test "a relay admits two clients, forwards both ways, and reports each once" {
    // Two datagrams of queue and one message written per pass. Those three
    // numbers are the whole reason the two queues can be told apart below: a
    // flood of three fills the data queue and the message that goes with it
    // still leaves before the datagrams do.
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 2,
            .queue_depth = 2,
            .drain_room = 1,
        } } },
    }, 0x5150);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xa1a1);
    defer a.deinit();
    const b = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xb2b2);
    defer b.deinit();

    // Three different identities, so no end of this can be the other: the
    // relay proves a client owns its node id, and a client that presented the
    // relay's own certificate would prove nothing.
    try t.expect(a.nodeId().order(b.nodeId()) != .eq);
    try t.expect(a.nodeId().order(relay.nodeId()) != .eq);

    const nodes = [_]*Node{ relay, a, b };
    var at: Instant = start_ns;

    // ── the handshake, twice ──
    const admitted = try driveUntil(&nodes, &at, bothAdmitted);
    if (!admitted) std.debug.print(
        "\nrelay stalled at pass {d}: clients {d} admitted {d} attempts {d} handler {d}\n" ++
            "  a: dials {d} refused {d} auth {d} est {d} established {d}\n" ++
            "  b: dials {d} refused {d} auth {d} est {d} established {d}\n" ++
            "  relay refused {d} oversize {d} unknown {d}\n",
        .{
            at,
            relay.clientCount(),
            relay.stats.relay_admitted,
            relay.stats.attempts,
            relay.stats.handler_connections,
            a.stats.relay_dials,
            a.stats.relay_dials_refused,
            a.stats.relay_auth_sent,
            a.stats.relay_established,
            a.establishedCount(),
            b.stats.relay_dials,
            b.stats.relay_dials_refused,
            b.stats.relay_auth_sent,
            b.stats.relay_established,
            b.establishedCount(),
            relay.stats.relay_refused,
            relay.stats.relay_oversized,
            relay.stats.relay_unknown_target,
        },
    );
    try t.expect(admitted);
    try t.expectEqual(@as(usize, 2), relay.clientCount());
    try t.expectEqual(@as(u64, 2), relay.stats.attempts);
    try t.expectEqual(@as(u64, 2), relay.stats.handler_connections);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    // One challenge signed by each, and one confirmation each: the path taken
    // is the challenge, because this transport has no key material to offer.
    try t.expectEqual(@as(u64, 1), a.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), b.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(u64, 1), b.stats.relay_established);

    // ── two queues, observed rather than assumed ──
    //
    // Three datagrams into a queue of two, and one to a peer nobody holds,
    // all written before the relay next looks. The third datagram cannot be
    // queued and the message about the missing peer goes on the *control*
    // queue, which has all the room there is.
    const stranger = (try identityOf(0x77)).nodeId();
    try a.sendThrough(b.nodeId(), "one");
    try a.sendThrough(b.nodeId(), "two");
    try a.sendThrough(b.nodeId(), "three");
    try a.sendThrough(stranger, "nowhere");

    try t.expect(try driveUntil(&nodes, &at, toldPeerGone));
    // The message did not wait behind the datagrams: when the first client was
    // told, fewer of the queued datagrams had gone out than the relay had
    // taken. Merged into one queue both of them would have gone first and this
    // would be two — which is invariant 9, observed rather than cited.
    try t.expect(b.delivered().len < relay.stats.relay_forwarded);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_forwarded);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_queue_full);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);

    // ── the datagrams themselves, in order ──
    try t.expect(try driveUntil(&nodes, &at, twoDelivered));
    try t.expectEqual(@as(usize, 2), b.delivered().len);
    try t.expectEqual(a.nodeId(), b.delivered()[0].src);
    try t.expectEqualStrings("one", b.delivered()[0].data);
    try t.expectEqual(a.nodeId(), b.delivered()[1].src);
    try t.expectEqualStrings("two", b.delivered()[1].data);

    // ── and the other direction, which is the same relay and no new path ──
    try b.sendThrough(a.nodeId(), "back");
    try t.expect(try driveUntil(&nodes, &at, oneDelivered));
    try t.expectEqual(@as(usize, 1), a.delivered().len);
    try t.expectEqual(b.nodeId(), a.delivered()[0].src);
    try t.expectEqualStrings("back", a.delivered()[0].data);

    // ── admission is once, however many passes follow ──
    var quiet: usize = 0;
    while (quiet < 16) : (quiet += 1) {
        at += time_quantum;
        for (nodes) |node| _ = try node.step(t.io, at, node.generator());
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), relay.clientCount());
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);

    // ── the shutdown, in the order `router.Shutdown` enforces ──
    //
    // The relay's clients are given up in `shutdown_handlers`, which is the
    // first of the three phases, so every disconnect is reported before the
    // endpoint close writes anything at all.
    for (nodes) |node| try node.close(t.io, at, node.generator());
    for (nodes) |node| {
        try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
        try t.expectEqual(@as(usize, 0), node.accept.live);
        try t.expect(!node.socket_open);
    }
    try t.expectEqual(@as(usize, 0), relay.clientCount());
    try t.expectEqual(@as(u64, 2), relay.stats.relay_disconnects);
    // The other two arms stay at zero, and that is the half that matters. A
    // `.disconnected` that is suppressed is the invariant working; a *first*
    // one that is swallowed is a connection the registry has let go of while
    // the relay still believes it has it, and the two look the same from
    // `relay_disconnects` alone. So the arms that would absorb a report —
    // `.duplicate`, which ends a connection a later one had already displaced,
    // and `.promoted`, which ends one and promotes another — are asserted at
    // zero rather than left to the sum.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);
    try t.expectEqual(@as(u64, 1), relay.stats.handler_shutdowns);

    // A second close is the no-op it looks like: the close runs only out of
    // `serving`, so nothing is given up twice and nothing is reported twice.
    for (nodes) |node| try node.close(t.io, at, node.generator());
    try t.expectEqual(@as(u64, 2), relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);
    try t.expectEqual(@as(u64, 1), relay.stats.handler_shutdowns);
}

/// One pass over every node, virtual time one quantum further on.
fn passOnce(nodes: []const *Node, at: *Instant) Error!void {
    at.* += time_quantum;
    for (nodes) |node| _ = try node.step(t.io, at.*, node.generator());
}

test "a relay with no room spends no stream, and admits again once a slot frees" {
    // **One client slot and three clients.** That is the shape that leaves two
    // connections established and unserved on every pass, and it is where an
    // open before a slot would spend the peer's whole grant on connections that
    // never become clients. `a` is the one the relay takes: the table is walked
    // in the order the clients dialled, and they are stepped in that order.
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5f),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    }, 0x5f5f);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xa1a1);
    defer a.deinit();
    const b = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xb2b2);
    defer b.deinit();
    const c = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc3),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xc3c3);
    defer c.deinit();
    const nodes = [_]*Node{ a, b, c, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;

    // ── one admitted, the other two refused for want of a slot ──
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and relay.stats.relay_refused > 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), relay.clientCount());
    try t.expectEqual(@as(u64, 1), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 3), relay.establishedCount());

    // ── and the refusals spent nothing ──
    //
    // A peer grants a hundred bidi streams (`connection.zig:539`) and the core
    // counts every stream this end opens against that grant for the life of the
    // connection, so a hundred and twenty-eight passes is more than either
    // refused connection could afford if this relay opened before it asked.
    //
    // The two counters say which of those happened: the refusal counter moves
    // every pass and the deferral counter does not move at all, because a relay
    // with no room never reaches the open. That is `serveAdmit`'s order, and it
    // is the whole difference between a client turned away and a connection
    // spent.
    const refused_before = relay.stats.relay_refused;
    pass = 0;
    while (pass < max_passes / 2) : (pass += 1) try passOnce(&nodes, &at);
    try t.expect(relay.stats.relay_refused > refused_before);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_stream_deferred);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 3), relay.establishedCount());

    // ── and a freed slot still finds a client ──
    //
    // The client this relay admitted goes away, which is the only thing that
    // frees a slot, and the connections refused on every pass since are still
    // admissible. Under an open before the slot they spent their grants in the
    // passes above and neither could be served at all — which is a relay that
    // refuses forever and says nothing but a counter.
    try a.close(t.io, at, a.generator());
    const rest = [_]*Node{ b, c, relay };
    pass = 0;
    while (pass < max_passes and relay.stats.relay_admitted < 2) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 1), relay.clientCount());
    try t.expectEqual(@as(u64, 0), relay.stats.relay_stream_deferred);

    // Every node is wound down through the router's shutdown rather than
    // dropped on the floor: a node deinit while still serving logs an error, and
    // four of those would fail this test for a reason that has nothing to do
    // with the passes above.
    for (nodes) |node| try node.close(t.io, at, node.generator());
}

test "a refused stream costs a connection and not the pass, a fault the pass" {
    // Built from an allocator this test can break at a chosen pass, because the
    // fault arm below has to fail *inside* a pass rather than before one: a
    // relay built on an allocator that is already refusing cannot be built at
    // all, and a fault that arrives at construction says nothing about whether
    // the accept path swallows one.
    var failing = t.FailingAllocator.init(t.allocator, .{});
    // **Two client slots and three clients.** That is the shape that leaves a
    // connection established and unserved *while a slot is free*, and it is the
    // only shape in which `serveAdmit` reaches `Stream.open` at all: the slot is
    // asked for first, so a connection refused for want of one is never asked
    // for a stream. Three rather than two because the refusal arm needs a
    // client left over to make the pass worth spending.
    const relay = try Node.create(failing.allocator(), t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 2,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    }, 0x5150);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xa1a1);
    defer a.deinit();
    const b = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xb2b2);
    defer b.deinit();
    const c = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc3),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xc3c3);
    defer c.deinit();
    const nodes = [_]*Node{ a, b, c, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;

    // ── two admitted, the third established and unserved ──
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (relay.stats.relay_admitted == 2 and relay.establishedCount() == 3) break;
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), relay.clientCount());
    try t.expectEqual(@as(usize, 3), relay.establishedCount());

    // The connection this relay is not serving, named by that rather than by the
    // slot the core keeps it in: which slot a connection occupies is the core's
    // ordering, not this test's to assume.
    var idle: ?bridge_mod.Conn = null;
    var index: usize = 0;
    while (relay.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        if (relay.servedFor(conn.id()) != null) continue;
        idle = conn;
        break;
    }
    const held = idle orelse return error.NoUnservedConnection;

    // ── and no stream either ──
    //
    // Zeroing the core's limit turns "a slot is free" into "and the core has no
    // stream id to give", which is the refusal the bridge names and the accept
    // path has to survive.
    //
    // **It has to be now and not a pass earlier.** The core re-applies the
    // peer's transport parameters at the instant the handshake completes
    // (`connection.zig:2650`) — in the same pass, immediately before
    // `serveAdmit` runs — so a limit set before that handshake is a limit the
    // handshake overwrites before anything reads it.
    held.entry.conn.streams.setMaxStreams(0, 8);

    // ── the refusal costs that connection and nothing else ──
    //
    // Closing a served client is the only thing that frees a slot, and the pass
    // after it is the first one that asks for a stream at all. The relay keeps
    // the client it had, the connection it could not open a stream on is
    // counted as deferred rather than refused, and it is counted again on the
    // next pass — which is the whole claim, because these are phases of one
    // pass and the first of them used to end it.
    try a.close(t.io, at, a.generator());
    const rest = [_]*Node{ b, c, relay };
    pass = 0;
    while (pass < max_passes and relay.stats.relay_stream_deferred < 2) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expect(relay.stats.relay_stream_deferred >= 2);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 1), relay.clientCount());

    // And a pass that got past `serveAdmit` is a pass that went on to read: a
    // datagram this relay has to route to a peer it does not hold is routed on
    // one of them, and the client that sent it is told.
    const stranger = (try identityOf(0x77)).nodeId();
    try b.sendThrough(stranger, "nowhere");
    pass = 0;
    while (pass < max_passes and b.stats.relay_peer_gone == 0) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);
    try t.expectEqual(@as(u64, 1), b.stats.relay_peer_gone);

    // ── a genuine fault, at the same call, still fails the pass ──
    //
    // The same connection, still unserved and now holding a stream of credit,
    // so `Stream.open` gets past the limit check and allocates. That allocation
    // is the whole difference between this call and the one above: a refusal the
    // protocol makes temporary, and a fault in this node. The allocator behind
    // this relay refuses the very next allocation.
    held.entry.conn.streams.setMaxStreams(1, 8);
    failing.fail_index = failing.alloc_index;
    const deferred_at_fault = relay.stats.relay_stream_deferred;
    // `CoreRefused` and not `NoStreamRoom`, on the same connection and the same
    // call: the refusal arm above cost this connection a pass and the fault
    // costs the pass, which is the difference the two arms exist to draw.
    try t.expectError(error.CoreRefused, relay.step(t.io, at, relay.generator()));
    try t.expectEqual(deferred_at_fault, relay.stats.relay_stream_deferred);

    // Every node is wound down through the router's shutdown rather than
    // dropped on the floor: a node deinit while still serving logs an error, and
    // four of those would fail this test for a reason that has nothing to do
    // with the arms above it.
    for (nodes) |node| try node.close(t.io, at, node.generator());
}

test "a frame a peer stopped writing is counted and dropped, never read as a message" {
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x60),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    }, 0x6060);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa4),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xa4a4);
    defer a.deinit();
    const nodes = [_]*Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and relay.clientCount() == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), relay.clientCount());

    // Half a frame, and then the end of the stream: a length whose bytes the
    // writer never sent. **This is what `Stream.drain` cannot report.** It
    // answers whether it appended bytes and nothing about what came before them,
    // so a stream that ended here and a stream with nothing on it read the same,
    // and `discardTail` is what tells them apart.
    const half = [_]u8{ 8, 0x51, 0x50 };
    // Both established above, so an absent spoke or stream here is a defect in
    // the path that got here and not a condition this test allows for. It is
    // returned rather than unwrapped so the runner reports which test broke
    // and the assertions below still say what was true of the wire.
    const spoke = a.spoke orelse return error.TestUnexpectedResult;
    var out = spoke.stream orelse return error.TestUnexpectedResult;
    try out.write(&half);
    out.close();

    pass = 0;
    while (pass < max_passes and relay.stats.relay_stream_truncated == 0) : (pass += 1) {
        try passOnce(&nodes, &at);
    }
    try t.expectEqual(@as(u64, 1), relay.stats.relay_stream_truncated);
    // And it was never a message: a length this relay could not read is a
    // length it refuses rather than one it decodes.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_datagrams_in);

    // Counted once, not on every pass after it: the bytes are gone.
    const truncated = relay.stats.relay_stream_truncated;
    pass = 0;
    while (pass < 8) : (pass += 1) try passOnce(&nodes, &at);
    try t.expectEqual(truncated, relay.stats.relay_stream_truncated);

    for (nodes) |node| try node.close(t.io, at, node.generator());
}

/// Three bytes that are a whole relay frame and not the beginning of one: a
/// QUIC varint length of two, then the frame type of `server_confirms_auth`
/// and one payload byte behind it. `relay/frame.zig:725` reads that frame only
/// when its payload is empty and answers `error.InvalidFrame` when it is not,
/// so `peekFrame` has a complete frame to hand over and the answer comes
/// back from `decode` rather than from the length.
///
/// **This is not the half-written frame the test above covers.** There the
/// length names bytes that never arrive and the reader must wait for them;
/// here every byte the length names has arrived, so the frame is this node's
/// to decide about and the decision is made once. A reader that leaves it on
/// the inbox decides about it again on the next pass, and on every pass after
/// that, for as long as the connection lives.
const poison_frame = [_]u8{ 2, 2, 0 };

/// The one client this relay is serving, named by the slot that is live rather
/// than by which connection the core happened to give it.
fn liveSlot(relay: *Node) ?*Served {
    for (relay.clients) |*slot| {
        if (slot.live) return slot;
    }
    return null;
}

test "a relay reads past a frame it cannot decode and does not serve one twice" {
    // **One datagram, then the poison, on one stream.** Both halves of a relay
    // read in one run of bytes and in that order, so the relay has acted on a
    // message and met a frame it cannot decode in a single pass, and whatever
    // it does with the second says what it does with the first.
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x61),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    }, 0x6161);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb1),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xb1b1);
    defer a.deinit();
    const nodes = [_]*Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and relay.clientCount() == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), relay.clientCount());

    // A datagram for a node id this relay holds nobody for, and then the frame
    // that cannot be decoded. The datagram is the one the counters can be read
    // against, which is why it goes first: a frame this relay has already
    // served is told apart from one it has not by what it counted, and not by
    // the pass it counted it in.
    const stranger = (try identityOf(0x77)).nodeId();
    try a.sendThrough(stranger, "one");
    // Established above, as in the test above: absent here is a defect in the
    // path that got here, reported rather than unwrapped.
    const spoke = a.spoke orelse return error.TestUnexpectedResult;
    var out = spoke.stream orelse return error.TestUnexpectedResult;
    try out.write(&poison_frame);

    // The relay is stepped one pass at a time and its refusals are counted
    // rather than returned, because the claim is about the passes *after* the
    // one that fails: a frame read whole and not decodable is answered once,
    // taken off the inbox, and every pass after it is a pass with nothing left
    // to do. `refused < 2` is what stops this loop on a reader that has not
    // done that — one refusal is the claim and a second is the defect.
    var refused: usize = 0;
    var clean: usize = 0;
    pass = 0;
    while (pass < max_passes and refused < 2) : (pass += 1) {
        at += time_quantum;
        _ = try a.step(t.io, at, a.generator());
        if (relay.step(t.io, at, relay.generator())) |_| {
            // Either the frame has not been drained yet or it is gone, and
            // only the second of those ends this loop, so only the second is
            // counted towards leaving it.
            if (refused == 1) clean += 1;
        } else |err| {
            try t.expectEqual(Error.InvalidFrame, err);
            refused += 1;
            clean = 0;
        }
        if (refused == 1 and clean == 4) break;
    }
    try t.expectEqual(@as(usize, 1), refused);

    // Acted on once: not zero, because the datagram was read whole and served
    // before the poison was met, and not once per pass, because the pass that
    // met the poison is not a pass that gave the datagram back.
    try t.expectEqual(@as(u64, 1), relay.stats.relay_datagrams_in);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);
    // And nothing is left on the inbox, which is the state those two counters
    // are otherwise re-derived from on the next pass.
    const slot = liveSlot(relay) orelse return error.NoLiveClient;
    try t.expectEqual(@as(usize, 0), slot.inbox.items.len);

    for (nodes) |node| try node.close(t.io, at, node.generator());
}

test "a relay client reads past a frame it cannot decode and acts on one frame once" {
    // The same three bytes in the other direction, and the same claim. The
    // client half of the protocol is a second copy of the walk `serveMessages`
    // does — framing, decode, act, compact — and a defect in one is not
    // evidence about the other, so both are named here.
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x62),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    }, 0x6262);
    defer relay.deinit();

    const relay_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = relay.address() },
    }};
    const a = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .alpn = relay_alpn,
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    }, 0xb2b2);
    defer a.deinit();
    const nodes = [_]*Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and relay.clientCount() == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), relay.clientCount());

    // The relay writes both frames itself, on the stream it opened to this
    // client, because a client only ever learns what a relay holds from what
    // the relay sends it. `endpoint_gone` is the cheapest frame that is
    // counted when it is acted on and writes nothing back.
    const slot = liveSlot(relay) orelse return error.NoLiveClient;
    const stranger = (try identityOf(0x78)).nodeId();
    try writeRelay(&slot.out, relay.relay_out, .{ .endpoint_gone = stranger });
    try slot.out.write(&poison_frame);

    // Counted, not returned, for the reason the test above gives: the pass
    // that fails is the one the claim is not about, and the four clean passes
    // after it are.
    var refused: usize = 0;
    var clean: usize = 0;
    pass = 0;
    while (pass < max_passes and refused < 2) : (pass += 1) {
        at += time_quantum;
        _ = try relay.step(t.io, at, relay.generator());
        if (a.step(t.io, at, a.generator())) |_| {
            if (refused == 1) clean += 1;
        } else |err| {
            try t.expectEqual(Error.InvalidFrame, err);
            refused += 1;
            clean = 0;
        }
        if (refused == 1 and clean == 4) break;
    }
    try t.expectEqual(@as(usize, 1), refused);

    // Told once, not once per pass: the frame in front of the poison was read
    // whole and acted on, and a pass that fails on the frame behind it does
    // not take the one in front of it back.
    try t.expectEqual(@as(u64, 1), a.stats.relay_peer_gone);
    // And the inbox holds nothing, which is the state that counter is
    // re-derived from on every pass that reads again.
    const inbox = (a.spoke orelse return error.TestUnexpectedResult).inbox;
    try t.expectEqual(@as(usize, 0), inbox.items.len);

    for (nodes) |node| try node.close(t.io, at, node.generator());
}

test "a closing relay client dials no relay" {
    // The window `close`'s own doc opens, taken on the public route. A close
    // that stopped in `closing_endpoint` leaves the machine mid-shutdown with
    // the descriptor open, and the same doc says the next `close` resumes
    // there, so a pass in between is a call this surface permits. The relay
    // client's half of that pass is the one thing on the node that would go and
    // take new work: a connection of its own, for a relay it has never spoken
    // to, on a node that has already said it is going — and `relay_dialled` is
    // latched, so a node driven on after an abandoned shutdown could never dial
    // that relay again.
    //
    // **Both addresses are bound sockets, and neither end ever answers**, which
    // is what makes the claim about this node's own decisions: the dialled
    // connection exists because `start` asked for it, not because anybody
    // replied. `Dialer.dial` sends nothing — it registers a core connection and
    // returns — so no `step` is needed for a connection to exist, and that is
    // what keeps the relay client itself undialed: `converse` runs only inside
    // `step`, and this fixture runs no `step` before the close.
    var peer_recipient = try Socket.create(loopback, .{});
    defer peer_recipient.close();
    var relay_recipient = try Socket.create(loopback, .{});
    defer relay_recipient.close();
    const peers = [_]Peer{.{
        .id = (try identityOf(0xc5)).nodeId(),
        .addr = .{ .ip = peer_recipient.address },
    }};
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc6),
        .listen = loopback,
        .alpn = relay_alpn,
        .peers = &peers,
        .relay = .{ .role = .{ .client = .{
            .id = (try identityOf(0xc7)).nodeId(),
            .addr = .{ .ip = relay_recipient.address },
        } } },
    }, 0xc6c6);
    defer node.deinit();

    // The preconditions, stated positively: one dialled connection, no relay at
    // all, and a node still serving.
    var at: Instant = start_ns;
    try node.start(at, node.generator());
    try t.expectEqual(@as(u64, 1), node.stats.dials);
    try t.expectEqual(router.Shutdown.Phase.serving, node.accept.shutdown.phase);
    try t.expect(!node.relay_dialled);
    try t.expect(node.spoke == null);

    // A close stopped one send short of the descriptor. It needs nothing to be
    // established: the core builds its close flight from whichever seal it
    // holds, and the Initial one is always there (`connection.zig` takes
    // `app_seal orelse handshake_seal orelse initial_seal`), so a connection no
    // pass has touched still owes a CONNECTION_CLOSE.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;
    try t.expectError(error.Canceled, node.close(cancelled, at, node.generator()));
    try t.expectEqual(router.Shutdown.Phase.closing_endpoint, node.accept.shutdown.phase);
    try t.expect(node.socket_open);

    // The pass the window allows. It takes no relay work: no dial, no `spoke` to
    // free, and nothing put on the wire for a relay this node will not speak to.
    at += time_quantum;
    _ = try node.step(t.io, at, node.generator());
    try t.expect(!node.relay_dialled);
    try t.expect(node.spoke == null);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 0), node.stats.relay_auth_sent);

    // And the passes after it, because a guard on one pass and not the next is
    // a pass and not a rule.
    at += time_quantum;
    _ = try node.step(t.io, at, node.generator());
    try t.expect(!node.relay_dialled);
    try t.expect(node.spoke == null);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials);

    // The close that was owed still finishes it, which is what says the pass
    // was refused and not the shutdown.
    try node.close(t.io, at, node.generator());
    try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expect(!node.socket_open);
}

test "a payload the relay handed over is retained once and given back once" {
    // The ownership of one delivered datagram, in both directions: the copy is
    // the node's, and it is freed by exactly one of `clearDelivered` and
    // `deinit`. The relay does not have to be standing up for either — what is
    // under test is the pair of lines that own the payload, not the frames
    // around them.
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x3d),
        .listen = loopback,
        .alpn = relay_alpn,
    }, 0x3d3d);
    defer node.deinit();

    // The node's own storage, so `delivered` and `clearDelivered` are reading
    // and freeing the same list the delivery appended to, and `deinit` finds
    // whatever is left on it.
    node.spoke = .{
        .conn = 0,
        .stream = null,
        .handshake = .{ .established = .signed_challenge },
        .inbox = .empty,
        .delivered = .empty,
    };

    const src = (try identityOf(0x4e)).nodeId();
    const frame = relay_frame.DatagramFrame{
        .node_id = src,
        .datagrams = .{
            .ecn = null,
            .segment_size = null,
            .contents = "from-the-relay",
        },
    };
    const spoke = if (node.spoke) |*active| active else return error.TestUnexpectedResult;

    // **The list refuses it.** The copy is made before the list is asked to
    // hold it, so an append that cannot grow must give the copy back rather
    // than leave one payload behind for every frame refused on the way. The
    // allocator refuses the *second* allocation of the call — the first is the
    // copy — and `t.allocator` underneath it is a leak detector, so a copy
    // nobody frees fails this test even though nothing here can see it.
    {
        var failing = t.FailingAllocator.init(t.allocator, .{});
        failing.fail_index = failing.alloc_index + 1;
        failing.resize_fail_index = failing.resize_index + 1;
        const whole = node.gpa;
        node.gpa = failing.allocator();
        defer node.gpa = whole;
        try t.expectError(error.OutOfMemory, node.retain(spoke, frame));
    }
    try t.expectEqual(@as(usize, 0), node.delivered().len);
    try t.expectEqual(@as(u64, 0), node.stats.relay_datagrams_out);

    // Retained: one copy, the node's own allocator's, counted once, and the
    // source id carried alongside the bytes rather than borrowed from them.
    try node.retain(spoke, frame);
    try t.expectEqual(@as(usize, 1), node.delivered().len);
    try t.expectEqual(src, node.delivered()[0].src);
    try t.expectEqualStrings("from-the-relay", node.delivered()[0].data);
    try t.expectEqual(@as(u64, 1), node.stats.relay_datagrams_out);

    // And given back by exactly one call. `clearDelivered` frees the payload
    // and empties the list together, so a second call has nothing to free and
    // the `defer node.deinit()` above finds nothing either — a double free
    // here would be the other half of the same claim.
    node.clearDelivered();
    try t.expectEqual(@as(usize, 0), node.delivered().len);
    node.clearDelivered();

    // The node still has to be closed rather than dropped: `deinit` reports an
    // endpoint abandoned in `serving` at error level, and an error-level log
    // fails the artifact for a reason that has nothing to do with the payload.
    try node.close(t.io, start_ns, node.generator());
}

test "a message length round-trips at every varint width" {
    // The widths a relay never reaches: a frame here is one datagram and a
    // datagram is `max_datagram` bytes, so nothing this node sends needs the
    // four- or eight-byte form. A length that crosses a width boundary and is
    // read back wrong is a frame decoded as a *different* frame, so the
    // widths are checked here rather than left to a datagram large enough to
    // need them.
    const widths = [_]u64{
        0,     63,            64,      16383,
        16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1,
    };
    var out: [varint_max]u8 = undefined;
    for (widths) |value| {
        const len = try writeVarint(&out, value);
        const read = readVarint(out[0..len]) orelse return error.NoVarint;
        try t.expectEqual(value, read.value);
        try t.expectEqual(len, read.len);
    }
    // A buffer with no room is refused rather than truncated, and half a
    // length is not a length.
    try t.expectError(error.NoRoom, writeVarint(out[0..1], 64));
    try t.expect(readVarint(&.{}) == null);
    try t.expect(readVarint(&.{0x40}) == null);
}

test "every relay role answers a client count, and only a serving relay holds one" {
    // Three roles and one answer each, for a node that has admitted nobody.
    // `.off` and `.client` build no registry at all — `initRelay` returns
    // before the table is initialised — so a count read out of one is a read
    // of bytes nobody wrote, and the memory `create` was handed says nothing
    // about what is in it. Filling that storage with a pattern first is what
    // turns the difference into a failing assertion rather than a lucky one.
    const gossip = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0xa1a1);
    defer closedOnExit(gossip);
    const spoke = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa2),
        .listen = loopback,
        .topic = briskTopic(),
        .relay = .{ .role = .{ .client = .{
            .id = (try identityOf(0xa3)).nodeId(),
            .addr = .{ .ip = loopback },
        } } },
    }, 0xa2a2);
    defer closedOnExit(spoke);
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa4),
        .listen = loopback,
        .topic = briskTopic(),
        .relay = .{ .role = .{ .serve = .{} } },
    }, 0xa4a4);
    defer closedOnExit(relay);

    gossip.registry.len = 3;
    spoke.registry.len = 3;

    try t.expectEqual(@as(usize, 0), gossip.clientCount());
    try t.expectEqual(@as(usize, 0), spoke.clientCount());
    // A serving relay has the table and is answered by it. A fresh one has
    // admitted nobody, which is the same zero the other two are owed rather
    // than a coincidence of uninitialised memory.
    try t.expectEqual(@as(usize, 0), relay.clientCount());
}

test "a start that could not join refuses again, and a start that joined is not repeated" {
    // `max_bootstrap` and one more: the length `Peers.init` refuses, and the
    // length `start` checks first so the list is not half filled before the
    // refusal. The dials happen before that check either way — a peer that was
    // not reached is a fact about the network and is not dialled again — so
    // what this pins is the other half of idempotence: the refusal is a
    // refusal every time, and not a success that joined nothing.
    var recipient = try Socket.create(loopback, .{});
    defer recipient.close();
    var peers: [hyparview.max_bootstrap + 1]Peer = undefined;
    for (&peers, 0..) |*peer, index| {
        peer.* = .{
            .id = (try identityOf(@intCast(0xb0 + index))).nodeId(),
            .addr = .{ .ip = recipient.address },
        };
    }
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb9),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0xb9b9);
    defer closedOnExit(node);

    try t.expectError(error.BootstrapListTooLong, node.start(start_ns, node.generator()));
    // Every peer was attempted exactly once, whichever way the dial answered.
    const attempted = node.stats.dials + node.stats.dials_refused;
    try t.expectEqual(@as(u64, hyparview.max_bootstrap + 1), attempted);

    try t.expectError(error.BootstrapListTooLong, node.start(start_ns, node.generator()));
    try t.expectEqual(attempted, node.stats.dials + node.stats.dials_refused);
    // No join was fed and none is claimed: `gossip_events` is the count of
    // events the layer handled, so a latch set before the check would leave
    // the second call reporting success over a count of nothing.
    try t.expectEqual(@as(u64, 0), node.stats.gossip_events);
    try t.expect(!node.joined);

    // And a node whose list fits is told to join exactly once, which is what
    // `run` leans on: it calls `start` on the first pass and the call after it
    // must not feed a second join.
    const joining = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xba),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0xbaba);
    defer closedOnExit(joining);
    try joining.start(start_ns, joining.generator());
    try t.expect(joining.joined);
    const events = joining.stats.gossip_events;
    try t.expect(events > 0);
    try joining.start(start_ns, joining.generator());
    try t.expectEqual(events, joining.stats.gossip_events);
}

test "a join the gossip layer could not take leaves the node not joined" {
    // One peer, and the *second* allocation `start` makes through this node's
    // own allocator refused: the first is the table the dial loop records the
    // peer in, and the second is the join command's own output list. So the
    // failure lands where the latch is decided rather than beside it.
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xbb),
        .listen = loopback,
        .topic = briskTopic(),
    }, 0xbbbb);
    defer closedOnExit(listener);
    const peers = [_]Peer{.{
        .id = listener.nodeId(),
        .addr = .{ .ip = listener.address() },
    }};
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xbc),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    }, 0xbcbc);
    defer closedOnExit(node);

    var failing = t.FailingAllocator.init(t.allocator, .{});
    failing.fail_index = 1;
    failing.resize_fail_index = 1;
    {
        const whole = node.gpa;
        node.gpa = failing.allocator();
        defer node.gpa = whole;
        try t.expectError(error.OutOfMemory, node.start(start_ns, node.generator()));
    }

    // It did not join, and the event was not counted: the join command is what
    // was refused, so a latch set before it was fed would leave the next
    // `start` a success over nothing. What the refused command left behind is
    // deliberately not fed again here — `step` states that a consumed event is
    // not one to replay — so this claims the latch and nothing about the
    // residue. The allocator goes back at the end of the block above, which is
    // what lets the close and the free below run on the one this node was built
    // with.
    try t.expect(!node.joined);
    try t.expectEqual(@as(u64, 0), node.stats.gossip_events);
}
