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
//! Not wired: **the gossip wire codec is not connected to this node.**
//! `gossip/codec.zig` and the six modules under `gossip/codec/` are a
//! production wire codec — upstream declaration-order tags, postcard framing,
//! byte-budgeted `IHave` chunking, its own fuzz target and tests. It exists,
//! it is exported as `ozai.gossip_codec`, and nothing in `src/node/` imports
//! it. `gossip/hyparview/message.zig` still says of itself that it has no
//! wire codec and that the obsolete `Disconnect` byte waits for one; that
//! second wait is over, because `gossip/codec/membership.zig` writes the
//! byte, and the sentence is behind the layer rather than true of the tree.
//!
//! So every `send_message` membership asks for is counted, in
//! `gossip_membership_asked` and `gossip_broadcast_asked`, and the peer it
//! names is kept in `Node.named`, and nothing else happens to it. That is
//! visible in the counters rather than inferred from silence: a node whose
//! counters grow while nothing arrives at its peer is a finding, and the
//! binary prints both halves. What closes the gap is calling
//! `gossip_codec.encode` on the message a `send_message` carries and handing
//! the frame to the connection table, which is also what a
//! `disconnect_peer` needs before this node can tear a connection down by
//! node id.
//!
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
//!
//! # How this file is arranged
//!
//! This file is the data owner and the front door: the `Node` struct with every
//! field and every public method, the names the rest of the tree reaches for,
//! and the tests at the bottom. Each of those is a reason the rest of `src/node/`
//! is split by what it *does*, not by where a line falls:
//!
//! **The methods are declared here because Zig has nowhere else to put
//! them.** A method is a declaration inside its struct's declaration, so
//! `Node.step` cannot be written in `node_transport.zig` however the work is
//! divided. Every method on `Node` is therefore a forwarder here, and the
//! work it forwards to is a free function in the sibling that owns it,
//! taking `*Node` as its first parameter. That is the only shape this split
//! can take; the alternative is one file holding all of it.
//!
//! - `node_config.zig` — what a node is told to be, and what it refuses.
//! - `node_build.zig` — `create`, `start` and `deinit`: the only way in, the
//!   go-live that dials and joins, and the only way out.
//! - `node_transport.zig` — datagrams in, datagrams out, the core's timers, and
//!   the bounds that size them.
//! - `node_accept.zig` — the endpoint's accept loop and the two operations it
//!   leaves to its caller.
//! - `node_gossip.zig` — the gossip layer's turn, and the peers it names.
//! - `node_loop.zig` — the pass's wait, the clock, `Stop`, and the wind-down.
//! - `node_close.zig` — the shutdown, in the order `router.Shutdown` enforces.
//! - `node_relay_table.zig` — the relay's storage and its client slots;
//!   `node_relay_serve.zig` — admitting a client; `node_relay_forward.zig` —
//!   what the relay does for one; `node_relay_release.zig` — ending one;
//!   `node_relay_client.zig` — the client half, and what a caller does with it;
//!   `node_relay_frame.zig` — the message boundary a WebSocket carried.
//! - `node_stats.zig` — what the node did, counted.

const std = @import("std");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const hyparview = @import("../gossip/hyparview.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_server = @import("../relay/server.zig");

const node_accept = @import("node_accept.zig");
const node_build = @import("node_build.zig");
const node_close = @import("node_close.zig");
const node_config = @import("node_config.zig");
const node_gossip = @import("node_gossip.zig");
const node_loop = @import("node_loop.zig");
const node_relay_client = @import("node_relay_client.zig");
const node_relay_frame = @import("node_relay_frame.zig");
const node_relay_serve = @import("node_relay_serve.zig");
const node_relay_table = @import("node_relay_table.zig");
const node_stats = @import("node_stats.zig");
const node_transport = @import("node_transport.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const Bridge = bridge_mod.Bridge;
const Egress = bridge_mod.Egress;
const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine has
/// to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

const Served = node_relay_table.Served;
const Spoke = node_relay_client.Spoke;
const Pending = node_gossip.Pending;
const relay_table_slots = node_relay_table.relay_table_slots;
const relay_displaced = node_relay_table.relay_displaced;

// One name per line, each pointing at the file that owns it, so a caller names
// this module and never the file a declaration happens to have moved to. The
// list is the whole of what the rest of the tree is allowed to reach for: every
// other module under `src/node/` is reachable only through here and through the
// siblings below it.

pub const Allocator = node_config.Allocator;
pub const Peer = node_config.Peer;
pub const Config = node_config.Config;
pub const Relay = node_config.Relay;
pub const Role = node_config.Role;
pub const Serve = node_config.Serve;
pub const Error = node_config.Error;
pub const Stop = node_loop.Stop;
pub const Stats = node_stats.Stats;
pub const Delivered = node_relay_client.Delivered;
pub const gossip_alpn = node_config.gossip_alpn;
pub const relay_alpn = node_config.relay_alpn;
pub const max_datagram = node_transport.max_datagram;
pub const max_egress = node_transport.max_egress;
pub const send_room = node_transport.send_room;
pub const scratch_room = node_transport.scratch_room;
pub const receive_room = node_transport.receive_room;
pub const max_accepts = node_accept.max_accepts;
pub const max_alpns = node_accept.max_alpns;
pub const max_pending_events = node_accept.max_pending_events;
pub const poll_interval_ms = node_loop.poll_interval_ms;
pub const named_ring = node_gossip.named_ring;
pub const max_close_steps = node_close.max_close_steps;
pub const max_relay_clients = node_relay_table.max_relay_clients;
pub const default_relay_queue_depth = node_relay_table.default_relay_queue_depth;
pub const relay_frame_room = node_relay_frame.relay_frame_room;

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
    /// it draws from. `node_build.create` is where the lifetimes are stated:
    /// what `gpa` must outlive, what `config` is copied and what it borrows,
    /// and which one thing `io` is used for.
    pub fn create(gpa: Allocator, io: std.Io, config: Config, seed: u64) Error!*Node {
        return node_build.create(gpa, io, config, seed);
    }

    /// Free everything the node owns. `node_build.deinit` is where the order is
    /// stated, and why a close that never ran is a misuse rather than a cleanup.
    pub fn deinit(self: *Node) void {
        node_build.deinit(self);
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

    /// Dial every peer the configuration names, once, and tell the gossip layer
    /// to join them. `node_build.start` states what a refused one leaves
    /// behind, and which caller may try again.
    pub fn start(self: *Node, at: Instant, random: std.Random) Error!void {
        return node_build.start(self, at, random);
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
        var moved = try node_transport.take(self, io, at, random);
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
        moved = try node_accept.admit(self, io, at, random) or moved;
        moved = try node_accept.drive(self, io, at, random) or moved;
        moved = try node_relay_serve.relay(self, at, random) or moved;
        moved = try node_transport.drain(self, io, at, random) or moved;
        moved = try node_transport.expire(self, io, at, random) or moved;
        moved = try node_gossip.gossip(self, at) or moved;
        return moved;
    }

    /// Block until the socket has something, or `timeout_ms` passes.
    /// `node_loop.wait` states what a datagram it took does next, and how a
    /// stop signal reaches the loop.
    pub fn wait(self: *Node, io: std.Io, timeout_ms: i32) Error!void {
        return node_loop.wait(self, io, timeout_ms);
    }

    /// Wind the node down, in the order `router.Shutdown` enforces.
    ///
    /// `node_close.close` states what a caller gets back: the machine at
    /// `.closed`, a close that resumes rather than refuses, and an
    /// `error.Canceled` that leaves the phase it reached rather than losing a
    /// node.
    pub fn close(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!void {
        if (self.accept.shutdown.phase == .closed) return;
        try node_close.finish(self, io, at, random);
    }

    /// The loop, with a clock. `stop` ends it, and the node is closed either
    /// way. `node_loop.run` states what the promise covers and which instant a
    /// close is stamped with.
    pub fn run(self: *Node, io: std.Io, stop: *const Stop) Error!void {
        return node_loop.run(self, io, stop);
    }

    /// What this node's relay has handed back, oldest first. A node that has
    /// not reached a relay answers an empty slice, and so does one that has
    /// called `clearDelivered`: both are "nothing is waiting", not "no relay".
    ///
    /// **The slice is a descriptor into a list that grows, and the payloads in
    /// it are not.** Two different lifetimes, and a caller has to know which
    /// one it is holding:
    ///
    /// - *The returned slice* points into `spoke.delivered`, an `ArrayList`
    ///   this node appends to in `node_relay_client.retain`. The next datagram a
    ///   relay hands over may reallocate that list, and the slice this call
    ///   returned describes the old storage. Take the items — or `data.len`, or
    ///   the count — before driving another pass, and take the slice again if you
    ///   need it after one.
    /// - *Each `Delivered.data`* is a copy this node allocated, and it stays
    ///   valid across every later delivery. What ends it is `clearDelivered`,
    ///   or `deinit` if the caller never got there.
    ///
    /// `delivered` takes `*const Node` and mutates nothing, so reading the
    /// list is safe from a caller holding only a shared borrow; it is not safe
    /// from another thread while a pass is running.
    pub fn delivered(self: *const Node) []const Delivered {
        return node_relay_client.delivered(self);
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
        node_relay_client.clearDelivered(self);
    }

    /// Retain one datagram a relay handed this node, owned by the node and
    /// freed by exactly one of `clearDelivered` and `deinit`.
    /// `node_relay_client.retain` states what a list that cannot grow does
    /// with the copy it has already made.
    fn retain(self: *Node, spoke: *Spoke, frame: relay_frame.DatagramFrame) Error!void {
        return node_relay_client.retain(self, spoke, frame);
    }

    /// Send one datagram to `peer` through this node's relay.
    /// `node_relay_client.sendThrough` states what a relay does with it, and
    /// why this queues bytes rather than performing an I/O.
    pub fn sendThrough(self: *Node, peer: NodeId, bytes: []const u8) Error!void {
        return node_relay_client.sendThrough(self, peer, bytes);
    }

    /// How many node ids this relay holds, which is the registry's own answer
    /// and not a count kept beside it.
    /// `node_relay_table.clientCount` states why a node that does not serve
    /// answers zero rather than reading a table nobody filled.
    pub fn clientCount(self: *const Node) usize {
        return node_relay_table.clientCount(self);
    }

    /// The live client slot serving `conn`, and `null` for a connection this
    /// node is not serving. `node_relay_table.servedFor` states why a
    /// connection that is not served still holds a slot.
    fn servedFor(self: *const Node, conn: u64) ?*Served {
        return node_relay_table.servedFor(self, conn);
    }
};

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
    try node_relay_frame.writeRelay(&slot.out, relay.relay_out, .{ .endpoint_gone = stranger });
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
    var out: [node_relay_frame.varint_max]u8 = undefined;
    for (widths) |value| {
        const len = try node_relay_frame.writeVarint(&out, value);
        const read = node_relay_frame.readVarint(out[0..len]) orelse return error.NoVarint;
        try t.expectEqual(value, read.value);
        try t.expectEqual(len, read.len);
    }
    // A buffer with no room is refused rather than truncated, and half a
    // length is not a length.
    try t.expectError(error.NoRoom, node_relay_frame.writeVarint(out[0..1], 64));
    try t.expect(node_relay_frame.readVarint(&.{}) == null);
    try t.expect(node_relay_frame.readVarint(&.{0x40}) == null);
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
