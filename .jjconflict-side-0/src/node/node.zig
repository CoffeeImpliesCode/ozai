//! Node-owned transport and protocol lifetimes.
//!
//! A pass admits authenticated inner QUIC connections before driving explicit
//! gossip subscriptions and Store-backed blob transfers. The TCP relay carrier
//! is independent of the application ALPN; synthetic peers never reach UDP.

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

const node_accept = @import("node_accept.zig");
const node_build = @import("node_build.zig");
const node_close = @import("node_close.zig");
const node_config = @import("node_config.zig");
const node_gossip = @import("node_gossip.zig");
const node_gossip_wire = @import("node_gossip_wire.zig");
const node_loop = @import("node_loop.zig");
const node_discovery_wire = @import("node_discovery_wire.zig");
const node_discovery = @import("node_discovery.zig");
const node_stats = @import("node_stats.zig");
const node_transport = @import("node_transport.zig");
const node_holepunch = @import("node_holepunch.zig");
const node_blobs = @import("node_blobs.zig");
const node_relay_runtime = @import("node_relay_runtime.zig");
const node_native = @import("node_native.zig");

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

const Pending = node_gossip.Pending;

// One name per line, each pointing at the file that owns it, so a caller names
// this module and never the file a declaration happens to have moved to. The
// list is the whole of what the rest of the tree is allowed to reach for: every
// other module under `src/node/` is reachable only through here and through the
// siblings below it.

pub const Allocator = node_config.Allocator;
pub const Peer = node_config.Peer;
pub const Config = node_config.Config;
pub const Relay = node_relay_runtime.Config;
pub const Blobs = node_blobs.Config;
pub const Traversal = node_config.Traversal;
pub const Error = node_config.Error;
pub const Stop = node_loop.Stop;
pub const Stats = node_stats.Stats;
pub const gossip_alpn = node_config.gossip_alpn;
pub const blobs_alpn = node_config.blobs_alpn;
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
pub const discovery_default_lookup_interval_ms = node_discovery.default_lookup_interval_ms;
pub const discovery_record_room = node_discovery.record_room;
pub const discovery_max_relays = node_discovery.max_relays;
pub const Discovery = node_config.Discovery;
pub const DiscoveryRelay = node_config.DiscoveryRelay;
pub const DiscoveryRefused = node_discovery_wire.Refused;
pub const DiscoveryOutcome = node_discovery_wire.Outcome;

// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

/// A node: an identity, a socket, a bridge over it, a dialer, the endpoint's
/// accept loop over that bridge, and explicitly subscribed gossip topics.
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
/// `run` and `close` are single-threaded operations on a node one thread owns.
/// The one operation permitted from another thread is `Stop.request`,
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

    /// Borrowed slices, callback context, directories and trust stores outlive
    /// the node. Protocol configuration is fixed at construction.
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
    gossip_topics: []hyparview.TopicState,
    timers: std.ArrayList(Pending),
    named: [named_ring]NodeId,
    named_len: usize,

    /// The gossip send path: the peers this node can reach, the stream each
    /// one's frames go out on, the room a frame is encoded in, and what the
    /// path did with every message the layer asked to be sent.
    ///
    /// **A value and not an allocation, so `create` writes nothing and
    /// `deinit` has nothing to give back.** Every field is fixed storage —
    /// the directory, the stream table, the frame room and the counters —
    /// which is why its default is a complete wire: `node_build.create` is
    /// not given one, and this node can send from its first pass.
    gossip: node_gossip_wire.Wire = .{},

    /// The node's own discovery: the republish timer and the record it
    /// republishes, the two DNS buffers, the TLS entropy, the lookup schedule,
    /// and what every refusal was counted under.
    ///
    /// **A value and not an allocation, so `create` writes nothing and
    /// `deinit` has one answer to give.** `node_discovery.zig`'s module doc is
    /// what the pass does; what matters here is that `step` runs it and
    /// `Stats` reads it, exactly as `gossip` above.
    discovery: node_discovery.State = .{},
    /// Established peer connections and authenticated received-path evidence.
    holepunch: node_holepunch.State,
    blobs: node_blobs.State,
    relay_runtime: node_relay_runtime.State,

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
    /// Static dials and identity-only lookup attempts, recorded even on failure.
    dialled: std.AutoArrayHashMapUnmanaged(NodeId, void),
    /// Whether the gossip layer has been told to join. Set once the join
    /// command has actually been fed, so a `start` that was refused feeds it
    /// on the next call rather than reporting success over nothing. See
    /// `start`'s own rule.
    joined: bool,


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

    /// Leave every explicit gossip subscription and queue protocol disconnects.
    pub fn quitGossip(self: *Node, at: Instant) Error!void {
        return node_gossip.quit(self, at);
    }

    /// Broadcast through the subscribed topic's gossip state machine.
    pub fn broadcast(self: *Node, topic: hyparview.TopicId, content: []const u8, at: Instant) Error!void {
        return node_gossip.broadcast(self, topic, content, .swarm, at);
    }

    /// Broadcast only to the subscribed topic's current neighbors.
    pub fn broadcastNeighbors(self: *Node, topic: hyparview.TopicId, content: []const u8, at: Instant) Error!void {
        return node_gossip.broadcast(self, topic, content, .neighbors, at);
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
    /// A closed node cannot be stepped; transport intake reports the closed socket.
    pub fn step(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
        self.stats.steps += 1;
        var moved = try node_transport.take(self, io, at, random);
        moved = try node_transport.takeRelay(self, io, at, random) or moved;
        // The sweep sits between the drain and the intake, and where it sits is
        // load-bearing rather than tidy. A connection that ended during this
        // pass's timers is already out of the core's table, so its `ConnEntry`
        // is dead — and `admit` walks that table by index, so a sweep after it
        // would leave the walk reading an entry the core had already taken out.
        // Sweeping here frees the dead entries and hands back a dense table,
        // which is what `Conn.drain` documents as the contract for a handle.
        self.bridge.sweep();
        moved = try node_accept.admit(self, io, at, random) or moved;
        moved = try node_accept.drive(self, io, at, random) or moved;
        moved = try node_gossip.receive(self, at) or moved;
        moved = try self.blobs.drive(self.gpa, io, self.bridge) or moved;
        moved = try node_native.pass(self, at, random) or moved;
        moved = try node_transport.drain(self, io, at, random) or moved;
        moved = try node_transport.expire(self, io, at, random) or moved;
        moved = try node_gossip.gossip(self, at) or moved;
        // The discovery pass sits last, and it is the only pass that can
        // block: a question waits on a nameserver and a publish waits on a
        // relay. Everything above it has already moved what it moved this
        // pass, so a relay that is slow costs this pass its own tick and not
        // the loop's. See `node_discovery.zig`'s module doc.
        moved = node_discovery.pass(self, io, at, random) or moved;
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

};

const t = std.testing;
const test_topics = [_]hyparview.TopicId{.fromBytes(@splat(0x42))};

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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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

    // Explicit subscriptions join, schedule timers, and emit membership traffic.
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
        .gossip_topics = &test_topics,
    }, 0x3333);
    defer gate.deinit();
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
    }, 0x3333);
    defer gate.deinit();
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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
        .gossip_topics = &test_topics,
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

const GossipInbox = struct {
    topics: [2]hyparview.TopicId,
    peer: NodeId,
    seen: [2]bool = .{ false, false },
    invalid: bool = false,

    fn receive(context: ?*anyopaque, topic_id: hyparview.TopicId, peer: NodeId, bytes: []const u8) void {
        const self: *GossipInbox = @ptrCast(@alignCast(context.?));
        if (peer.order(self.peer) != .eq or !std.mem.eql(u8, bytes, "multi-topic-payload")) {
            self.invalid = true;
            return;
        }
        for (self.topics, 0..) |subscribed, index| {
            if (topic_id.eql(subscribed)) {
                self.seen[index] = true;
                return;
            }
        }
        self.invalid = true;
    }
};

test "explicit topics deliver application payloads under each topic identity" {
    const topics = [_]hyparview.TopicId{ .fromBytes(@splat(0x61)), .fromBytes(@splat(0x62)) };
    const sender_secret = try identityOf(0x82);
    var inbox: GossipInbox = .{ .topics = topics, .peer = sender_secret.nodeId() };
    const listener = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x81),
        .gossip_topics = &topics,
        .topic = briskTopic(),
        .on_gossip = GossipInbox.receive,
        .on_gossip_context = &inbox,
    }, 0x8181);
    defer closedOnExit(listener);
    const peers = [_]Peer{.{ .id = listener.nodeId(), .addr = .{ .ip = listener.address() } }};
    const sender = try Node.create(t.allocator, t.io, .{
        .secret = sender_secret,
        .peers = &peers,
        .gossip_topics = &topics,
        .topic = briskTopic(),
        .gossip_message = "multi-topic-payload",
    }, 0x8282);
    defer closedOnExit(sender);
    try listener.start(start_ns, listener.generator());
    try sender.start(start_ns, sender.generator());
    var at = start_ns;
    for (0..max_passes) |_| {
        at += time_quantum;
        _ = try sender.step(t.io, at, sender.generator());
        _ = try listener.step(t.io, at, listener.generator());
        if (inbox.seen[0] and inbox.seen[1]) break;
    }
    try t.expect(!inbox.invalid);
    try t.expect(inbox.seen[0]);
    try t.expect(inbox.seen[1]);
}

test "an endpoint without subscriptions does not start gossip" {
    const node = try Node.create(t.allocator, t.io, .{ .secret = try identityOf(0x83) }, 0x8383);
    defer closedOnExit(node);
    try node.start(start_ns, node.generator());
    _ = try node.step(t.io, start_ns + time_quantum, node.generator());
    try t.expectEqual(@as(u64, 0), node.stats.gossip_events);
    try t.expectEqual(@as(usize, 0), node.timers.items.len);
    try t.expectEqual(@as(usize, 0), node.namedPeers().len);
}

test "broadcast refuses a topic this node did not subscribe to" {
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x84),
        .gossip_topics = &test_topics,
    }, 0x8484);
    defer closedOnExit(node);
    try node.start(start_ns, node.generator());
    const events = node.stats.gossip_events;
    try t.expectError(error.UnknownGossipTopic, node.broadcast(
        .fromBytes(@splat(0x43)), "not-subscribed", start_ns,
    ));
    try t.expectEqual(events, node.stats.gossip_events);
}

test "neighbor broadcast refuses an unsubscribed topic before changing gossip state" {
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x85),
        .gossip_topics = &test_topics,
    }, 0x8585);
    defer closedOnExit(node);
    try node.start(start_ns, node.generator());
    const events = node.stats.gossip_events;
    try t.expectError(error.UnknownGossipTopic, node.broadcastNeighbors(
        .fromBytes(@splat(0x43)), "not-subscribed", start_ns,
    ));
    try t.expectEqual(events, node.stats.gossip_events);
}
