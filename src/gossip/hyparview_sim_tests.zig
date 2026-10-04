//! The deterministic simulator, and the runs that decide whether this module
//! agrees with the reference implementation.
//!
//! # Why the harness left `hyparview.zig`
//!
//! The simulator is upstream's `proto/sim.rs`: a discrete-event in-process
//! network that runs several `TopicState`s against each other with a seeded
//! generator, scheduled latencies and a link table. It **allocates**, and that
//! is the whole reason it cannot stay where it was — `hyparview.zig`'s module
//! doc promises "no allocator, no I/O" for every declaration in the file, and a
//! harness holding `std.ArrayList`s and a link table breaks that promise for
//! every reader of the file, not only for the harness's own user.
//!
//! So the harness moved out whole, together with the tests that drive it, and
//! `hyparview.zig` is left holding the two state machines and nothing else.
//!
//! # What this file is for
//!
//! A membership layer that only ever exchanges bytes has not been tested. The
//! deviation this port makes — a `ForwardJoin` that reaches the end of its walk
//! sends a `Neighbor` and does **not** insert, so a peer joins the active view
//! only when it answers — is byte-level invisible: an implementation that
//! inserts eagerly passes every framing test and diverges from the reference
//! only once two of its nodes run against each other. The runs below are where
//! that is caught: four nodes converging on the three links upstream forms, a
//! join into a full view evicting one peer and staying synchronous, a quit
//! leaving the rest connected, and a broadcast reaching the whole swarm.
//!
//! The digest tests exist for the same reason: `rng_seed` makes a whole run
//! reproducible, so two implementations can be handed the same seed and
//! compared byte for byte instead of argued about.
//!
//! # Reach
//!
//! Reached through the native root `src/unit_test.zig` and the socket-free root
//! `src/portable_test.zig`. Nothing here opens a socket, which is why the
//! portable root keeps it: the simulator is the largest piece of gossip
//! coverage there is, and a root that dropped it would report a passing
//! portable suite while testing a third of the module.

const std = @import("std");
const key = @import("../base/key.zig");
const hyparview = @import("hyparview.zig");

/// The broadcast layer, named because the harness spans both: `HarnessError`
/// unions this module's refusals with plumtree's, and `NetworkConfig` carries a
/// plumtree `Config` for the iTree each simulated node runs.
const plumtree = @import("plumtree.zig");

const NodeId = key.NodeId;
const Allocator = std.mem.Allocator;

/// Every production declaration the harness or a run below names unqualified.
///
/// They came out of `hyparview.zig`, where they shared a namespace with the
/// state machines and could spell every one of these bare. They cannot share
/// one now, so each is bound once here and in the order the harness first
/// reaches for it: a binding list is this file's dependency list, and it is
/// only reviewable if it reads in the order the code uses it.
const Nanos = hyparview.Nanos;
const nanos_per_milli = hyparview.nanos_per_milli;
const nanos_per_second = hyparview.nanos_per_second;
const TopicId = hyparview.TopicId;
const topic_id_length = hyparview.topic_id_length;
const PeerInfo = hyparview.PeerInfo;
const PeerInfos = hyparview.PeerInfos;
const max_shuffle_nodes = hyparview.max_shuffle_nodes;
const max_bootstrap = hyparview.max_bootstrap;
const Config = hyparview.Config;
const TopicConfig = hyparview.TopicConfig;
const TopicState = hyparview.TopicState;
const Rng = hyparview.Rng;
const Error = hyparview.Error;
const Peers = hyparview.Peers;
const SwarmMessage = hyparview.SwarmMessage;
const Message = hyparview.Message;
const Command = hyparview.Command;
const InEvent = hyparview.InEvent;
const AppEvent = hyparview.AppEvent;
const OutEvent = hyparview.OutEvent;
const Actions = hyparview.Actions;

/// The testing seam, named here rather than further down: everything below the
/// `sim` namespace is a test, and the harness above it is the fixture they
/// share.
const t = std.testing;

/// The node-id comparison `hyparview` makes, restated rather than imported.
///
/// `hyparview.sameNode` is file-private there, and a test that reached for the
/// production copy would be checking that the module agrees with itself rather
/// than checking that two ids mean the same peer.
fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

/// A deterministic in-process network. Upstream `proto/sim.rs`.
///
/// # Why it is here and not in a test
///
/// Upstream's own comment on the module is that the gossip protocol is
/// I/O-free and `sim.rs` is the way to test it. That is right, and the reason
/// is sharper than "it is convenient": HyParView is a protocol about
/// *agreement*, and a state machine tested only by feeding it messages never
/// checks that two of them agree. The convergence of two nodes' active views
/// is a property of the network, not of either node, and there is no way to
/// observe it without one.
///
/// # Determinism, and where upstream's is not
///
/// Time is a counter this module owns, so there is no clock. Every random
/// choice comes from a generator the caller seeds, and every per-node
/// generator is drawn from the network's, so one seed fixes the whole run.
/// The event queue breaks ties by insertion order, not by a sort.
///
/// Upstream's simulator is *not* reproducible across processes, and cannot be:
/// `pending_neighbor_requests` and `alive_disconnect_peers` are `HashSet`s
/// built on `RandomState`, whose seed is per-process and per-instance, and
/// `refill_active_from_passive` iterates one of them. Two runs of the same
/// binary with the same `SEED` take different paths. Every such set here is a
/// bounded array, so `zig build test` gives the same answer on every machine
/// and in CI, which is the property a simulator has to have to be a test.
/// That is a deliberate divergence and it is the reason the `Zig` port's
/// numbers are not comparable to upstream's event-for-event.
///
/// The bits are not comparable anyway: upstream seeds `ChaCha12` and this
/// seeds `xoshiro256`, so even with identical control flow the two would
/// draw different peers. What *is* comparable, and what the tests here pin, is
/// the outcome: the same neighbour sets, the same `NeighborUp` events, the
/// same number of broadcast deliveries, the same synchrony. Those come from
/// the reference's own test expectations, captured from its source at the
/// commit named at the top of this file.
pub const sim = struct {
    /// How many nodes one simulated swarm holds.
    pub const max_peers = 12;
    /// An undirected link is one unordered pair, so this is the ceiling on how
    /// many can exist.
    const max_conns = max_peers * (max_peers - 1) / 2;
    /// Enough for every link to be torn down inside one tick.
    const max_kills = max_conns;
    /// A microsecond, which is upstream's own grace period. The comment
    /// upstream gives it is the reason it exists: an event queued at the
    /// current instant must land before the disconnect that follows it, so a
    /// node is not removed while a message is on its way to it.
    const disconnect_grace: Nanos = 1_000;
    /// The topic the simulator runs: 32 zero bytes, which is upstream's
    /// `sim::TOPIC` and a fixture rather than a value anyone would choose.
    pub const topic: TopicId = TopicId.fromBytes([_]u8{0} ** topic_id_length);
    /// The number of neighbour events one `neighbourEvents` buffer holds.
    /// Sized for a swarm that reshuffles several times over, which is several
    /// times the node count.
    pub const max_neighbour_events = max_peers * 8;

    /// Everything that can go wrong in the harness rather than in the
    /// protocol. Separate from `Error` because none of it is a protocol
    /// refusal: a simulator asked to add a thirteenth node, or to add one
    /// twice, has been asked something impossible.
    pub const SimError = error{
        PeerIndexOutOfRange,
        DuplicatePeer,
        TooManyDisconnects,
    };

    /// Every way this harness can fail, over both layers. `key.KeyError` is
    /// here because `nodeIdFor` mints a real key from a seed, and a seed that
    /// derives the identity point is a harness input like any other.
    pub const HarnessError = Error || plumtree.Error || SimError ||
        key.KeyError || Allocator.Error;

    /// A node's identity, from a fixed seed. A `NodeId` cannot be made from
    /// arbitrary bytes — `NodeId.fromBytes` rejects anything that is not a
    /// point on the curve — so a simulator of `u64` peer ids has to mint real
    /// keys, deterministically.
    ///
    /// Fallible because `SecretKey.fromSeed` refuses a seed that derives the
    /// identity point, and a `0x5c` fill says nothing about the twelve
    /// indices a swarm holds. A harness caller reports it, a test fails on
    /// it, and both name the seed; `unreachable` could do neither and would
    /// have taken the process down instead.
    pub fn nodeIdFor(index: u8) key.KeyError!NodeId {
        var seed: [key.SecretKey.seed_length]u8 = undefined;
        @memset(&seed, 0x5c);
        seed[0] = index;
        return (try key.SecretKey.fromSeed(seed)).nodeId();
    }

    /// How long a message takes to cross a link. Upstream `LatencyConfig`.
    pub const LatencyConfig = union(enum) {
        /// The same on every link. Upstream `LatencyConfig::Static`.
        fixed: Nanos,
        /// Drawn once per link. Upstream `LatencyConfig::Dynamic`.
        drawn: struct { min: Nanos, max: Nanos },

        pub const default_fixed: LatencyConfig = .{ .fixed = 50 * nanos_per_milli };
        pub const default_drawn: LatencyConfig = .{
            .drawn = .{ .min = 10 * nanos_per_milli, .max = 100 * nanos_per_milli },
        };

        pub fn maxLatency(self: LatencyConfig) Nanos {
            return switch (self) {
                .fixed => |value| value,
                .drawn => |range| range.max,
            };
        }

        fn draw(self: LatencyConfig, rng: *Rng) Nanos {
            return switch (self) {
                .fixed => |value| value,
                .drawn => |range| rng.range(range.min, range.max),
            };
        }
    };

    pub const NetworkConfig = struct {
        latency: LatencyConfig = LatencyConfig.default_drawn,
        membership: Config = .{},
        broadcast: plumtree.Config = .{},

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012
        pub fn topicConfig(self: NetworkConfig) TopicConfig {
            return .{ .membership = self.membership, .broadcast = self.broadcast };
        }
    };

    pub const SimulatorConfig = struct {
        /// The one seed that fixes the whole run.
        rng_seed: u64 = 0,
        peers: u8 = 8,
        gossip_round_timeout: Nanos = 5 * nanos_per_second,
    };

    /// How a swarm is brought up. Upstream `sim::BootstrapMode`.
    pub const BootstrapMode = union(enum) {
        /// Every peer joins one peer.
        single,
        /// The first `count` form a core; the rest join a random core member.
        core: u8,
    };

    /// Something the application saw. Upstream's is a `(PI, TopicId, Event)`
    /// triple; a simulated node is on one topic, so the topic is not repeated.
    pub const SimEvent = struct {
        peer: u8,
        event: AppEvent,
    };

    /// A neighbour change, reduced to two indices and a direction, so a test
    /// can hold a run against upstream's expected event lists.
    pub const NeighbourEvent = struct {
        up: bool,
        a: u8,
        b: u8,
    };

    /// One simulated node, carrying a whole `TopicState`. That is tens of
    /// kilobytes per slot, so whether a slot holds a node is answered by
    /// `Network.occupied` and never by reading a `Peer` `insert` has not
    /// written: the bytes of an unwritten one are the compiler's `undefined`
    /// fill, and asking them whether node 4 is in the swarm is asking a `bool`
    /// field for a bit pattern that is not a bool.
    const Peer = struct {
        id: NodeId,
        /// Whether the node is still on the topic. Upstream drops the whole
        /// per-topic state on `Quit` and then ignores every later event for
        /// it, which is what this flag reproduces: a node that left does not
        /// start answering `Join` requests again because a message arrived.
        joined: bool = false,
        state: TopicState,
    };

    const QueueEntry = struct {
        time: Nanos,
        peer: u8,
        event: InEvent,
    };

    const Conn = struct { a: u8, b: u8 };

    const Latency = struct { conn: Conn, latency: Nanos };

    pub const Network = struct {
        gpa: Allocator,
        /// Where payloads of parked messages are copied. This is the one place
        /// a message outlives the state that produced it, and it is where the
        /// borrow rule both layers document is discharged.
        arena: std.heap.ArenaAllocator,
        rng: Rng,
        config: NetworkConfig,
        time: Nanos,
        /// The three fixed arrays below stay `undefined`, and that is safe for
        /// exactly one reason each: every read of `links` and `latencies` is
        /// cut by its own counter, and every read of `peers` is cut by
        /// `occupied`. Occupancy is therefore a field of its own and not a
        /// flag inside a `Peer` nobody has written.
        peers: [max_peers]Peer,
        /// Which slots hold a node. The only defined record of that.
        occupied: [max_peers]bool,
        peer_count: usize,
        queue: std.ArrayList(QueueEntry),
        events: std.ArrayList(SimEvent),
        links: [max_conns]Conn,
        conn_count: usize,
        latencies: [max_conns]Latency,
        latency_count: usize,

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        pub fn init(
            gpa: Allocator,
            config: NetworkConfig,
            seed: u64,
        ) HarnessError!Network {
            try config.membership.validate();
            return .{
                .gpa = gpa,
                .arena = std.heap.ArenaAllocator.init(gpa),
                .rng = .init(seed),
                .config = config,
                .time = 0,
                .peers = undefined,
                .occupied = [_]bool{false} ** max_peers,
                .peer_count = 0,
                .queue = .empty,
                .events = .empty,
                .links = undefined,
                .conn_count = 0,
                .latencies = undefined,
                .latency_count = 0,
            };
        }

        pub fn deinit(self: *Network) void {
            self.queue.deinit(self.gpa);
            self.events.deinit(self.gpa);
            self.arena.deinit();
            // Everything above is freed, so the struct is poisoned rather than
            // half-reset: a field that still looked like a network would read
            // as a plausible run instead of as the use-after-free that it is.
            self.* = undefined;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Add a node. Upstream `Network::insert_with_config`.
        pub fn insert(self: *Network, index: u8) HarnessError!void {
            if (index >= max_peers) return error.PeerIndexOutOfRange;
            if (self.occupied[index]) return error.DuplicatePeer;
            // Upstream draws each node's generator from the network's, so two
            // nodes in one simulation do not walk in lockstep.
            const rng = self.rng.child();
            // Minted before the slot is written and used twice: a `NodeId` is
            // a key derivation, not a lookup, and a slot written from one
            // `id` and another `state.id` would be a swarm that disagrees
            // with itself about who it is.
            const id = try nodeIdFor(index);
            self.peers[index] = .{
                .id = id,
                .joined = true,
                .state = try TopicState.init(
                    id,
                    null,
                    self.config.topicConfig(),
                    rng,
                ),
            };
            // Marked after the state is built: a `TopicState.init` that fails
            // leaves the slot as it found it.
            self.occupied[index] = true;
            if (index + 1 > self.peer_count) self.peer_count = index + 1;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Add a node and send it a join command. Upstream
        /// `Network::insert_and_join`.
        pub fn insertAndJoin(
            self: *Network,
            index: u8,
            bootstrap: []const u8,
        ) HarnessError!void {
            try self.insert(index);
            var peers: [max_bootstrap]NodeId = undefined;
            for (bootstrap, 0..) |peer, position| peers[position] = try nodeIdFor(peer);
            try self.command(index, .{ .join = try Peers.init(peers[0..bootstrap.len]) });
        }

        pub fn peerOf(self: *const Network, index: u8) ?*const Peer {
            if (index >= max_peers) return null;
            if (!self.occupied[index]) return null;
            return &self.peers[index];
        }

        fn peerSlot(self: *Network, index: u8) ?*Peer {
            if (index >= max_peers) return null;
            if (!self.occupied[index]) return null;
            return &self.peers[index];
        }

        pub fn peerIndexOf(self: *const Network, id: NodeId) ?u8 {
            for (self.peers[0..self.peer_count], 0..) |peer, index| {
                if (!self.occupied[index]) continue;
                if (sameNode(peer.id, id)) return @intCast(index);
            }
            return null;
        }

        /// The membership layer's active view for one node, as node ids.
        pub fn neighbors(self: *const Network, index: u8) []const NodeId {
            const peer = self.peerOf(index) orelse return &.{};
            if (!peer.joined) return &.{};
            return peer.state.swarm.activeView();
        }

        /// Whether a node is still on the topic. Upstream asserts this after a
        /// quit with `network.peer(&3).unwrap().state(&t).is_none()`.
        pub fn hasJoined(self: *const Network, index: u8) bool {
            const peer = self.peerOf(index) orelse return false;
            return peer.joined;
        }

        /// The same view as node indices, which is what a test asserts on.
        pub fn neighborIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
            var count: usize = 0;
            for (self.neighbors(index)) |peer| {
                const found = self.peerIndexOf(peer) orelse continue;
                out[count] = found;
                count += 1;
            }
            return count;
        }

        /// The broadcast layer's eager set as node indices.
        pub fn eagerIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
            const peer = self.peerOf(index) orelse return 0;
            var count: usize = 0;
            for (peer.state.gossip.eagerPeers()) |eager| {
                const found = self.peerIndexOf(eager) orelse continue;
                out[count] = found;
                count += 1;
            }
            return count;
        }

        pub fn hasNeighbor(self: *const Network, index: u8, other: u8) bool {
            var found: [max_peers]u8 = undefined;
            const count = self.neighborIndices(index, &found);
            for (found[0..count]) |candidate| {
                if (candidate == other) return true;
            }
            return false;
        }

        pub fn neighborCount(self: *const Network, index: u8) usize {
            return self.neighbors(index).len;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Hand a command to a node, then run whatever the current instant
        /// has queued. Upstream `Network::command`.
        pub fn command(self: *Network, index: u8, request: Command) HarnessError!void {
            const leaving = request == .quit;
            const parked = try self.park(.{ .command = request });
            try self.enqueue(self.time, index, parked);
            try self.tick();
            if (!leaving) return;
            if (self.peerSlot(index)) |peer| peer.joined = false;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        pub fn runTrips(self: *Network, count: u64) HarnessError!void {
            try self.runDuration(self.config.latency.maxLatency() * count);
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        pub fn runDuration(self: *Network, duration: Nanos) HarnessError!void {
            const end = self.time + duration;
            while (self.queue.items.len > 0 and self.queue.items[0].time <= end) {
                try self.tick();
            }
            self.time = end;
        }

        /// When the next queued event is due, or `null` when nothing is
        /// pending. A gossip round uses this to stop on its timeout.
        pub fn nextTime(self: *const Network) ?Nanos {
            if (self.queue.items.len == 0) return null;
            return self.queue.items[0].time;
        }

        /// Insert keeping the queue ordered by `(time, insertion order)`.
        ///
        /// **The tie-break is part of the contract.** Among events due at the
        /// same instant the earliest *inserted* is handled first, so a node
        /// sees a message before the disconnect that follows it, and a
        /// `Neighbor` before whatever provoked it. Inserting after every entry
        /// whose time is less than or equal to the new one gives that for
        /// free, and it is exactly what upstream's
        /// `BinaryHeap<(TimedEvent, i32)>` does: a reversed `Ord` on the time
        /// and a negated sequence number as the second key, which together pop
        /// equal times first-in-first-out. A queue sorted by peer id, or with
        /// any other tie-break, silently changes the run, and because the
        /// protocol is symmetric the change is invisible in the final views
        /// and visible only in the event counts.
        fn enqueue(
            self: *Network,
            time: Nanos,
            index: u8,
            event: InEvent,
        ) HarnessError!void {
            var at = self.queue.items.len;
            for (self.queue.items, 0..) |entry, position| {
                if (entry.time > time) {
                    at = position;
                    break;
                }
            }
            try self.queue.insert(self.gpa, at, .{
                .time = time,
                .peer = index,
                .event = event,
            });
        }

        fn tick(self: *Network) HarnessError!void {
            if (self.queue.items.len == 0) return;
            const entry = self.queue.orderedRemove(0);
            self.time = entry.time;
            const peer = self.peerSlot(entry.peer) orelse return;
            if (!peer.joined) return;
            if (entry.event == .recv_message) {
                if (self.peerIndexOf(entry.event.recv_message.from)) |other| {
                    self.addConn(other, entry.peer);
                }
            }
            var out: Actions(OutEvent) = .init(self.gpa);
            defer out.deinit();
            try peer.state.handle(entry.event, self.time, &out);

            var kills: [max_kills]Conn = undefined;
            var kill_count: usize = 0;
            for (out.slice()) |event| switch (event) {
                .send_message => |send| {
                    const to = self.peerIndexOf(send.to) orelse continue;
                    const latency = self.latencyBetween(entry.peer, to);
                    const parked = try self.park(.{
                        .recv_message = .{ .from = peer.id, .message = send.message },
                    });
                    try self.enqueue(self.time + latency, to, parked);
                },
                .schedule_timer => |schedule| {
                    const parked = try self.park(.{ .timer_expired = schedule.timer });
                    try self.enqueue(self.time + schedule.after, entry.peer, parked);
                },
                .disconnect_peer => |other| {
                    const to = self.peerIndexOf(other) orelse continue;
                    if (kill_count == max_kills) return error.TooManyDisconnects;
                    kills[kill_count] = .{ .a = @min(entry.peer, to), .b = @max(entry.peer, to) };
                    kill_count += 1;
                },
                .emit_event => |reported| try self.events.append(self.gpa, .{
                    .peer = entry.peer,
                    .event = try self.parkEvent(reported),
                }),
                .peer_data => {},
            };
            for (kills[0..kill_count]) |conn| try self.killConnection(conn.a, conn.b);
        }

        /// Break a link; the other end hears about it one microsecond after the
        /// usual latency, so anything already in flight lands first.
        fn killConnection(self: *Network, a: u8, b: u8) HarnessError!void {
            if (!self.removeConn(a, b)) return;
            const latency = self.latencyBetween(a, b) + disconnect_grace;
            try self.enqueue(self.time + latency, b, .{
                .peer_disconnected = try nodeIdFor(a),
            });
        }

        fn addConn(self: *Network, a: u8, b: u8) void {
            if (a == b) return;
            if (self.findConn(a, b) != null) return;
            if (self.conn_count == max_conns) return;
            self.links[self.conn_count] = .{ .a = @min(a, b), .b = @max(a, b) };
            self.conn_count += 1;
        }

        fn removeConn(self: *Network, a: u8, b: u8) bool {
            for (self.links[0..self.conn_count], 0..) |conn, index| {
                if (conn.a != @min(a, b) or conn.b != @max(a, b)) continue;
                @memmove(
                    self.links[index .. self.conn_count - 1],
                    self.links[index + 1 .. self.conn_count],
                );
                self.conn_count -= 1;
                return true;
            }
            return false;
        }

        fn findConn(self: *const Network, a: u8, b: u8) ?Conn {
            for (self.links[0..self.conn_count]) |conn| {
                if (conn.a == @min(a, b) and conn.b == @max(a, b)) return conn;
            }
            return null;
        }

        /// One latency per link, drawn the first time the link is used and
        /// kept. A link whose speed changed every message would be a different
        /// network on every tick, and the run would stop being reproducible.
        fn latencyBetween(self: *Network, a: u8, b: u8) Nanos {
            const conn: Conn = .{ .a = @min(a, b), .b = @max(a, b) };
            for (self.latencies[0..self.latency_count]) |entry| {
                if (entry.conn.a == conn.a and entry.conn.b == conn.b) return entry.latency;
            }
            const drawn = self.config.latency.draw(&self.rng);
            if (self.latency_count == max_conns) return drawn;
            self.latencies[self.latency_count] = .{ .conn = conn, .latency = drawn };
            self.latency_count += 1;
            return drawn;
        }

        /// Deep-copy an event's payloads into the arena, so a queued message
        /// does not point into the state that emitted it.
        fn park(self: *Network, event: InEvent) HarnessError!InEvent {
            const a = self.arena.allocator();
            return switch (event) {
                .recv_message => |recv| .{ .recv_message = .{
                    .from = recv.from,
                    .message = try parkMessage(a, recv.message),
                } },
                .command => |requested| switch (requested) {
                    .broadcast => |b| .{ .command = .{ .broadcast = .{
                        .content = try a.dupe(u8, b.content),
                        .scope = b.scope,
                    } } },
                    else => .{ .command = requested },
                },
                else => event,
            };
        }

        fn parkEvent(self: *Network, event: AppEvent) HarnessError!AppEvent {
            return switch (event) {
                .received => |received| .{ .received = .{
                    .content = try self.arena.allocator().dupe(u8, received.content),
                    .delivered_from = received.delivered_from,
                    .scope = received.scope,
                } },
                else => event,
            };
        }

        /// Are both layers synchronous? Upstream `check_synchronicity`: every
        /// active neighbour of ours lists us, and every eager peer of ours
        /// lists us.
        ///
        /// This is the check the protocol exists to make true, and the one
        /// thing a state-machine test cannot make. A membership layer that
        /// inserts on `ForwardJoin` passes every message-level test and fails
        /// here, because a node that inserted a peer it never reached believes
        /// in a link the other end has no record of.
        pub fn checkSynchronicity(self: *const Network) bool {
            var ours: [max_peers]u8 = undefined;
            var theirs: [max_peers]u8 = undefined;
            for (self.peers[0..self.peer_count], 0..) |peer, index| {
                if (!self.occupied[index] or !peer.joined) continue;
                const me: u8 = @intCast(index);
                for (peer.state.swarm.activeView()) |neighbour| {
                    const other = self.peerIndexOf(neighbour) orelse continue;
                    // A node that has left the topic has no view to be held
                    // to, which is why upstream's check reaches for a state
                    // that a quit has already removed.
                    if (!self.hasJoined(other)) continue;
                    const count = self.neighborIndices(other, &theirs);
                    if (!hasIndex(theirs[0..count], me)) return false;
                }
                for (peer.state.gossip.eagerPeers()) |eager| {
                    const other = self.peerIndexOf(eager) orelse continue;
                    if (!self.hasJoined(other)) continue;
                    const count = self.eagerIndices(other, &ours);
                    if (!hasIndex(ours[0..count], me)) return false;
                }
            }
            return true;
        }

        /// Links one end still believes in and the other end does not.
        ///
        /// A healthy converged swarm has none, and this is the number that says
        /// so more honestly than "no node is alone": a node can have three
        /// neighbours and one of them can be a fiction.
        ///
        /// It is not always zero, and that is upstream rather than a port
        /// defect. `on_neighbor` treats a `Neighbor` as a *reply* whenever the
        /// sender is in `pending_neighbor_requests`, and a reply is not
        /// answered. So a node that evicts a peer for room, and then receives
        /// the `Neighbor` that peer had sent moments earlier, silently puts it
        /// back — and then processes the `Disconnect` the eviction produced,
        /// which removes the *other* end. The two views disagree and, because
        /// the requester's pending entry is spent, nothing ever asks again.
        /// Upstream has the identical code path; `check_synchronicity` is a
        /// helper, not a property it claims, and its own convergence test
        /// asserts only that no node is left without neighbours.
        ///
        /// What must hold — and what this is for — is that the count does not
        /// grow: a swarm that has stopped joining stops disagreeing.
        pub fn asymmetricLinks(self: *const Network) usize {
            var count: usize = 0;
            var index: u8 = 0;
            while (index < self.peer_count) : (index += 1) {
                if (!self.hasJoined(index)) continue;
                for (self.neighbors(index)) |neighbour| {
                    const other = self.peerIndexOf(neighbour) orelse continue;
                    if (other <= index) continue;
                    if (self.hasNeighbor(other, index)) continue;
                    count += 1;
                }
            }
            return count;
        }

        /// How many nodes have no neighbours at all. A converged swarm has
        /// none, and upstream's bootstrap asserts exactly this.
        pub fn peersWithoutNeighbors(self: *const Network) usize {
            var count: usize = 0;
            for (self.peers[0..self.peer_count], 0..) |_, index| {
                if (!self.occupied[index]) continue;
                if (self.neighborCount(@intCast(index)) == 0) count += 1;
            }
            return count;
        }

        /// The smallest and largest active view in the swarm. Upstream
        /// `NetworkReport`'s active histogram, reduced to its two ends: a mean
        /// would hide the one node that came out empty, which is the number
        /// that matters.
        pub fn activeExtent(self: *const Network) struct { min: usize, max: usize } {
            var smallest: usize = max_peers;
            var largest: usize = 0;
            for (self.peers[0..self.peer_count], 0..) |_, index| {
                if (!self.occupied[index]) continue;
                const count = self.neighborCount(@intCast(index));
                smallest = @min(smallest, count);
                largest = @max(largest, count);
            }
            return .{ .min = smallest, .max = largest };
        }

        /// Every open link. Upstream `Network::conns`.
        pub fn conns(self: *const Network) []const Conn {
            return self.links[0..self.conn_count];
        }

        /// The neighbour changes seen so far, sorted, so a test can hold a run
        /// against upstream's expected event lists.
        pub fn neighbourEvents(
            self: *const Network,
            out: *[max_neighbour_events]NeighbourEvent,
        ) []NeighbourEvent {
            var count: usize = 0;
            for (self.events.items) |seen| switch (seen.event) {
                .neighbor_up => |peer| {
                    if (count == max_neighbour_events) break;
                    const other = self.peerIndexOf(peer) orelse continue;
                    out[count] = .{ .up = true, .a = seen.peer, .b = other };
                    count += 1;
                },
                .neighbor_down => |peer| {
                    if (count == max_neighbour_events) break;
                    const other = self.peerIndexOf(peer) orelse continue;
                    out[count] = .{ .up = false, .a = seen.peer, .b = other };
                    count += 1;
                },
                .received => {},
            };
            const slice = out[0..count];
            std.mem.sort(NeighbourEvent, slice, {}, lessNeighbourEvent);
            return slice;
        }
    };

    fn lessNeighbourEvent(_: void, a: NeighbourEvent, b: NeighbourEvent) bool {
        if (a.a != b.a) return a.a < b.a;
        if (a.b != b.b) return a.b < b.b;
        return !a.up and b.up;
    }

    fn hasIndex(indices: []const u8, wanted: u8) bool {
        for (indices) |index| {
            if (index == wanted) return true;
        }
        return false;
    }

    fn parkMessage(a: Allocator, message: Message) HarnessError!Message {
        return switch (message) {
            .swarm => |swarm| .{ .swarm = try parkSwarm(a, swarm) },
            .gossip => |gossip| switch (gossip) {
                .gossip => |inner| .{ .gossip = .{ .gossip = .{
                    .id = inner.id,
                    .content = try a.dupe(u8, inner.content),
                    .scope = inner.scope,
                } } },
                else => .{ .gossip = gossip },
            },
        };
    }

    fn parkSwarm(a: Allocator, message: SwarmMessage) HarnessError!SwarmMessage {
        return switch (message) {
            .join => |data| .{ .join = try parkData(a, data) },
            .neighbor => |neighbor| .{ .neighbor = .{
                .priority = neighbor.priority,
                .data = try parkData(a, neighbor.data),
            } },
            .forward_join => |forward| .{ .forward_join = .{
                .peer = try parkInfo(a, forward.peer),
                .ttl = forward.ttl,
            } },
            .shuffle => |shuffle| .{ .shuffle = .{
                .origin = shuffle.origin,
                .nodes = try parkInfos(a, shuffle.nodes),
                .ttl = shuffle.ttl,
            } },
            .shuffle_reply => |reply| .{ .shuffle_reply = .{
                .nodes = try parkInfos(a, reply.nodes),
            } },
            .disconnect => |disconnect| .{ .disconnect = disconnect },
        };
    }

    fn parkData(a: Allocator, data: ?[]const u8) HarnessError!?[]const u8 {
        const held = data orelse return null;
        const parked = try a.dupe(u8, held);
        return parked;
    }

    fn parkInfo(a: Allocator, info: PeerInfo) HarnessError!PeerInfo {
        return .{ .id = info.id, .data = try parkData(a, info.data) };
    }

    fn parkInfos(a: Allocator, list: PeerInfos) HarnessError!PeerInfos {
        var parked: [max_shuffle_nodes]PeerInfo = undefined;
        const items = list.slice();
        for (items, 0..) |info, index| parked[index] = try parkInfo(a, info);
        return PeerInfos.init(parked[0..items.len]);
    }

    /// What one broadcast round cost. Upstream's `RoundStats` without its three
    /// ratios: those measure a run against upstream's numbers, and this port's
    /// numbers are not comparable — see the determinism note on `sim`. What is
    /// left is what a port can be held to.
    pub const RoundStats = struct {
        /// Nodes that were supposed to get the message.
        expected: usize,
        /// Nodes that did, counted once each.
        delivered: usize,
        /// `Received` events for a node that already had one. Upstream treats
        /// this as a panic, because deduplication is supposed to make it
        /// impossible; here it is a number a test asserts is zero, which is the
        /// same statement without taking the process down.
        duplicated: usize,
        /// The furthest a message got, in hops from its origin.
        max_round: u16,
    };

    /// A swarm under test. Upstream `proto::sim::Simulator`.
    pub const Simulator = struct {
        network: Network,
        config: SimulatorConfig,

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        pub fn init(
            gpa: Allocator,
            config: SimulatorConfig,
            network_config: NetworkConfig,
        ) HarnessError!Simulator {
            return .{
                .network = try Network.init(gpa, network_config, config.rng_seed),
                .config = config,
            };
        }

        pub fn deinit(self: *Simulator) void {
            self.network.deinit();
            self.* = undefined;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        /// Bring the swarm up. Upstream `Simulator::bootstrap`.
        pub fn bootstrap(self: *Simulator, mode: BootstrapMode) HarnessError!void {
            const count = self.config.peers;
            switch (mode) {
                .single => {
                    try self.network.insertAndJoin(0, &[_]u8{});
                    var index: u8 = 1;
                    while (index < count) : (index += 1) {
                        try self.network.insertAndJoin(index, &[_]u8{0});
                    }
                    try self.network.runTrips(20);
                },
                .core => {
                    const core = @min(mode.core, count);
                    try self.network.insertAndJoin(0, &[_]u8{});
                    var index: u8 = 1;
                    while (index < core) : (index += 1) {
                        try self.network.insertAndJoin(index, &[_]u8{0});
                    }
                    try self.network.runTrips(7);
                    while (index < count) : (index += 1) {
                        const contact: u8 = @intCast(
                            self.network.rng.below(@as(usize, core)),
                        );
                        try self.network.insertAndJoin(index, &[_]u8{contact});
                    }
                    try self.network.runTrips(20);
                },
            }
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        /// Broadcast from one node and count who got it. Upstream
        /// `Simulator::gossip_round`, reduced to a single sender: the
        /// multiple-sender case differs only in how many messages are in
        /// flight, and this port's iTree is the thing under test.
        pub fn gossipRound(
            self: *Simulator,
            from: u8,
            content: []const u8,
        ) HarnessError!RoundStats {
            const expected = if (self.network.peer_count > 0) self.network.peer_count - 1 else 0;
            var stats: RoundStats = .{
                .expected = expected,
                .delivered = 0,
                .duplicated = 0,
                .max_round = 0,
            };
            var seen = [_]bool{false} ** max_peers;
            self.network.events.clearRetainingCapacity();
            try self.network.command(from, .{
                .broadcast = .{ .content = content, .scope = .swarm },
            });
            self.harvest(&stats, &seen);
            const end = self.network.time + self.config.gossip_round_timeout;
            while (stats.delivered < expected) {
                const at = self.network.nextTime() orelse break;
                if (at > end) break;
                try self.network.tick();
                self.harvest(&stats, &seen);
            }
            return stats;
        }

        fn harvest(self: *Simulator, stats: *RoundStats, seen: *[max_peers]bool) void {
            for (self.network.events.items) |event| {
                switch (event.event) {
                    .received => |received| {
                        if (seen[event.peer]) stats.duplicated += 1;
                        seen[event.peer] = true;
                        stats.delivered += 1;
                        stats.max_round = switch (received.scope) {
                            .swarm => |round| @max(stats.max_round, round.value),
                            .neighbors => stats.max_round,
                        };
                    },
                    else => {},
                }
            }
            self.network.events.clearRetainingCapacity();
        }
    };
};

// ---------------------------------------------------------------------------
// The simulator's own runs
// ---------------------------------------------------------------------------

/// Feed one byte to a running digest, so a run can be fingerprinted without
/// being printed.
fn fold(hasher: anytype, value: u8) void {
    var one = [_]u8{value};
    hasher.update(&one);
}

/// A whole run, reduced to a digest: every neighbour change in order, then
/// every node's active view. Two runs agree exactly when these agree.
fn runDigest(seed: u64, peers: u8) sim.HarnessError![32]u8 {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = seed,
        .peers = peers,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (simulator.network.neighbourEvents(&buffer)) |event| {
        fold(&hasher, event.a);
        fold(&hasher, event.b);
        fold(&hasher, @intFromBool(event.up));
    }
    var found: [sim.max_peers]u8 = undefined;
    var index: u8 = 0;
    while (index < peers) : (index += 1) {
        const count = simulator.network.neighborIndices(index, &found);
        fold(&hasher, @intCast(count));
        for (found[0..count]) |neighbour| fold(&hasher, neighbour);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn sameEvents(got: []const sim.NeighbourEvent, want: []const sim.NeighbourEvent) bool {
    if (got.len != want.len) return false;
    for (got, want) |a, b| {
        if (a.a != b.a or a.b != b.b or a.up != b.up) return false;
    }
    return true;
}

fn countReceived(events: []const sim.SimEvent) usize {
    var count: usize = 0;
    for (events) |event| {
        if (event.event == .received) count += 1;
    }
    return count;
}

fn joinOf(peers: []const NodeId) sim.HarnessError!Command {
    return .{ .join = try Peers.init(peers) };
}

// Upstream `proto::test::hyparview_smoke`: four nodes, an active view of two,
// a fixed latency, and three join commands. The expected neighbour events and
// the three surviving links are upstream's own assertions, captured from
// `proto.rs` at the commit named at the top of this file.
test "four nodes converge on the three links upstream does" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const expected = [_]sim.NeighbourEvent{
        .{ .up = true, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 2 },
        .{ .up = true, .a = 1, .b = 0 },
        .{ .up = true, .a = 1, .b = 2 },
        .{ .up = true, .a = 2, .b = 0 },
        .{ .up = true, .a = 2, .b = 1 },
    };
    try t.expect(sameEvents(network.neighbourEvents(&buffer), &expected));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
    // Node 3 was inserted but never asked to join, so it is in no view.
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
}

// The rest of upstream's `hyparview_smoke`: a fourth node joins a full view.
// Upstream accepts either outcome, because which peer node 0 drops is a
// random choice, and asserts the connections and the synchrony either way.
test "a node joining a full view evicts one peer, either one, and stays synchronous" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    network.events.clearRetainingCapacity();
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.runTrips(2);

    // The two possible neighbour-event lists, as upstream writes them. The
    // eviction is random; the shape is not.
    const kept_one = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 1, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    const kept_two = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 2 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 2, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const events = network.neighbourEvents(&buffer);
    try t.expect(sameEvents(events, &kept_one) or sameEvents(events, &kept_two));

    try t.expect(network.hasNeighbor(0, 3));
    try t.expect(network.hasNeighbor(3, 0));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::quit`: a chain of four joins, then the last one
// leaves, and everybody else is still connected to somebody.
test "a node that quits leaves the swarm and the rest stay connected" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(1)}));
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.runTrips(2);

    var seen = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 4) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            seen[found] = true;
        }
    }
    for (seen[0..4]) |present| try t.expect(present);
    try t.expect(network.checkSynchronicity());

    try network.command(3, .quit);
    try network.runTrips(4);

    // Upstream asserts the topic state is gone, which here is the node no
    // longer counting as joined and no longer holding a link.
    try t.expect(!network.hasJoined(3));
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
    var after = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 3) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            after[found] = true;
        }
    }
    try t.expect(after[0]);
    try t.expect(after[1]);
    try t.expect(after[2]);
    try t.expect(!after[3]);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::plumtree_smoke`: six nodes in two components, a
// broadcast that reaches two nodes, the components joined, and a broadcast
// that then reaches all five others.
test "a broadcast reaches the whole swarm, once the halves are joined" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 6,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 6) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(3, try joinOf(&.{}));
    try network.command(4, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.command(5, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.runTrips(4);
    network.events.clearRetainingCapacity();
    try t.expect(network.checkSynchronicity());

    // In the half node 1 is in, two others.
    try network.command(1, .{ .broadcast = .{ .content = "hi1", .scope = .swarm } });
    try network.runTrips(4);
    try t.expectEqual(@as(usize, 2), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());

    // Join the two halves and broadcast again.
    network.events.clearRetainingCapacity();
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(5)}));
    try network.runTrips(3);
    network.events.clearRetainingCapacity();
    try network.command(1, .{ .broadcast = .{ .content = "hi2", .scope = .swarm } });
    try network.runTrips(5);
    try t.expectEqual(@as(usize, 5), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());
}

// The plan's bar: two or more nodes agree on membership, which is a property
// of a network and not of any one state machine. Every node is connected, and
// every link is held by both ends.
test "a bootstrapped swarm converges: nobody is alone, and the disagreement stops" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 7,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);

    // Upstream's own bar for a bootstrapped swarm: nobody is left with no
    // neighbours at all. That is the assertion `big_hyparview` makes, and it
    // is the one a node that never joined would fail.
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const extent = simulator.network.activeExtent();
    try t.expect(extent.max <= 3);
    try t.expect(extent.min >= 1);

    // Convergence, as opposed to merely being non-empty: the run keeps going
    // with nothing left to join, and the disagreement count does not grow. A
    // swarm that kept acquiring one-sided links would be failing, and one
    // that had acquired some and stopped would be merely unlucky — which is
    // upstream's position and is written down in `asymmetricLinks`.
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());

    // And the broadcast built on top of that membership reaches every other
    // node exactly once, without disturbing the membership it was built on.
    const settled = simulator.network.asymmetricLinks();
    const stats = try simulator.gossipRound(0, "hello");
    try t.expectEqual(stats.expected, stats.delivered);
    try t.expectEqual(@as(usize, 0), stats.duplicated);
    try t.expectEqual(settled, simulator.network.asymmetricLinks());
}

// The same run twice, from the same seed, is the same run. Upstream's
// simulator cannot say this: its pending-request and alive-disconnect sets
// are hash sets on a per-process seed, and it iterates one of them.
test "the same seed gives the same run, byte for byte" {
    const first = try runDigest(0x5eed, 8);
    const second = try runDigest(0x5eed, 8);
    try t.expectEqualSlices(u8, &first, &second);
}

// And the seed is what makes it so: a different seed is a different run, and
// an unseeded one would be a different run every time.
test "a different seed is a different run" {
    const first = try runDigest(1, 8);
    const second = try runDigest(2, 8);
    try t.expect(!std.mem.eql(u8, &first, &second));
}

// The second bootstrap mode: a core forms first, then everybody else joins a
// random core member. Same convergence, different topology.
test "a core bootstrap converges the same way" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 3,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.{ .core = 3 });
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());
}

// The harness refuses what it cannot hold, rather than quietly truncating.
test "the simulator refuses a thirteenth node and a duplicate" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 2,
    }, .{ .latency = .default_fixed });
    defer simulator.deinit();
    try simulator.network.insert(0);
    try t.expectError(error.DuplicatePeer, simulator.network.insert(0));
    try t.expectError(error.PeerIndexOutOfRange, simulator.network.insert(sim.max_peers));
}

// The simulator's identities are a fixture, and a fixture that quietly
// produced the same node twice would turn every convergence assertion into a
// tautology. This walks the whole index range, so a degenerate seed panics
// here rather than passing.
test "every simulated node has its own identity" {
    var index: u8 = 0;
    while (index < sim.max_peers) : (index += 1) {
        const mine = try sim.nodeIdFor(index);
        try t.expect(sameNode(mine, try sim.nodeIdFor(index)));
        var other: u8 = 0;
        while (other < sim.max_peers) : (other += 1) {
            if (other == index) continue;
            try t.expect(!sameNode(mine, try sim.nodeIdFor(other)));
        }
    }
}
