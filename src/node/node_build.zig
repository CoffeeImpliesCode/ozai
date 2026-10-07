//! Building a node, and taking it apart again.
//!
//! `create` is where the project's vocabulary is translated into the seams —
//! once, and nowhere else — and it is also the only way a node exists, because
//! the endpoint lease and the handler context are both taken from the address
//! it returns. `deinit` is the only exit, and it gives back in the reverse
//! order because a guard reaches into the relay table and a client slot points
//! at a connection the core is about to free.
//!
//! `start` is the go-live half between the two: it dials what `Config.peers`
//! names and feeds the gossip layer its join command. It is not part of
//! `create` because a dial needs an instant and a generator, and `create` has
//! a seed rather than either.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_accept = @import("node_accept.zig");
const node_relay_table = @import("node_relay_table.zig");
const node_transport = @import("node_transport.zig");
const node_gossip = @import("node_gossip.zig");
const node_holepunch = @import("node_holepunch.zig");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const node_discovery = @import("node_discovery.zig");
const node_discovery_record = @import("node_discovery_record.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const hyparview = @import("../gossip/hyparview.zig");

const Node = node_mod.Node;
const Allocator = node_config.Allocator;
const Config = node_config.Config;
const Error = node_config.Error;
const NodeId = base_key.NodeId;
const named_ring = node_gossip.named_ring;
const SocketAddr = base_addr.SocketAddr;
const Bridge = bridge_mod.Bridge;
const Instant = bridge_mod.Instant;
const Egress = bridge_mod.Egress;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const Prng = std.Random.DefaultPrng;
const max_egress = node_transport.max_egress;
const send_room = node_transport.send_room;
const scratch_room = node_transport.scratch_room;
const receive_room = node_transport.receive_room;

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
    if (config.discovery.deadline_ms <= 0 or config.discovery.interval_ms == 0 or
        config.discovery.interval_ms > @as(u64, @intCast(std.math.maxInt(i64))) /
            std.time.ns_per_ms or
        (config.discovery.peer_ids.len != 0 and config.discovery.lookup == null and
            !config.discovery.resolve_pkarr) or
        (config.discovery.resolve_pkarr and config.discovery.relay == null))
    {
        return error.InvalidDiscoveryConfig;
    }
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
        .discovery = .{},
        .holepunch = undefined,
    };
    errdefer self.map.deinit(gpa);
    errdefer self.offered.deinit(gpa);
    errdefer self.dialled.deinit(gpa);
    errdefer self.timers.deinit(gpa);

    self.socket = try Socket.create(config.listen, .{});
    errdefer node_transport.shutdownSocket(self);
    self.bridge = try Bridge.create(gpa, io, .{
        // Null on purpose: one pin cannot name every peer, and the pin
        // that is enforced on this node's accepted connections is the
        // per-dial one the dialer carries.
        .expect_peer = null,
        .secret = config.secret,
        .alpn = config.alpn,
        .initial_policy = config.initial_policy,
    }, self.generator());
    errdefer self.bridge.destroy();
    self.holepunch = try node_holepunch.State.init(gpa, self.bridge.manager.max_connections);
    errdefer self.holepunch.deinit(gpa);
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
    try node_relay_table.initRelay(self);
    errdefer node_relay_table.freeRelay(self);

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
    const registered = try builder.accept(config.alpn, node_accept.handler(self));
    // `.fresh` is the only answer here: the table was built a line ago and
    // holds no ALPN, so a `.replaced` would be a second registration for
    // the one protocol this node speaks, which `max_alpns` rules out.
    std.debug.assert(registered == .fresh);
    self.table = builder.build();
    self.accept = endpoint.Loop.init(&self.table, null, &self.tasks);
    self.lease = self.accept.acquire();
    // The node's own record, armed once and republished by the discovery pass
    // on its timer. Not a failure: a node configured with no relay has nothing
    // to publish, and that is `discovery/preset.zig`'s own default rather than
    // a refusal of the node — `arm` counts it by name and leaves the timer
    // unarmed, so the pass never comes due.
    node_discovery_record.arm(self);
    return self;
}

/// Dial every peer the configuration names, once, and tell the gossip layer to
/// join them.
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
/// out inside `node_gossip.feedGossip` — leaves a node willing rather than
/// latched into a success that joined nothing. Re-arming says the caller
/// *may* try, not that a retry is safe: what a failed `feedGossip` left in
/// the gossip layer is not promised to be replayable (`Node.step`'s own
/// rule), and `run` and the binary's own loop both answer a failed `start`
/// by leaving the loop rather than by calling it again. A caller driving
/// `start` itself owns that choice — try once more, or close the node and
/// throw it away.
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
    if (self.config.peers.len + self.config.discovery.peer_ids.len > hyparview.max_bootstrap) {
        return error.BootstrapListTooLong;
    }
    // The command is fed even when no peer was named: an empty list means
    // "be ready to be asked", which is how upstream's bootstrap node starts
    // (`hyparview.Command`'s own doc).
    var ids: [hyparview.max_bootstrap]NodeId = undefined;
    var count: usize = 0;
    for (self.config.peers) |peer| {
        ids[count] = peer.id;
        count += 1;
    }
    for (self.config.discovery.peer_ids) |peer| {
        var duplicate = false;
        for (ids[0..count]) |known| {
            if (known.order(peer) == .eq) duplicate = true;
        }
        if (!duplicate) {
            ids[count] = peer;
            count += 1;
        }
    }
    try node_gossip.feedGossip(self, .{
        .command = .{ .join = try hyparview.Peers.init(ids[0..count]) },
    }, try node_gossip.gossipNow(at));
    // Set after the feed and not before it: a latch set here is what made
    // a refused `start` a success on the next call, over a node that had
    // joined nothing and would never be told otherwise.
    self.joined = true;
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
    node_relay_table.freeRelay(self);
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
    self.discovery.release();
    self.holepunch.deinit(self.gpa);
    node_transport.shutdownSocket(self);
    self.config.secret.deinit();
    self.gpa.destroy(self);
}
