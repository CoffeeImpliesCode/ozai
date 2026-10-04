//! The relay on the wire: a client that finds a relay the way a peer finds one.
//!
//! `src/node/node_tests.zig`'s own relay test is a real test. Three nodes, three
//! sockets, a kernel, the whole QUIC stack, and every counter read off the
//! machinery rather than off a stand-in. What it cannot show is the one step a
//! relay exists to make possible: that a peer holding **nothing but a relay
//! URL** can reach the relay at all. Its two clients are handed
//! `node_mod.address(relay)` — a `SocketAddr` the test built out of the
//! value it was trying to prove a peer could find on its own.
//!
//! # What this file found, and what it added
//!
//! Nothing in the tree turned a `RelayUrl` into anything a dial could use.
//! `base/addr.zig`'s `RelayUrl` parsed, formatted and ordered;
//! `transport/dial.zig` took a `TransportAddr.relay` and resolved it through
//! `base/ula.zig` into a synthetic RFC 4193 address, which is not routable on
//! a socket. The original node driver documented this gap rather than patching
//! around it. `net/probe.zig` decides which relays to ask and
//! `discovery/dns.zig` builds the queries, but every `net_probe_run.Transport`
//! in the tree is a test fake, so there is no resolver to reach either.
//!
//! So this file's addition is `RelayUrl.socketAddr`: the host, when the host
//! is an IP literal, as a `SocketAddr`. That is upstream's own shape —
//! `derp/src/client.rs` parses `url.host` as a `SocketAddr` outright and
//! refuses anything else — and it is pure, so `base` stays a leaf. **The half
//! that needs a name lookup is still open** and is named rather than papered
//! over: a named relay host answers `error.NotAnIpLiteral`, and a caller
//! holding one needs `src/discovery/`, which has no live transport yet. How
//! far this file gets is exactly that far — a peer is given a URL here, the URL
//! becomes a socket, and the socket is what the dial is told.
//!
//! # What is asserted
//!
//! Three things, each against traffic rather than against a fixture:
//!
//! 1. A client reaches a relay it did not place, and a datagram crosses
//!    through that relay in both directions with its bytes intact.
//! 2. Admission is once: a **repeated handshake** — a second connection
//!    presenting the same node id — is admitted, and displaces rather than
//!    making a second entry. Every departure is reported exactly once, and
//!    which arm of `relay_server.Unregister` each one took is named.
//! 3. The two queues are two. A data queue driven to its whole upstream depth
//!    of 512 still lets a control frame through, and the control frame costs
//!    the full data queue nothing.
//!
//! # A finding this file made on its way, and what became of it
//!
//! `node_relay_serve.serveRead` used to read a client's relay stream into
//! `relay_in`, which `node_config.relay_frame_room` sizes for the largest *frame*, while
//! `quic_stream.Stream.take` hands back the largest *read* — the whole
//! contiguous run out of the core's frame sorter, coalesced up to 64 KiB
//! (`vendor/quic/src/quic/stream.zig:72`) — and refused it with `error.NoRoom`
//! after having already popped the bytes. A burst of relay frames wider than
//! one frame therefore killed a serving relay's pass. Confirmed by a second
//! pair of eyes.
//!
//! **It is fixed, and the pacing in the third test is what it cost while it was
//! not.** The read is now `Stream.drain`, which appends whatever the core hands
//! over onto the caller's inbox and so has no fixed size to be too small for —
//! see `src/transport/quic_stream.zig`. There is no `relay_in` left, so
//! `node_config.relay_frame_room` remains a frame-sized buffer bound, not a
//! stream read limit. **What replaced the pacing is a test
//! rather than a note**: the third test's round is now wider than the frame
//! room it used to be paced around, and the fourth drives a burst wider than
//! the stream receive window.
//!
//! The earlier attribution of this to the *outbound* frame bound was wrong and
//! is not repeated here. The read bound and the frame bound were two different
//! numbers being asked to be one; a 6 MiB buffer sized for the run ceiling
//! would have been the other answer and a worse one.
//!
//! # What cannot be measured here, and why it is named
//!
//! "The control frame was written *ahead* of the datagrams" is the other half
//! of invariant 9, and this file does **not** assert it, because the relay's
//! queues are its own storage: nothing outside `src/relay/server.zig` can read
//! their depth or their order. What is observable from here is a client's
//! `node_relay_client.delivered` count, and that count grows with every frame
//! the relay drains — which, while a flood is in, is exactly what is filling
//! the queue. So the two ends of the claim are not independently measurable
//! and the ordering half is named rather than asserted at a bound that would
//! only hold because of how this file schedules its passes.
//!
//! What is asserted instead is the half that *is* checkable from outside, and
//! it is the failure the invariant names: a control frame queued against a
//! data queue at capacity costs that queue nothing, and it arrives. Merged,
//! one queue at capacity refuses the control frame outright — `relay_queue_full`
//! goes up by one and the client is never told — so the refusal counter is the
//! measurement, and the third test holds it still across exactly that message.
//!
//! # Discipline
//!
//! No sleep and no fixed port anywhere in this file. Time is virtual and moves
//! one quantum a pass, every bound is on passes, and every socket binds port
//! zero so the kernel picks. A drive that runs out of passes **names what it
//! was waiting for** and prints all three sides' account before failing: a
//! stall in here is a finding about the relay, and a test that only said "no"
//! would cost the finding.
//! # Six more, and what they are for
//!
//! The four above drive two well-behaved clients at a relay, so every path in
//! them is a path a real peer takes. What they cannot reach is a **misbehaved**
//! one, and a relay is reachable by anything that can complete a QUIC
//! handshake: a peer that answers a challenge with the wrong frame, a peer
//! whose stream ends before it says anything, a peer that declares a
//! gigabyte of frame and sends none of it, a relay that denies a client it has
//! already taken a stream for. Each of those is a peer's behaviour on the
//! wire, and putting it on the wire here means a fixture rather than a reach
//! into a node's storage: `Raw` below is a real socket, a real
//! `quic_bridge.Bridge` and a real `transport_dial.Dialer` driven exactly as
//! `node_runtime.step` drives a node, and the frames it writes are the frames
//! `relay/server.zig` and `relay/client.zig` produce, encoded through
//! `relay/frame.zig` itself.
//!
//! **And a seventh is not misbehaviour at all.** A peer that negotiates no
//! protocol is a conforming RFC 7301 shape — a ClientHello carrying no ALPN
//! extension never reaches the core's `no_application_protocol`, so neither
//! end fails (`vendor/quic/src/quic/tls13.zig:1432-1435`) — and it is here
//! because a relay that read its config's first protocol instead of the
//! handshake's own selection would take a client slot for it. What that costs
//! is proved the way a slot's cost is proved here: a client that *did* name
//! the relay ALPN is still admitted onto the same relay, with one slot.
//!
//! **What each one claims is a consumer-visible thing and nothing else.** A
//! client slot that comes back is proved by the next real `Node` being
//! admitted, never by reading the slot table; a relay serving two protocols
//! is proved by its relay client still getting in while the other protocol's
//! connection stays up; a client that has been refused is proved by
//! `node_relay_client.sendThrough` answering `error.NoRelay` — which is the
//! one assertion of the three a build that kept a usable relay slot past the
//! end of the handshake cannot pass — with what that handshake did carry read
//! off the wire by the far end rather than counted by the client. No counter
//! is asserted that is not the thing the test is about, and none of them is
//! read out of a private field.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const node_config = ozai.node_config;
const node_protocol = ozai.node_protocol;
const node_lifecycle = ozai.node_lifecycle;
const node_runtime = ozai.node_runtime;
const node_close = ozai.node_close;
const node_relay_client = ozai.node_relay_client;
const node_mod = ozai.node;
const Node = node_mod.Node;
const Peer = node_config.Peer;
const RelayUrl = ozai.RelayUrl;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;
const Instant = ozai.transport_quic_conn.Instant;
const router_shutdown = ozai.router_shutdown;
const relay_server = ozai.relay_server_queue;

// The raw peer below, and the wire it speaks. See "Six more" in the module doc.
const relay_frame = ozai.relay_frame_types;
const relay_writer = ozai.relay_frame_writer;
const relay_codec = ozai.relay_frame_codec;
const node_framing = ozai.node_framing;
const Bridge = ozai.transport_quic_bridge.Bridge;
const Dialer = ozai.transport_dial.Dialer;
const Conn = ozai.transport_quic_conn.Conn;
const Egress = ozai.transport_quic_conn.Egress;
const quic_stream = ozai.transport_quic_stream;
const Socket = ozai.transport_socket.Socket;
const ControlBuffer = ozai.transport_socket.ControlBuffer;
const MappedAddrs = ozai.addr_map.MappedAddrs;
const FrameType = relay_frame.FrameType;

/// A test generator, not a security claim: the identity this fixture presents
/// is `SecretKey.fromSeed`, which is what a peer authenticates on.
const Prng = std.Random.DefaultPrng;

/// Where every node binds, with port zero: the kernel picks, so two runs at
/// once and a socket left over from the last one cannot collide.
const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. It never stops; see the module doc.
const start_ns: Instant = 1_000 * std.time.ns_per_s;

/// How far the clock moves per pass. A clock and not a delay: nothing here
/// waits for it to elapse.
const time_quantum: Instant = std.time.ns_per_ms;

/// How many passes one drive may run.
///
/// Generous, because a pass is a handful of syscalls and nothing in this file
/// can block — the third test moves 512 datagrams one per pass at a relay
/// configured with a drain room of one. The bound is a backstop against a run
/// that never converges, not a timer.
const max_passes = 16384;

/// How many passes a drive over a **connection close timeline** may run.
///
/// Four times `max_passes`, and for a reason the other bound has no room for:
/// a slot is handed back when the core finishes draining a connection the
/// relay closed, and that is three PTOs away on a clock this file moves one
/// millisecond a pass. The third test's pass is a handful of syscalls and so is
/// this one, so the number is a backstop against a run that never converges
/// and not a timer either — nothing here waits for it to elapse.
const max_recovery_passes = 65_536;

/// How many queued frames one client may be given per pass in the third test.
///
/// One, and the number is load-bearing in both directions: with more room the
/// relay could empty a full data queue before the control frame was ever
/// queued, and with less than one it could not write the control frame either.
const drain_room: usize = 1;

/// How many datagrams the third test writes between two passes.
///
/// **A convenience now; it was a workaround, and it was for the relay's sake,
/// not this one's.** See the module doc's "A finding this file made on its
/// way": while the relay read a client's stream into a buffer sized for one
/// *frame*, a round had to stay inside one frame or the read was refused after
/// the bytes had been taken. That is fixed, and nothing here defends against it
/// any more — the fourth test drives a burst past every bound that used to
/// matter, including the stream receive window.
///
/// **What this number is still for is this test's own arithmetic.** It walks
/// what the second client ends up holding as a gap-free prefix of the flood
/// with one run of refusals in the middle, and that walk only holds while the
/// queue fills faster than `drain_room` empties it. A wider round empties it as
/// fast as it fills, the refusals interleave with the acceptances, and the walk
/// is wrong — measured, not assumed: at 256 it asks for payload 171 and is
/// handed 254. So the round stays at the width the walk was written against,
/// and the run that is deliberately unbounded is the fourth test's.
const frames_per_round = 8;

/// A datagram payload: its own index, written twice, so every datagram in a
/// flood of them is distinguishable from every other even after the flood runs
/// past the queue's depth and the later ones are refused — and so a byte that
/// was reordered, duplicated or truncated is visible rather than merely absent.
const payload_length = 16;

fn payload(index: u64) [payload_length]u8 {
    var out: [payload_length]u8 = @splat(0xa5);
    var at: usize = 0;
    while (at < payload_length) : (at += 8) {
        std.mem.writeInt(u64, out[at..][0..8], index, .big);
    }
    return out;
}

/// A fixed identity per node, so every run presents the same certificates and
/// a failure reproduces rather than having to be re-diagnosed.
fn identityOf(tag: u8) ozai.KeyError!SecretKey {
    return SecretKey.fromSeed(@splat(tag));
}

/// The nodes one test drives, and the bookkeeping that makes a stall readable.
const Cast = struct {
    relay: *Node,
    /// Admitted first and therefore served first, which is the order the
    /// relay's own client walk runs in.
    ///
    /// Optional because a test whose peer is a fixture has no client to place
    /// here yet, and because a cast is built before the node that answers the
    /// relay is known. The four tests above always fill both.
    first: ?*Node = null,
    second: ?*Node = null,
    /// A fourth node, when one test needs one: the second test dials the same
    /// node id over a second connection, and a node the cast cannot step is a
    /// node that never dials at all.
    again: ?*Node = null,
    /// A peer that is not a `Node`, stepped once per pass after every node.
    ///
    /// A fixture, not a mock: it is a socket and a bridge like any peer, and
    /// nothing about the node under test can see the difference.
    raw: ?*Raw = null,
    /// What the clients were given, kept so a test can hand a fourth node the
    /// same thing without reaching back for the relay's socket.
    route: SocketAddr,
    /// How far virtual time has come.
    at: Instant = start_ns,

    /// The nodes, in drive order, over storage this struct owns. Not a local
    /// of `nodes`: a slice into a frame that died on return is exactly what
    /// `docs/ARCHITECTURE.md` invariant 6 is about, and a test is the last
    /// place in this repository where it should be got wrong.
    order: [4]*Node = undefined,

    /// The senders first and the relay last, so a frame written this pass is
    /// on the wire before the relay is asked to read it. That is the order
    /// `node_runtime.step` is internally ordered for, and the reason a test
    /// driving several nodes should walk them so.
    fn nodes(self: *Cast) []const *Node {
        var len: usize = 0;
        for ([_]?*Node{ self.first, self.second }) |sender| {
            const node = sender orelse continue;
            self.order[len] = node;
            len += 1;
        }
        if (self.again) |extra| {
            self.order[len] = extra;
            len += 1;
        }
        self.order[len] = self.relay;
        return self.order[0 .. len + 1];
    }

    /// The relay as a client is given it: a node id, and the address the URL
    /// named. That is the whole of what a peer knows about a relay before it
    /// has said anything to one.
    fn peer(self: *const Cast) Peer {
        return .{ .id = node_mod.nodeId(self.relay), .addr = .{ .ip = self.route } };
    }

    fn deinit(self: *Cast) void {
        for (self.nodes()) |node| node_lifecycle.deinit(node);
        self.* = undefined;
    }

    /// One pass over every node, and over the raw peer if this cast has one.
    ///
    /// The fixture goes last for the same reason the relay does: a pass ends
    /// with whoever was going to answer having had its chance to hear this
    /// pass. Both orders converge over the passes a drive runs, and neither
    /// waits for anything.
    fn pass(self: *Cast) !void {
        self.at += time_quantum;
        for (self.nodes()) |node| _ = try node_runtime.step(t.io, node, self.at, node_mod.generator(node));
        if (self.raw) |raw_peer| _ = try raw_peer.exchange(self.at);
    }

    /// Drive until `want` holds, or say what was being waited for.
    fn drive(
        self: *Cast,
        what: []const u8,
        want: *const fn (*const Cast) bool,
    ) !void {
        return self.driveWithin(what, want, max_passes);
    }

    /// The same drive over a bound of its own, for a run whose convergence is
    /// a close timeline rather than a queue.
    fn driveWithin(
        self: *Cast,
        what: []const u8,
        want: *const fn (*const Cast) bool,
        passes: usize,
    ) !void {
        var pass_index: usize = 0;
        while (pass_index < passes) : (pass_index += 1) {
            try self.pass();
            if (want(self)) return;
        }
        self.report(what, pass_index);
        return error.Stalled;
    }

    /// Wind every node down through the router's shutdown, and check the order
    /// `router_shutdown.Shutdown` enforces.
    ///
    /// The relay's clients are given up in `shutdown_handlers`, the first of
    /// the three phases, so every report is made before the endpoint close
    /// writes anything at all. A second call is the no-op it looks like: the
    /// close runs only out of `serving`, so nothing is given up twice.
    fn close(self: *Cast) !void {
        for (self.nodes()) |node| {
            try node_close.close(t.io, node, self.at, node_mod.generator(node));
        }
        for (self.nodes()) |node| {
            try t.expectEqual(router_shutdown.Shutdown.Phase.closed, node.accept.shutdown.phase);
            try t.expectEqual(@as(usize, 0), node.accept.live);
            try t.expect(!node.socket_open);
        }
    }

    /// Say what was awaited and what every node has to say about it.
    ///
    /// The numbers are the whole of the diagnosis: what the relay admitted,
    /// what it forwarded, and what each client dialled, established and was
    /// handed. A relay that admits nothing and a relay that admits twice look
    /// identical from the outside, so every side is printed.
    fn report(self: *const Cast, what: []const u8, passes: usize) void {
        const served = self.relay.stats;
        std.debug.print(
            "\nstalled after {d} passes waiting for {s}\n" ++
                "  relay:  node ids {d} admitted {d} replaced {d} promoted {d} refused {d}\n" ++
                "          forwarded {d} in {d} full {d} unknown {d} oversize {d}\n" ++
                "          disconnects {d} duplicates {d} double {d} told {d}\n",
            .{
                passes,
                what,
                node_relay_client.clientCount(self.relay),
                served.relay_admitted,
                served.relay_replaced,
                served.relay_promoted,
                served.relay_refused,
                served.relay_forwarded,
                served.relay_datagrams_in,
                served.relay_queue_full,
                served.relay_unknown_target,
                served.relay_oversized,
                served.relay_disconnects,
                served.relay_duplicates,
                served.relay_double_reports,
                served.relay_told_displaced,
            },
        );
        if (self.first) |client| sayClient("first", client);
        if (self.second) |client| sayClient("second", client);
        if (self.again) |extra| sayClient("again", extra);
    }
};

/// One client's account, in the stall report's own vocabulary. The node id is
/// left out because a `NodeId` has no number formatter, and two clients are
/// told apart by which line of the report they are on.
fn sayClient(label: []const u8, client: *const Node) void {
    std.debug.print(
        "  {s}: dials {d} refused {d} auth {d} established {d} peer-gone {d}" ++
            " displaced {d} sent {d} handed {d}\n",
        .{
            label,
            client.stats.relay_dials,
            client.stats.relay_dials_refused,
            client.stats.relay_auth_sent,
            client.stats.relay_established,
            client.stats.relay_peer_gone,
            client.stats.relay_displaced,
            client.stats.relay_sent,
            node_relay_client.delivered(client).len,
        },
    );
}

/// A serving relay and two clients that reached it by relay URL.
///
/// The URL is built from the address the relay's own socket reports and is
/// then the only thing the clients are given: `Config` and `Peer` never see a
/// `SocketAddr` here, and `node_mod.address(relay)` is not read again after
/// this. Three identities, so no end of this can be the other — the relay
/// proves a client owns the node id it claims, and a client that presented the
/// relay's own certificate would prove nothing.
fn stand(scratch: []u8, serve: node_config.Serve) !Cast {
    const relay = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = serve } },
    });
    errdefer node_lifecycle.deinit(relay);

    // The step this whole file is about, done once and in one place: a relay
    // URL becomes the socket a dial is told. `derp` does the same thing with
    // `url.host` and refuses a name outright; see `RelayUrl.socketAddr`.
    const url = try relayUrl(scratch, node_mod.address(relay));
    const route = try url.socketAddr();
    if (route.order(node_mod.address(relay)) != .eq) return error.UrlNamedAnotherRelay;

    const route_peer = [_]Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = route },
    }};
    const first = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = route_peer[0] } },
    });
    errdefer node_lifecycle.deinit(first);
    const second = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = route_peer[0] } },
    });
    errdefer node_lifecycle.deinit(second);
    return .{ .relay = relay, .first = first, .second = second, .route = route };
}

/// A node holding an existing node's identity, reached by the same URL.
///
/// `seed_tag` is the identity to re-present, and it is the only thing this
/// node shares with the client it duplicates: its generator is its own CSPRNG,
/// drawn from `t.io` by `node_lifecycle.create` like every other node's, so a
/// is not a copy of anything but its key.
fn duplicateOf(cast: *const Cast, seed_tag: u8) !*Node {
    return clientOf(cast, seed_tag);
}

/// The relay URL that names `socket`, spelled the way a peer is handed one.
fn relayUrl(scratch: []u8, socket: SocketAddr) !RelayUrl {
    var host = std.Io.Writer.fixed(scratch);
    try socket.format(&host);
    var text: [80]u8 = undefined;
    return RelayUrl.parse(try std.fmt.bufPrint(&text, "http://{s}/", .{host.buffered()}));
}

/// One of the cast's own clients. The four tests above place both before they
/// ask, so the null arm is this file's own mistake and not a state a run
/// reaches; a test that fills a slot with a fixture instead never asks.
fn own(cast: *const Cast, slot: enum { first, second }) *Node {
    return switch (slot) {
        .first => cast.first orelse unreachable,
        .second => cast.second orelse unreachable,
    };
}

/// Both clients are established and the relay holds two node ids.
fn bothAdmitted(cast: *const Cast) bool {
    return node_relay_client.clientCount(cast.relay) == 2 and
        own(cast, .first).stats.relay_established == 1 and
        own(cast, .second).stats.relay_established == 1;
}

/// The first client has been handed a datagram.
fn oneDelivered(cast: *const Cast) bool {
    return node_relay_client.delivered(own(cast, .first)).len >= 1;
}

/// The second client has been handed a datagram.
fn oneHanded(cast: *const Cast) bool {
    return node_relay_client.delivered(own(cast, .second)).len >= 1;
}

/// The duplicate has displaced the first connection and the first was told.
fn displaced(cast: *const Cast) bool {
    return cast.relay.stats.relay_told_displaced == 1 and
        own(cast, .first).stats.relay_displaced == 1;
}

/// The second client has been told it was displaced by a later connection.
fn toldDisplaced(cast: *const Cast) bool {
    return own(cast, .second).stats.relay_displaced == 1;
}

test "a peer holding a relay URL reaches a relay, and a datagram crosses both ways" {
    var scratch: [80]u8 = undefined;
    var cast = try stand(&scratch, .{ .clients = 2, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    const first = own(&cast, .first);
    const second = own(&cast, .second);
    try t.expect(
        node_mod.nodeId(first).order(node_mod.nodeId(second)) != .eq,
    );
    try t.expect(
        node_mod.nodeId(first).order(node_mod.nodeId(cast.relay)) != .eq,
    );

    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // The handshake each client ran, from the relay's side and the client's.
    // The mechanism is `.signed_challenge` on both ends: this transport has no
    // key material to offer, so a challenge is the only way in.
    try t.expectEqual(@as(usize, 2), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 2), cast.relay.stats.attempts);
    try t.expectEqual(@as(u64, 1), first.stats.relay_dials);
    try t.expectEqual(@as(u64, 1), second.stats.relay_dials);
    try t.expectEqual(@as(u64, 0), first.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 0), second.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 1), first.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), second.stats.relay_auth_sent);
    // Nothing displaced and nothing refused, which is what a relay that has
    // admitted two distinct peers has to say.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_replaced);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_refused);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);

    // ── a datagram each way, through the relay and not between the peers ──
    //
    // Sixteen bytes with a recognisable pattern in them, because a relay that
    // forwarded a datagram of the right length and the wrong content would
    // pass every length check this project has.
    try node_relay_client.sendThrough(
        first,
        node_mod.nodeId(second),
        "first-to-second!!",
    );
    try cast.drive("the second client to be handed the first's datagram", oneHanded);
    try t.expectEqual(@as(usize, 1), node_relay_client.delivered(second).len);
    try t.expectEqual(
        node_mod.nodeId(first),
        node_relay_client.delivered(second)[0].src,
    );
    try t.expectEqualStrings(
        "first-to-second!!",
        node_relay_client.delivered(second)[0].data,
    );

    try node_relay_client.sendThrough(
        second,
        node_mod.nodeId(first),
        "second-to-first!!",
    );
    try cast.drive("the first client to be handed the second's datagram", oneDelivered);
    try t.expectEqual(@as(usize, 1), node_relay_client.delivered(first).len);
    try t.expectEqual(
        node_mod.nodeId(second),
        node_relay_client.delivered(first)[0].src,
    );
    try t.expectEqualStrings(
        "second-to-first!!",
        node_relay_client.delivered(first)[0].data,
    );

    // Each client counted the one datagram it was handed, so the counters say
    // the two frames arrived at two different nodes rather than one node
    // seeing its own twice.
    try t.expectEqual(@as(u64, 1), first.stats.relay_datagrams_out);
    try t.expectEqual(@as(u64, 1), second.stats.relay_datagrams_out);
    // And the relay read both datagrams off its clients and queued each of
    // them once. Neither direction is a shortcut: there is no other path
    // between these two sockets, and the relay is the only thing that saw
    // either datagram.
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_datagrams_in);
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_forwarded);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_queue_full);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_unknown_target);

    // ── and a control frame the relay could not have put on a data queue ──
    //
    // A datagram to a node id nobody holds, so the relay answers on the
    // **control** queue. The first client's data queue is empty here, so this
    // is not the overloaded case the third test drives; it is here because it
    // is the one control frame a client can provoke by itself, and its
    // accounting is the same counter either way. `relay_queue_full` not moving
    // is the observation: merged, this message would have had to take a slot.
    const stranger = (try identityOf(0x77)).nodeId();
    try node_relay_client.sendThrough(first, stranger, "no such peer");
    try cast.drive("the first client to be told that peer is not at the relay", toldPeerGone);
    try t.expectEqual(@as(u64, 1), first.stats.relay_peer_gone);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_unknown_target);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_queue_full);

    // ── admission is once, however many passes follow ──
    var quiet: usize = 0;
    while (quiet < 32) : (quiet += 1) {
        try cast.pass();
    }
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);

    // ── and every departure is reported exactly once ──
    try cast.close();
    try t.expectEqual(@as(usize, 0), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_disconnects);

    // **The other three arms stay at zero, and that is the half that
    // matters.** A `.disconnected` that is suppressed is the invariant
    // working; a *first* one that is swallowed is a connection the registry has
    // let go of while the relay still believes it has one, and the two look
    // the same from `relay_disconnects` alone. So the arms that would absorb
    // a report — `.duplicate`, which ends a connection a later one had
    // displaced, `.promoted`, which ends one and promotes another, and
    // `.already_gone`, which is a second exit reaching a connection the
    // registry no longer holds — are asserted at zero rather than left to the
    // sum.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
    try t.expectEqual(
        cast.relay.stats.relay_admitted,
        cast.relay.stats.relay_disconnects + cast.relay.stats.relay_duplicates,
    );

    // A second close is the no-op it looks like: nothing is given up twice and
    // nothing is reported twice.
    try cast.close();
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
}

test "a repeated handshake makes no second entry, and every departure is reported once" {
    var scratch: [80]u8 = undefined;
    // Three client slots, because three connections are about to exist and a
    // relay with no room for the third **refuses** it rather than dropping it
    // (`node_relay_serve.serveAdmit`'s own reason) — which would be a test
    // wrong refusal.
    var cast = try stand(&scratch, .{ .clients = 3, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();
    const first = own(&cast, .first);
    const second = own(&cast, .second);
    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // A fourth node holding the *first* node's identity: the same seed, so the
    // same certificate, so the relay sees the same node id over a second
    // connection. It is given the URL's socket and the node id, exactly as the
    // first was, and it binds its own socket and dials the relay itself.
    const again = try duplicateOf(&cast, 0xa1);
    cast.again = again;

    // ── admitted again, and no second entry ──
    //
    // Three handshakes have run and two of them proved the same node id, so
    // the registry holds two node ids and not three — a repeated handshake
    // takes the entry rather than making one. `relay_admitted` counts
    // *connections*, which is why it is three and the registry's count is not.
    try cast.drive("the duplicate to be admitted and the first to be told", displaced);
    try t.expectEqual(@as(u64, 3), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_replaced);
    try t.expectEqual(@as(u64, 1), again.stats.relay_established);
    try t.expectEqual(@as(u64, 1), first.stats.relay_established);

    // The displaced connection was told over its **control** queue, which is
    // the queue a full data queue would have nothing to do with.
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_told_displaced);
    try t.expectEqual(@as(u64, 1), first.stats.relay_displaced);

    // And the relay forwards to whichever connection is now the active one: a
    // datagram the duplicate sends reaches the second client carrying the node
    // id of the identity it re-presented.
    try node_relay_client.sendThrough(
        again,
        node_mod.nodeId(second),
        "after-the-replacement",
    );
    try cast.drive("the second client to be handed the replacement's datagram", oneHanded);
    try t.expectEqual(@as(usize, 1), node_relay_client.delivered(second).len);
    try t.expectEqual(
        node_mod.nodeId(first),
        node_relay_client.delivered(second)[0].src,
    );
    try t.expectEqualStrings(
        "after-the-replacement",
        node_relay_client.delivered(second)[0].data,
    );

    // ── three connections, three reports, none twice ──
    try cast.close();
    try t.expectEqual(@as(usize, 0), node_relay_client.clientCount(cast.relay));

    // Two of the three departures are `.disconnected`: nothing was waiting to
    // be promoted. The first node's *first* connection is the one that ended
    // through `.duplicate`, because a later connection for its node id had
    // already displaced it — and that is the arm that exists so a displaced
    // connection's departure does not take the entry with it.
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_promoted);
    // **Zero is the whole claim**: three connections were admitted and three
    // reports were made, so none was made twice and none reached a connection
    // the registry had already let go of.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
    try t.expectEqual(
        cast.relay.stats.relay_admitted,
        cast.relay.stats.relay_disconnects + cast.relay.stats.relay_duplicates,
    );

    // A second close adds nothing, whichever arm the first one took.
    try cast.close();
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
}

test "a control frame gets through a data queue that is at its whole capacity" {
    const depth = relay_server.per_client_send_queue_depth;
    var scratch: [80]u8 = undefined;
    // Three client slots for three connections, as in the second test: the
    // duplicate needs room to be admitted, and a relay that refuses it has
    // answered a different question than this one asks.
    var cast = try stand(&scratch, .{
        .clients = 3,
        .queue_depth = depth,
        .drain_room = drain_room,
    });
    defer cast.deinit();
    const second = own(&cast, .second);
    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // ── fill the second client's data queue until the relay refuses one ──
    //
    // A refusal is the only way to learn from outside that the queue reached
    // its capacity: the relay's queues are its own storage, nothing publishes
    // their depth, and `forward` refuses rather than overwrites.
    var sent: usize = 0;
    var rounds: usize = 0;
    while (cast.relay.stats.relay_queue_full == 0) : (rounds += 1) {
        if (rounds > max_passes) {
            cast.report("the second client's data queue to reach its capacity", rounds);
            return error.QueueNeverFull;
        }
        try feed(&cast, &sent, frames_per_round);
        try cast.pass();
    }

    // ── hold it at capacity while a duplicate of the second one dials ──
    //
    // **One datagram a pass from here.** The relay drains one queued frame per
    // pass, so a single datagram a pass puts the queue back at all 512 of 512
    // at the start of every `node_relay_serve.serveRead` and never gets
    // refused itself — which freezes `relay_queue_full` for the rest of the
    // drive. Anything that moves it from here is something that had to share
    // the data queue's room, and the control frame below is the candidate.
    const refused_while_full = cast.relay.stats.relay_queue_full;
    // How many datagrams the relay had accepted when the flood stopped, and so
    // how long the run of payloads the second client is holding is before the
    // top-ups start. The queue refused a few *between* accepted ones rather
    // than only at the end — it fills inside a round, so the last round of a
    // flood takes seven and refuses one — so the split is this count and not
    // the queue's depth.
    const filled_before_top_up = cast.relay.stats.relay_forwarded;
    // The duplicate identity gets an independent CSPRNG, not the same
    // predictable connection-ID sequence as the displaced client.
    const again = try duplicateOf(&cast, 0xb2);
    cast.again = again;
    // The loop's condition is the **relay's** counter, not the client's, and
    // that is load-bearing twice over. `relay_told_displaced` moves in the same
    // pass the duplicate is registered, and the last datagram fed before then
    // is read on that same pass and before it — `node_relay_serve.serveRead`
    // walks the flood's client first. So the queue is at capacity at the
    // instant the status is queued, and not one datagram is routed to the
    // connection that replaced it, which is what keeps the second client's
    // list a gap-free run.
    rounds = 0;
    while (cast.relay.stats.relay_told_displaced == 0) : (rounds += 1) {
        if (rounds > max_passes) {
            cast.report("the second client to be told it had been displaced", rounds);
            return error.NeverDisplaced;
        }
        try feed(&cast, &sent, 1);
        try cast.pass();
    }

    // The status is queued; let the client read it.
    try cast.drive("the second client to be told it had been displaced", toldDisplaced);

    // ── what the measurement is ──
    //
    // **The control frame cost the full data queue nothing.** A status frame
    // went out to a client whose datagram queue was at all 512 of 512, and the
    // relay's refusal count did not move by one to let it: under one merged
    // queue this message is a push against a queue with no room, so it would
    // be refused exactly as a datagram is, `relay_queue_full` would be one
    // higher, and the client would never learn it had been displaced. The
    // counter is the relay's own, so this is the model's permission being
    // *checked* rather than cited.
    try t.expectEqual(refused_while_full, cast.relay.stats.relay_queue_full);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_told_displaced);
    try t.expectEqual(@as(u64, 1), second.stats.relay_displaced);

    // And it did not wait for the backlog to drain: the relay still owed this
    // client hundreds of queued datagrams when the status reached it. How
    // *far* ahead of them it went is not readable from outside — the relay's
    // queues are its own storage and nothing publishes their order — so the
    // claim is pinned to what is: the frame went out, and it went out without
    // the backlog having to move first. See the module doc's "What cannot be
    // measured here".
    try t.expect(node_relay_client.delivered(second).len < depth);

    // ── and the whole backlog still arrives, in order, whole ──
    try cast.drive(
        "the second client to be handed every queued datagram",
        allAccepted,
    );
    // Every datagram the relay accepted, and no more: the queue's depth is the
    // bound on how many could be waiting, so a client holding this many has
    // been handed everything and nothing was dropped on the way.
    try t.expectEqual(
        cast.relay.stats.relay_forwarded,
        @as(u64, node_relay_client.delivered(second).len),
    );
    // What the client is holding is every payload the relay accepted, and the
    // queue accepted some and refused others *interleaved* — it fills inside a
    // round, so the last round of the flood takes seven and refuses one. The
    // assertion walks that sequence rather than pretending nothing was ever
    // refused, and every payload carries its own index twice, so a dropped,
    // duplicated or reordered datagram is a difference in the bytes and not
    // only a count.
    for (node_relay_client.delivered(second), 0..) |item, index| {
        try t.expectEqual(node_mod.nodeId(own(&cast, .first)), item.src);
        const want = if (index < filled_before_top_up) index else index + refused_while_full;
        try t.expectEqualSlices(u8, &payload(want), item.data);
    }
    // At least a whole queue's worth of them, so the depth this test is about
    // was really reached and really drained, and nothing was oversized on the
    // way in or out.
    try t.expect(node_relay_client.delivered(second).len >= depth);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_oversized);

    try cast.close();
    // Three connections, three reports: two `.disconnected` and one
    // `.duplicate`, because the second node's *first* connection was the one a
    // later connection for its own node id displaced.
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
}

/// How many datagrams one burst of the fourth test holds.
///
/// **Past every bound the finding above was about.** The relay used to read a
/// client's stream into a buffer sized for one *frame*, so a burst has to be
/// wider than a frame to reach that at all; the run the core hands over is
/// coalesced to 64 KiB (`vendor/quic/src/quic/stream.zig:72`), so it has to be
/// wider than that too; and it has to be wider than the stream receive window
/// the core advertises — 6_291_456 bytes (`stream.zig:1235`) — because a burst
/// that stops under it never asks for the window to be handed back and granted
/// again even once. Every payload here is a whole `node_config.max_datagram`,
/// so a frame is 1535 bytes and this is over six and a half megabytes on the
/// wire.
const burst_datagrams = 4_200;

/// A burst payload: its own index at both ends over a pattern between them, so
/// a datagram that arrives twice, out of order or short is a difference in the
/// bytes and not only a count.
fn wide(index: usize) [node_config.max_datagram]u8 {
    var out: [node_config.max_datagram]u8 = @splat(0x3c);
    std.mem.writeInt(u64, out[0..8], @intCast(index), .big);
    std.mem.writeInt(u64, out[out.len - 8 ..][0..8], @intCast(index), .big);
    return out;
}

test "a burst beyond the receive window keeps serving and accounts for every datagram" {
    const depth = relay_server.per_client_send_queue_depth;
    var scratch: [80]u8 = undefined;
    // A wide drain room, so the backlog comes down in a handful of passes rather
    // than one datagram at a time. This test is about the read, and one
    // datagram a pass would make it a test of the queue's patience as well.
    var cast = try stand(&scratch, .{
        .clients = 2,
        .queue_depth = depth,
        .drain_room = 64,
    });
    defer cast.deinit();
    const first = own(&cast, .first);
    const second = own(&cast, .second);
    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // ── the burst, written before a single pass runs ──
    //
    // Nothing here is paced, and that is the whole of what this test is: the
    // third test above writes its flood a round at a time and reads a frame at a
    // time, which is the shape that let the defect this file found through.
    for (0..burst_datagrams) |index| {
        try node_relay_client.sendThrough(
            first,
            node_mod.nodeId(second),
            &wide(index),
        );
    }

    // ── the relay reads all of it ──
    //
    // `relay_datagrams_in` counts the frames off its clients, so this converges
    // only once the whole burst has been read. Under the defect it never was:
    // the pass that met the first run wider than a frame ended with the bytes
    // already popped, and the rest of the burst went to a relay that was not
    // serving.
    try cast.drive("the relay to read every datagram of the burst", burstRead);

    // ── every datagram accounted for, and nothing lost on the way ──
    //
    // The relay forwards what its queue has room for and refuses the rest, and
    // those two are the whole of what happened to every datagram it read. A
    // byte dropped by a read would make the sum come up short, which is the one
    // thing this accounting cannot call success.
    try t.expectEqual(@as(u64, burst_datagrams), cast.relay.stats.relay_datagrams_in);
    try t.expectEqual(
        cast.relay.stats.relay_datagrams_in,
        cast.relay.stats.relay_forwarded + cast.relay.stats.relay_queue_full,
    );
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_unknown_target);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_oversized);
    // **Nothing was refused, and that is the stronger of the two accountings.**
    // The drain room is wide enough to keep up with a burst this size, so every
    // datagram the relay read went on a queue rather than being turned away, and
    // the identity below is one long sum rather than a split. A read that lost
    // bytes would make it come up short; that is the one thing this cannot call
    // success.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_queue_full);
    try t.expectEqual(@as(u64, burst_datagrams), cast.relay.stats.relay_forwarded);

    // ── and what it did queue arrives whole and in order ──
    try cast.drive(
        "the second client to be handed every queued datagram",
        allAccepted,
    );
    try t.expectEqual(
        cast.relay.stats.relay_forwarded,
        @as(u64, node_relay_client.delivered(second).len),
    );
    // A queue takes datagrams in the order they arrive and gives room back from
    // its head, so what it accepted is a gap-free prefix of the burst: the
    // datagram at index `n` is the one written at index `n`, and no offset is
    // needed to say which datagrams the refusals fell on.
    for (node_relay_client.delivered(second), 0..) |item, index| {
        try t.expectEqual(node_mod.nodeId(first), item.src);
        try t.expectEqualSlices(u8, &wide(index), item.data);
    }

    // ── and the pass is still serving afterwards ──
    //
    // "Survived the burst" and "stopped serving" are not the same claim, and
    // only a datagram written after the burst tells them apart.
    try node_relay_client.sendThrough(
        first,
        node_mod.nodeId(second),
        "after-the-burst",
    );
    try cast.drive(
        "the second client to be handed a datagram after the burst",
        afterBurst,
    );
    const held = node_relay_client.delivered(second);
    try t.expectEqualStrings("after-the-burst", held[held.len - 1].data);

    try cast.close();
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
}

/// Write `count` more datagrams at the second client, numbered from `*sent`.
fn feed(cast: *Cast, sent: *usize, count: usize) !void {
    for (0..count) |offset| {
        try node_relay_client.sendThrough(
            own(cast, .first),
            node_mod.nodeId(own(cast, .second)),
            &payload(sent.* + offset),
        );
    }
    sent.* += count;
}

/// The relay has read every datagram the burst held.
fn burstRead(cast: *const Cast) bool {
    return cast.relay.stats.relay_datagrams_in >= burst_datagrams;
}

/// The second client is holding the datagram written after the burst.
fn afterBurst(cast: *const Cast) bool {
    const held = node_relay_client.delivered(own(cast, .second));
    if (held.len == 0) return false;
    return std.mem.eql(u8, held[held.len - 1].data, "after-the-burst");
}

/// The second client has been handed everything the relay ever accepted.
fn allAccepted(cast: *const Cast) bool {
    return node_relay_client.delivered(own(cast, .second)).len >=
        cast.relay.stats.relay_forwarded;
}

/// The first client has been told that a peer is not at the relay.
fn toldPeerGone(cast: *const Cast) bool {
    return own(cast, .first).stats.relay_peer_gone == 1;
}

// ---------------------------------------------------------------------------
// A peer that is not a Node
// ---------------------------------------------------------------------------

/// One end of the relay protocol that is **not** a `Node`: a real socket, a
/// real `quic_bridge.Bridge` and a real `transport_dial.Dialer`, driven
/// exactly as `node_runtime.step` drives a node and in the same order.
///
/// It exists because **a `Node` in the client role cannot misbehave.** Every
/// path the tests below reach is a peer's behaviour — the wrong frame in the
/// wrong state, a stream that ends, a length prefix for a frame that never
/// arrives, a denial from the far end — and a peer's behaviour belongs on the
/// wire rather than in a reach through somebody else's storage. The bytes it
/// writes are the bytes `relay/server.zig` and `relay/client.zig` produce,
/// encoded through `relay/frame.zig` and length-prefixed the way
/// `node_framing.writeRelay` length-prefixes them.
///
/// The generator is a plain `Prng` and the Retry keys are constants, so a
/// failure reproduces run for run. The identity is `SecretKey.fromSeed`,
/// which is the half a relay actually authenticates on.
const Raw = struct {
    /// The node id this end presents.
    id: ozai.NodeId,
    secret: SecretKey,
    /// Where this end listens, and where it sends from.
    socket: Socket,
    bridge: *Bridge,
    dialer: *Dialer,
    map: MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,

    /// The connection this end dialled, by core id. An id rather than the
    /// handle because a handle dies at `Bridge.sweep` and this outlives a pass.
    dialled: ?u64 = null,
    /// The stream the relay protocol runs on, opened by this end.
    ///
    /// A borrowed handle over core-owned storage, exactly as
    /// `relay_state.Spoke.stream` is: good until the sweep, and read only
    /// between passes.
    spoke: ?quic_stream.Stream = null,
    /// What the peer's stream has said and has not yet been asked about.
    inbox: std.ArrayList(u8) = .empty,
    /// The tag of the first whole frame the peer sent on its own stream.
    heard: ?FrameType = null,

    fn init(tag: u8) !Raw {
        const secret = try identityOf(tag);
        var self: Raw = .{
            .id = secret.nodeId(),
            .secret = secret,
            .socket = undefined,
            .bridge = undefined,
            .dialer = undefined,
            .map = MappedAddrs.init(),
            .engine = Prng.init(tag),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.secret.deinit();
        errdefer self.map.deinit(t.allocator);
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // No peer pin: this end is a fixture, and a pin would only refuse the
        // node it is here to be hostile towards.
        // And **one ALPN, the relay's, on both ends.** `serveAdmit` skips any
        // connection whose negotiated ALPN is not this one, so a fixture that
        // offered anything else would be refused at admission — no slot, no
        // challenge, no stream — and `rawChallenged` would never flip. That is
        // the behaviour the third test asserts, seen from this side, so the
        // offer list here is what keeps this fixture on the other side of it.
        self.bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = secret,
            .expect_peer = null,
            .alpns = &.{node_protocol.relay_alpn},
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.dialer = try Dialer.create(t.allocator, self.bridge, .{
            .secret = secret,
            .alpns = &.{node_protocol.relay_alpn},
        });
        errdefer self.dialer.destroy() catch @panic("a new dialer holds no connection");
        self.egress = try t.allocator.alloc(Egress, node_config.max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, node_config.send_room);
        errdefer t.allocator.free(self.out);
        self.scratch = try t.allocator.alloc(u8, node_config.scratch_room);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, node_config.receive_room);
        return self;
    }

    fn deinit(self: *Raw) void {
        self.inbox.deinit(t.allocator);
        // Backwards, because `removeConnection` swap-removes and a forward walk
        // would skip an entry and leave a freed one behind.
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        self.dialer.destroy() catch @panic("the dialer kept a connection after removal");
        self.bridge.destroy();
        t.allocator.free(self.egress);
        t.allocator.free(self.out);
        t.allocator.free(self.scratch);
        t.allocator.free(self.buf);
        self.map.deinit(t.allocator);
        self.socket.close();
        self.secret.deinit();
        self.* = undefined;
    }

    fn random(self: *Raw) std.Random {
        return self.engine.random();
    }

    /// Where this end listens, which is where a peer reaches it.
    fn address(self: *const Raw) SocketAddr {
        return self.socket.address;
    }

    /// One pass of this end: everything the kernel has, then everything the
    /// core built from it, then the timers, then whatever the peer said.
    /// `node_runtime.step`'s own order, for the same reason.
    fn exchange(self: *Raw, at: Instant) !bool {
        const taken = try self.take(at);
        const sent = try self.flush(at);
        self.listen();
        return sent or taken;
    }

    /// Take everything queued on this socket and hand it to the core.
    fn take(self: *Raw, at: Instant) !bool {
        var moved = false;
        while (true) {
            const got = self.socket.tryReceive(t.io, self.buf, &self.control) catch |err| switch (err) {
                // Non-blocking from the moment it existed, so an empty queue is
                // a fact the pass acts on rather than a stall.
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            // A read is not one datagram: `UDP_GRO` may have coalesced a burst.
            var position: usize = 0;
            while (recv.datagram(position)) |datagram| : (position += 1) {
                const ingress = try self.bridge.recv(&self.map, .{
                    .bytes = datagram,
                    .from = got.from,
                    .local = self.socket.address,
                    .ecn = recv.ecn,
                }, self.scratch, at, self.random());
                moved = true;
                switch (ingress.outcome) {
                    .processed => {},
                    .reply => |reply| _ = try self.socket.send(t.io, ingress.source.socket, reply),
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// Drain every connection and write each datagram out, then run the timers.
    fn flush(self: *Raw, at: Instant) !bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                _ = try self.socket.send(t.io, egress.to, egress.send);
                moved = true;
            }
        }
        var scan: usize = 0;
        while (self.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) moved = true;
        }
        return moved;
    }

    /// Dial `target`, pinning `expect` the way `converseOpen` pins a relay.
    fn dialTo(self: *Raw, target: SocketAddr, expect: ozai.NodeId, at: Instant) !void {
        if (self.dialled != null) return;
        const reached = try self.dialer.dial(
            .{ .ip = target },
            expect,
            self.socket.address,
            &self.map,
            at,
            self.random(),
        );
        self.dialled = reached.conn.id();
    }

    fn connById(self: *const Raw, id: u64) ?Conn {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.id() == id) return conn;
        }
        return null;
    }

    /// The connection this end dialled, while the core still holds it.
    fn dialledConn(self: *const Raw) ?Conn {
        return self.connById(self.dialled orelse return null);
    }

    /// The first established connection a peer opened to this end.
    fn accepted(self: *const Raw) ?Conn {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (!conn.entry.conn.is_server) continue;
            if (!conn.established()) continue;
            return conn;
        }
        return null;
    }

    /// The connection the relay protocol runs on: the one this end dialled, or
    /// the one a peer opened to it.
    fn speech(self: *const Raw) ?Conn {
        return self.dialledConn() orelse self.accepted();
    }

    /// Open the stream this end speaks on.
    ///
    /// The relay opens its own for a reason (`relay_state.ClientSlot.out`'s
    /// own note): a stream is read by whichever end opened it, so the two
    /// halves of this protocol each need the one their end opened.
    fn open(self: *Raw) !void {
        if (self.spoke != null) return;
        const conn = self.speech() orelse return error.NoConnection;
        self.spoke = try quic_stream.openBidi(conn.entry.conn);
    }

    /// Write one relay frame, length-prefixed exactly as `node_framing.writeRelay`
    /// prefixes it: the widest varint reserved first, the body moved down over
    /// the prefix it did not use.
    fn write(self: *Raw, message: relay_frame.Message) !void {
        const stream = if (self.spoke) |*held| held else return error.NoStream;
        var room: [node_config.relay_frame_room + node_framing.varint_max]u8 = undefined;
        const body = try relay_writer.encode(message, .v2, room[node_framing.varint_max..]);
        const prefix = try node_framing.writeVarint(room[0..node_framing.varint_max], body.len);
        @memmove(room[prefix..][0..body.len], body);
        const framed = room[0 .. prefix + body.len];
        if (try stream.write(framed) != framed.len) return error.CoreRefused;
    }

    /// Write a length prefix and **nothing else**: `declared` bytes of frame
    /// announced, and none of them sent.
    fn declare(self: *Raw, declared: u64) !void {
        const stream = if (self.spoke) |*held| held else return error.NoStream;
        var prefix: [node_framing.varint_max]u8 = undefined;
        const len = try node_framing.writeVarint(&prefix, declared);
        if (try stream.write(prefix[0..len]) != len) return error.CoreRefused;
    }

    /// Say nothing more on this end's stream. A peer reads the end as a FIN.
    fn fin(self: *Raw) void {
        if (self.spoke) |*stream| stream.close();
    }

    /// Take whatever the peer has said and note the tag of the first whole
    /// frame among it.
    ///
    /// Only the tag is kept: a test waits for a peer to have spoken a
    /// particular frame, not for the bytes of it, and a frame this fixture
    /// cannot parse is not one a test is waiting for. The prefix is read with
    /// `node_framing.readVarint` and not `peekFrame`, because the bound
    /// `peekFrame` decides is one of the things under test.
    fn listen(self: *Raw) void {
        if (self.heard != null) return;
        const conn = self.speech() orelse return;
        // **No cursor on any pass, not this end's own stream id**, and for
        // `node_relay_serve.serveRead`'s reason: this end re-derives the
        // handle each tick and never retains one, so a cursor advanced past the
        // stream would answer null and stop the drain. The relay protocol has
        // one peer-opened stream per connection, so the lowest one is the
        // stream there is — and it is not always above zero, which is what a
        // cursor of `0` silently assumed when this fixture's own server-side
        // read of a client stream found nothing.
        var incoming = conn.peerStream(null) orelse return;
        _ = incoming.drain(t.allocator, &self.inbox) catch return;
        const head = node_framing.readVarint(self.inbox.items) orelse return;
        const whole = std.math.cast(usize, head.value) orelse return;
        if (self.inbox.items.len < head.len + whole) return;
        const frame = self.inbox.items[head.len..][0..whole];
        self.heard = std.meta.activeTag(relay_codec.decode(frame, .v2) catch return);
    }
};

/// Open the fixture's stream, waiting the passes the peer needs to grant bidi
/// credit.
///
/// The same wait `node_relay_client.converse` makes and refused with the same
/// error, because it is the core's stream limit and not a fault; this end drives
/// nothing itself, so the passes have to come from the cast.
fn openSpoke(peer: *Raw, cast: *Cast) !void {
    var waited: usize = 0;
    while (waited < max_passes) : (waited += 1) {
        peer.open() catch |err| switch (err) {
            error.NoStreamRoom => try cast.pass(),
            else => return err,
        };
        if (peer.spoke != null) return;
        try cast.pass();
    }
    cast.report("a stream to speak the relay protocol on", waited);
    return error.Stalled;
}

/// A serving relay and nothing else.
///
/// A test whose peer is a fixture has no client to place yet, and the tests
/// that care what a slot does configure **one** of them: a second slot would
/// hide a slot that never came back behind plain capacity.
fn relayAlone(scratch: []u8, serve: node_config.Serve) !Cast {
    const relay = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = serve } },
    });
    errdefer node_lifecycle.deinit(relay);
    const route = try (try relayUrl(scratch, node_mod.address(relay))).socketAddr();
    return .{ .relay = relay, .route = route };
}

/// A client node given this relay by URL and node id, and nothing else.
///
/// The general name for what `duplicateOf` does for the duplicate, and the same
/// construction for the same reason: a peer is told a relay's address and node
/// id and nothing at all about the node behind them.
fn clientOf(cast: *const Cast, seed_tag: u8) !*Node {
    return node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(seed_tag),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = cast.peer() } },
    });
}

/// A client node whose relay is a fixture rather than a relay.
///
/// The node under test is the **client** half in the last two tests, so it takes
/// the cast's `relay` slot: that is the position the walk steps last, and the
/// position `Cast.peer()` reads a relay's identity out of. Neither is read
/// there — what is asserted is what this client does after its relay answers.
fn clientFor(peer: *const Raw) !*Node {
    return node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = .{
            .id = peer.id,
            .addr = .{ .ip = peer.address() },
        } } },
    });
}

/// The fixture's dialled connection has finished its handshake.
fn rawUp(cast: *const Cast) bool {
    const peer = cast.raw orelse return false;
    const conn = peer.dialledConn() orelse return false;
    return conn.established();
}

/// The fixture has an established connection a peer opened to it.
fn rawAccepted(cast: *const Cast) bool {
    const peer = cast.raw orelse return false;
    return peer.accepted() != null;
}

/// The fixture that named no protocol has finished its handshake and has been
/// refused by the accept walk.
///
/// The second half is the load-bearing one: `node_runtime.step` admits and
/// drives before it serves, so a pass that has refused this connection has
/// already offered it for a client slot on that same pass. Waiting only for
/// the dial would leave the relay a pass in which `serveAdmit` had not been
/// run over an established connection carrying no protocol at all.
fn quietRefused(cast: *const Cast) bool {
    const peer = cast.raw orelse return false;
    const conn = peer.dialledConn() orelse return false;
    return conn.established() and cast.relay.stats.protocols_refused == 1;
}

/// The relay has answered the fixture with a challenge.
///
/// That is the proof, from out here, that `serveAdmit` gave this peer a client
/// slot and a stream to speak on — the two things every test below spends.
fn rawChallenged(cast: *const Cast) bool {
    const peer = cast.raw orelse return false;
    return peer.heard == .server_challenge;
}

/// The cast's own client is established, so the relay admitted somebody.
fn oneAdmitted(cast: *const Cast) bool {
    const client = cast.first orelse return false;
    return cast.relay.stats.relay_admitted >= 1 and client.stats.relay_established == 1;
}

/// The gossip-only peer reached the relay, **and the accept walk has run a
/// pass over the connection**.
///
/// The second half is the load-bearing one: `node_runtime.step` admits and
/// drives before it serves, so a pass that has routed this connection has
/// already offered it for a client slot. Waiting only for the dial would leave
/// the relay a pass in which it had not yet been offered anything.
fn gossipRouted(cast: *const Cast) bool {
    const gossiper = cast.again orelse return false;
    return gossiper.stats.dials == 1 and cast.relay.stats.tasks_routed >= 1;
}

/// The node under test closed the stream its relay handshake ran on.
fn clientClosed(cast: *const Cast) bool {
    return cast.relay.stats.relay_closed == 1;
}

/// The node under test has signed the challenge and is waiting for a verdict.
fn clientSigned(cast: *const Cast) bool {
    return cast.relay.stats.relay_auth_sent == 1;
}

/// What a client whose relay handshake has ended can still do, which is
/// nothing.
///
/// **A send is a refusal, not a frame the core will take and no relay will
/// read.** The handle is still open on the wire and the core still accepts
/// bytes on it, so a `sendThrough` that returned would be reporting a frame
/// written to a stream whose peer is gone and that the handshake has already
/// closed; and `relay_sent` would then be counting it. `NoRelay` is what makes
/// the second half impossible rather than merely unlikely.
///
/// **`relay` is the far end rather than the client, and which end it is
/// decides what a wire read of this stream can say.** In both tests that reach
/// here this fixture is the **relay** and the node under test is the client, so
/// what `Raw.listen` accumulated is what the *client* wrote — its signed
/// answer, not the ServerChallenge this end sent. An empty inbox would
/// therefore be a statement about the client's silence rather than about the
/// slot, and this helper does not claim it.
fn refusesThrough(client: *Node, relay: *const Raw) !void {
    // **The far end's own read of the wire, which is the half of the claim no
    // counter below can reach.** `relay.heard` is set from bytes `Raw.listen`
    // drained off this end's connection, so `.client_auth` says the client's
    // signed answer was on the wire and arrived before the handshake ended —
    // a fact `clientSigned` above cannot distinguish from a write the node
    // counted and the core never sent. It is read first so it is read on every
    // build rather than behind an earlier failure.
    //
    // **It is not what carries the claim and is not dressed up as carrying it.**
    // The assertion that does is the `NoRelay` below, and this one's own limit
    // is worth naming rather than leaving implied: `Raw.listen` stops draining
    // once it has heard a whole frame, so a fixture on this side of the stream
    // cannot see anything the client writes afterwards. What it can say is
    // that the handshake was mid — a refusal claim about what came *before*
    // the end, which is the half the client-side assertions below cannot make.
    try t.expect(relay.heard == .client_auth);

    // **A send is a refusal**, and this is the assertion a build that kept a
    // usable relay slot past the end of the handshake cannot pass: there
    // `Spoke.ended` is never consulted, the frame is written whole, and the
    // call returns where this one is promised `NoRelay`.
    try t.expectError(
        error.NoRelay,
        node_relay_client.sendThrough(client, relay.id, "after-the-close"),
    );
    // What a refused send leaves behind. **Neither of these two discriminates on
    // its own** — a client that never had a spoke to write on holds both at
    // zero, and `relay_sent` is only reachable once the `NoRelay` above has
    // already passed. They are kept because they are what the refused call did
    // not do, and a build that refused the send and still wrote the frame would
    // have to fail one of them.
    try t.expectEqual(@as(u64, 0), client.stats.relay_sent);
    try t.expectEqual(@as(usize, 0), node_relay_client.delivered(client).len);
}

/// Drive a settled window and hand back the refusals it did not add to.
///
/// A slot is handed back when the core finishes draining the connection the
/// relay closed, and until it does, `serveAdmit` runs first and finds no room
/// for anybody — so the refusal count is **transiently above zero** and is not
/// claimed to be anything else here. What it must be is settled: a close whose
/// drain never finishes refuses on every pass for the life of the node, and
/// that is the difference these tests are about.
fn settledRefusals(cast: *Cast) !u64 {
    const before = cast.relay.stats.relay_refused;
    var quiet: usize = 0;
    while (quiet < 64) : (quiet += 1) try cast.pass();
    try t.expectEqual(before, cast.relay.stats.relay_refused);
    return before;
}

test "a peer that answers a challenge with the wrong frame is closed and its slot returns" {
    var scratch: [80]u8 = undefined;
    // **One client slot, because that is the whole claim.** A relay that keeps
    // the slot it spent on a peer it has already refused admits nobody, and a
    // second slot would hide exactly that behind capacity.
    var cast = try relayAlone(&scratch, .{ .clients = 1, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    var peer = try Raw.init(0x31);
    defer peer.deinit();
    cast.raw = &peer;

    // The fixture reaches the relay by the same URL a client is handed, and
    // pins the relay's node id the way `converseOpen` does.
    try peer.dialTo(cast.route, node_mod.nodeId(cast.relay), cast.at);
    try cast.drive("the peer to finish its handshake with the relay", rawUp);
    try openSpoke(&peer, &cast);
    try cast.drive("the relay to challenge the peer", rawChallenged);

    // A ping is a frame the challenge did not ask for. `relay_server`'s own
    // `.challenged` arm names it — `Failure{ .unexpected_frame = .ping }` —
    // and it is a **well-formed** frame rather than bytes the codec refuses, so
    // the relay has to answer it rather than trip over decoding it.
    try peer.write(.{ .ping = @splat(0x11) });

    // A real client, arriving after the relay has closed the fixture's
    // connection. Nothing else about it differs from the first test's.
    const client = try clientOf(&cast, 0xa1);
    cast.first = client;
    try cast.driveWithin(
        "the relay's one client slot to come back",
        oneAdmitted,
        max_recovery_passes,
    );

    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 1), client.stats.relay_established);
    // The wrong frame was answered, not cut short: the stream did not end.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_truncated);
    _ = try settledRefusals(&cast);

    try cast.close();
}

test "a relay stream that ends mid-handshake is closed and its slot returns" {
    var scratch: [80]u8 = undefined;
    var cast = try relayAlone(&scratch, .{ .clients = 1, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    var peer = try Raw.init(0x32);
    defer peer.deinit();
    cast.raw = &peer;

    try peer.dialTo(cast.route, node_mod.nodeId(cast.relay), cast.at);
    try cast.drive("the peer to finish its handshake with the relay", rawUp);
    try openSpoke(&peer, &cast);
    // The challenge first, so this is provably a stream that ended **mid**
    // handshake: the relay has spent a slot and written to it, and this end has
    // said nothing at all in answer.
    try cast.drive("the relay to challenge the peer", rawChallenged);

    // Nothing more on this stream, ever. A peer reads the end as a FIN, and the
    // connection stays up — which is what makes this a slot that is held
    // rather than one the kernel gave back.
    peer.fin();

    const client = try clientOf(&cast, 0xa1);
    cast.first = client;
    try cast.driveWithin(
        "the relay's one client slot to come back",
        oneAdmitted,
        max_recovery_passes,
    );

    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 1), client.stats.relay_established);
    // **Nothing was cut short.** The stream ended between frames, so there was
    // no partial frame to drop; a truncated frame is a different fact and this
    // counter is where it is counted.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_truncated);
    _ = try settledRefusals(&cast);

    try cast.close();
}

test "a relay serving two protocols spends no client slot on the other one" {
    var scratch: [80]u8 = undefined;
    // Two registrations is the whole of what "more than one protocol" can be:
    // `node_protocol.max_alpns` is two. And one client slot, so a slot spent
    // on the wrong connection is a slot the relay client does not get.
    // **The cast takes the relay in the same statement that builds it.** The
    // `errdefer` is scoped to the block that can still fail and the `defer`
    // below is the one and only release; without the block the two would both
    // run on an error and free the relay twice.
    var cast: Cast = blk: {
        const relay = try node_lifecycle.create(t.allocator, t.io, .{
            .secret = try identityOf(0x5e),
            .listen = loopback,
            .protocols = &.{
                .{ .alpn = node_protocol.gossip_alpn },
                .{ .alpn = node_protocol.relay_alpn },
            },
            .relay = .{ .role = .{ .serve = .{ .clients = 1, .queue_depth = 8, .drain_room = 4 } } },
        });
        errdefer node_lifecycle.deinit(relay);
        const route = try (try relayUrl(&scratch, node_mod.address(relay))).socketAddr();
        break :blk .{ .relay = relay, .route = route };
    };
    defer cast.deinit();

    // A peer that speaks only gossip, dialling the relay the way any bootstrap
    // peer is dialled. Its own relay role is off, so it never reaches for a
    // client slot itself.
    const bootstrap = [_]Peer{.{
        .id = node_mod.nodeId(cast.relay),
        .addr = .{ .ip = cast.route },
    }};
    const gossiper = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x9c),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.gossip_alpn }},
        .peers = &bootstrap,
        .relay = .{ .role = .off },
    });
    cast.again = gossiper;
    try node_runtime.start(gossiper, cast.at, node_mod.generator(gossiper));

    try cast.drive("the gossip peer to reach the relay", gossipRouted);
    // The gossip connection selected an ALPN a configured protocol claims, so
    // no refusal is due here under any source.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.protocols_refused);

    // Only now does the relay's own client arrive, on the one slot.
    const client = try clientOf(&cast, 0xa1);
    cast.first = client;
    try cast.driveWithin(
        "the relay to admit a relay client",
        oneAdmitted,
        max_recovery_passes,
    );

    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 1), client.stats.relay_established);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_deferred);
    _ = try settledRefusals(&cast);

    // **And the other protocol went on being served.** The gossip lane is the
    // one at index zero, it is still serving, and both connections are still
    // up: admitting a relay client cost the gossip connection nothing, and no
    // connection was dropped to make room.
    const lane = node_close.laneStats(cast.relay, 0) orelse return error.NoGossipLane;
    try t.expectEqualStrings(node_protocol.gossip_alpn, lane.alpn);
    try t.expect(lane.serving);
    try t.expectEqual(@as(usize, 2), node_mod.establishedCount(cast.relay));
    try t.expectEqual(@as(u64, 0), cast.relay.stats.protocols_refused);

    try cast.close();
}

test "a peer that negotiates no protocol spends no client slot" {
    var scratch: [80]u8 = undefined;
    // One client slot, because that is the whole claim: a slot spent on a peer
    // that named no protocol is a slot no client of this relay can ever get,
    // and a second slot would hide exactly that behind plain capacity.
    //
    // **And the relay ALPN first and alone in this node's protocol list**,
    // which is what makes the claim bite at all.
    // `relayAlone` configures `protocols = &.{.{ .alpn = relay_alpn }}`, and
    // `Connection.negotiatedAlpn` answers a handshake that selected nothing
    // with `Config.protocols[0]`
    // (`vendor/quic/src/quic/tls13.zig:2060-2063`) — so this is a relay whose
    // own first configured protocol would match a peer that offered none.
    var cast = try relayAlone(&scratch, .{ .clients = 1, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    var peer = try Raw.init(0x6d);
    defer peer.deinit();
    cast.raw = &peer;

    // **Only the offer list is emptied, and what it buys is the wire shape and
    // nothing else.** A first-party `Dialer.create` refuses an empty offer list
    // by name (`src/transport/quic_config.zig:84-91`), so the count is
    // emptied here — after that check has run, and past the field's own note
    // that a zero count belongs to a `create` that was refused
    // (`src/transport/dial.zig:383-384`). What a dialer writes into a
    // ClientHello is `tlsConfigFor`'s `alpn`, which is
    // `alpn_list[0..alpn_count]` (`src/transport/dial.zig:462-493`), and the
    // vendored core's own `buildClientHello` omits the extension for an empty
    // offer list (`vendor/quic/src/quic/tls13.zig:4338-4339`). Every other byte
    // of this peer is this file's ordinary `Socket` + `Bridge` + `Dialer`, and
    // no private dialer state is reached into to get here.
    //
    // **The bridge keeps its own real list**: that is this peer's listener
    // half, and no connection on it is accepted in this test.
    peer.dialer.alpn_count = 0;
    try peer.dialTo(cast.route, node_mod.nodeId(cast.relay), cast.at);

    // **The handshake completes, and that is why the relay has to refuse this
    // connection itself.** RFC 7301 §3.2's `no_application_protocol` is a
    // refusal of an empty intersection of an offer that *was* made
    // (`vendor/quic/src/quic/tls13.zig:3169-3178`), and it lives inside the
    // ALPN extension's parse, which a ClientHello carrying no extension never
    // reaches (`tls13.zig:3100-3114`) — the core says so in its own terms at
    // `tls13.zig:1432-1435`, "neither end fails". What arrives below is an
    // established connection with no protocol on it.
    try cast.drive(
        "the quiet peer to finish its handshake and be refused at the accept walk",
        quietRefused,
    );

    // **And it cost the relay nothing**, over a settled window rather than on
    // the one pass that refused it: `serveAdmit` runs after the accept walk on
    // every pass, and a window is what says it ran again and again over an
    // established connection carrying no protocol.
    _ = try settledRefusals(&cast);

    // **No slot was spent and no challenge was written.** `relay_admitted` is
    // where it was before this peer arrived, the registry holds no node id,
    // and `relay_stream_deferred` never moved — so nothing was asked of the
    // core's stream credit either. And this end has heard **nothing at all**:
    // `Raw.heard` is read off this end's own stream off the wire, so an empty
    // inbox is the absence of a ServerChallenge rather than a counter that
    // failed to move.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 0), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_deferred);
    try t.expect(peer.heard == null);

    // **And the one slot is still there for a peer that did name the relay
    // ALPN.** This is the half with teeth. A `serveAdmit` reading the config
    // fallback would have taken that slot for the quiet peer above, written it
    // a ServerChallenge, and left a handshake that can never authenticate
    // holding the slot for as long as the connection lives — so this client
    // would be refused on every pass and the drive below would stall rather
    // than fail quietly.
    const client = try clientOf(&cast, 0xa1);
    cast.first = client;
    try cast.driveWithin(
        "the relay to admit a client that named the relay ALPN",
        oneAdmitted,
        max_recovery_passes,
    );

    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 1), client.stats.relay_established);
    try t.expectEqual(@as(usize, 1), node_relay_client.clientCount(cast.relay));
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_deferred);
    // The quiet peer is still up, still has said nothing, and was still never
    // admitted: what it did not take is what the client above got.
    try t.expect(peer.heard == null);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.protocols_refused);

    try cast.close();
}

test "a declared frame length past the frame room is refused at its prefix" {
    var scratch: [80]u8 = undefined;
    var cast = try relayAlone(&scratch, .{ .clients = 1, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    var peer = try Raw.init(0x4d);
    defer peer.deinit();
    cast.raw = &peer;

    try peer.dialTo(cast.route, node_mod.nodeId(cast.relay), cast.at);
    try cast.drive("the peer to finish its handshake with the relay", rawUp);
    try openSpoke(&peer, &cast);
    try cast.drive("the relay to challenge the peer", rawChallenged);

    // **A prefix and nothing else.** A gibibyte of frame announced by eight
    // bytes, and not one byte of it sent: the stream's receive window is six
    // megabytes, so this peer could not have delivered that body even if it
    // wanted to, and the relay's inbox is an unbounded list it grows. **There
    // is no body anywhere in this test**, which is what makes "without
    // buffering the body" a fact about the wire rather than about a buffer.
    try peer.declare(1 << 30);

    // The relay answers the prefix itself rather than waiting for the frame it
    // was told to expect, and the answer is a refusal at the bound.
    var refused_at_prefix = false;
    var index: usize = 0;
    while (index < max_recovery_passes) : (index += 1) {
        var failure: ?anyerror = null;
        cast.pass() catch |err| {
            failure = err;
        };
        if (failure) |err| {
            if (err != error.FrameTooLarge) {
                std.debug.print(
                    "\nafter {d} passes the relay answered {t} for a declared length past the frame room\n",
                    .{ index, err },
                );
                return err;
            }
            refused_at_prefix = true;
            break;
        }
    }
    try t.expect(refused_at_prefix);
    // A refusal at the prefix is not a truncated frame: nothing was cut short,
    // the stream has not ended, and no client was authenticated.
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_stream_truncated);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_admitted);

    // `node_runtime.step`'s own note covers this: a pass that failed may have
    // consumed input, so the node is closed rather than driven again.
    try cast.close();
}

test "a client the relay denied cannot send through it" {
    var peer = try Raw.init(0x61);
    defer peer.deinit();

    var cast: Cast = .{ .relay = try clientFor(&peer), .route = peer.address() };
    defer cast.deinit();
    cast.raw = &peer;

    try cast.drive("the client to reach the fixture's relay", rawAccepted);
    try openSpoke(&peer, &cast);
    // A challenge and then a denial, in that order, which is what
    // `relay_server`'s own `.access = .{ .deny = .. }` arm writes: the client
    // is given a challenge, answers it, and is then told it was never welcome.
    try peer.write(.{ .server_challenge = .{ .challenge = @splat(0x5c) } });
    try cast.drive("the client to sign the challenge", clientSigned);
    try peer.write(.{ .server_denies_auth = .{ .reason = "denied by this test" } });

    try cast.driveWithin(
        "the client to close on the denial",
        clientClosed,
        max_recovery_passes,
    );
    try refusesThrough(cast.relay, &peer);

    try cast.close();
}

test "a client whose relay stream ends mid-handshake cannot send through it" {
    var peer = try Raw.init(0x62);
    defer peer.deinit();

    var cast: Cast = .{ .relay = try clientFor(&peer), .route = peer.address() };
    defer cast.deinit();
    cast.raw = &peer;

    try cast.drive("the client to reach the fixture's relay", rawAccepted);
    try openSpoke(&peer, &cast);
    try peer.write(.{ .server_challenge = .{ .challenge = @splat(0x5c) } });
    // The client's answer is on the wire before the end: it has signed the
    // challenge and is waiting for a verdict, so the stream that ends here
    // ended **mid** handshake rather than after one.
    try cast.drive("the client to sign the challenge", clientSigned);
    peer.fin();

    try cast.driveWithin(
        "the client to close on the ended stream",
        clientClosed,
        max_recovery_passes,
    );
    try refusesThrough(cast.relay, &peer);

    try cast.close();
}
