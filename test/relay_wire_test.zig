//! The relay on the wire: a client that finds a relay the way a peer finds one.
//!
//! `src/node/node.zig`'s own relay test is a real test. Three nodes, three
//! sockets, a kernel, the whole QUIC stack, and every counter read off the
//! machinery rather than off a stand-in. What it cannot show is the one step a
//! relay exists to make possible: that a peer holding **nothing but a relay
//! URL** can reach the relay at all. Its two clients are handed
//! `relay.address()` — a `SocketAddr` the test built out of the value it was
//! trying to prove a peer could find on its own.
//!
//! # What this file found, and what it added
//!
//! Nothing in the tree turned a `RelayUrl` into anything a dial could use.
//! `base/addr.zig`'s `RelayUrl` parsed, formatted and ordered;
//! `transport/dial.zig` took a `TransportAddr.relay` and resolved it through
//! `base/ula.zig` into a synthetic RFC 4193 address, which is not routable on
//! a socket — the gap `src/node/node.zig` names in its own module doc rather
//! than patching around. `net/probe.zig` decides which relays to ask and
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
//! `Node.serveRead` used to read a client's relay stream into `relay_in`, which
//! `relay_frame_room` sizes for the largest *frame*, while
//! `quic_bridge.Stream.take` hands back the largest *read* — the whole
//! contiguous run out of the core's frame sorter, coalesced up to 64 KiB
//! (`vendor/quic/src/quic/stream.zig:72`) — and refused it with `error.NoRoom`
//! after having already popped the bytes. A burst of relay frames wider than
//! one frame therefore killed a serving relay's pass. Confirmed by a second
//! pair of eyes.
//!
//! **It is fixed, and the pacing in the third test is what it cost while it was
//! not.** The read is now `Stream.drain`, which appends whatever the core hands
//! over onto the caller's inbox and so has no fixed size to be too small for —
//! see `src/transport/quic_bridge.zig`. There is no `relay_in` left, so
//! `relay_frame_room` is once again the only buffer bound in `node.zig` and
//! means only the one thing it says. **What replaced the pacing is a test
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
//! `delivered()` count, and that count grows with every frame the relay drains
//! — which, while a flood is in, is exactly what is filling the queue. So the
//! two ends of the claim are not independently measurable and the ordering
//! half is named rather than asserted at a bound that would only hold because
//! of how this file schedules its passes.
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

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const node_mod = ozai.node;
const Node = node_mod.Node;
const Peer = node_mod.Peer;
const RelayUrl = ozai.RelayUrl;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;
const Instant = ozai.transport_quic_bridge.Instant;
const router = ozai.router;
const relay_server = ozai.relay_server;

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

fn payload(index: usize) [payload_length]u8 {
    var out: [payload_length]u8 = @splat(0xa5);
    var at: usize = 0;
    while (at < payload_length) : (at += 8) {
        std.mem.writeInt(u64, out[at..][0..8], @intCast(index), .big);
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
    first: *Node,
    second: *Node,
    /// A fourth node, when one test needs one: the second test dials the same
    /// node id over a second connection, and a node the cast cannot step is a
    /// node that never dials at all.
    again: ?*Node = null,
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
    /// `src/node/node.zig`'s own `step` is internally ordered for, and the
    /// reason a test driving several nodes should walk them so.
    fn nodes(self: *Cast) []const *Node {
        var len: usize = 0;
        for ([_]*Node{ self.first, self.second }) |sender| {
            self.order[len] = sender;
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
        return .{ .id = self.relay.nodeId(), .addr = .{ .ip = self.route } };
    }

    fn deinit(self: *Cast) void {
        for (self.nodes()) |node| node.deinit();
        self.* = undefined;
    }

    /// One pass over every node.
    fn pass(self: *Cast) !void {
        self.at += time_quantum;
        for (self.nodes()) |node| _ = try node.step(t.io, self.at, node.generator());
    }

    /// Drive until `want` holds, or say what was being waited for.
    fn drive(
        self: *Cast,
        what: []const u8,
        want: *const fn (*const Cast) bool,
    ) !void {
        var pass_index: usize = 0;
        while (pass_index < max_passes) : (pass_index += 1) {
            try self.pass();
            if (want(self)) return;
        }
        self.report(what, pass_index);
        return error.Stalled;
    }

    /// Wind every node down through the router's shutdown, and check the order
    /// `router.Shutdown` enforces.
    ///
    /// The relay's clients are given up in `shutdown_handlers`, the first of
    /// the three phases, so every report is made before the endpoint close
    /// writes anything at all. A second call is the no-op it looks like: the
    /// close runs only out of `serving`, so nothing is given up twice.
    fn close(self: *Cast) !void {
        for (self.nodes()) |node| try node.close(t.io, self.at, node.generator());
        for (self.nodes()) |node| {
            try t.expectEqual(router.Shutdown.Phase.closed, node.accept.shutdown.phase);
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
                self.relay.clientCount(),
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
        sayClient("first", self.first);
        sayClient("second", self.second);
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
            client.delivered().len,
        },
    );
}

/// A serving relay and two clients that reached it by relay URL.
///
/// The URL is built from the address the relay's own socket reports and is
/// then the only thing the clients are given: `Config` and `Peer` never see a
/// `SocketAddr` here, and `relay.address()` is not read again after this.
/// Three identities, so no end of this can be the other — the relay proves a
/// client owns the node id it claims, and a client that presented the relay's
/// own certificate would prove nothing.
fn stand(scratch: []u8, serve: node_mod.Serve) !Cast {
    const relay = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .alpn = node_mod.relay_alpn,
        .relay = .{ .role = .{ .serve = serve } },
    }, 0x5150);
    errdefer relay.deinit();

    // The step this whole file is about, done once and in one place: a relay
    // URL becomes the socket a dial is told. `derp` does the same thing with
    // `url.host` and refuses a name outright; see `RelayUrl.socketAddr`.
    const url = try relayUrl(scratch, relay.address());
    const route = try url.socketAddr();
    if (route.order(relay.address()) != .eq) return error.UrlNamedAnotherRelay;

    const route_peer = [_]Peer{.{
        .id = relay.nodeId(),
        .addr = .{ .ip = route },
    }};
    const first = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .alpn = node_mod.relay_alpn,
        .relay = .{ .role = .{ .client = route_peer[0] } },
    }, 0xa1a1);
    errdefer first.deinit();
    const second = try Node.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .alpn = node_mod.relay_alpn,
        .relay = .{ .role = .{ .client = route_peer[0] } },
    }, 0xb2b2);
    errdefer second.deinit();
    return .{ .relay = relay, .first = first, .second = second, .route = route };
}

/// A node holding an existing node's identity, reached by the same URL.
///
/// `seed_tag` is the identity to re-present and `generator` seeds this node's
/// own generator, so a duplicate is not a copy of anything but its key.
fn duplicateOf(cast: *const Cast, seed_tag: u8, generator: u64) !*Node {
    return Node.create(t.allocator, t.io, .{
        .secret = try identityOf(seed_tag),
        .listen = loopback,
        .alpn = node_mod.relay_alpn,
        .relay = .{ .role = .{ .client = cast.peer() } },
    }, generator);
}

/// The relay URL that names `socket`, spelled the way a peer is handed one.
fn relayUrl(scratch: []u8, socket: SocketAddr) !RelayUrl {
    var host = std.Io.Writer.fixed(scratch);
    try socket.format(&host);
    var text: [80]u8 = undefined;
    return RelayUrl.parse(try std.fmt.bufPrint(&text, "http://{s}/", .{host.buffered()}));
}

/// Both clients are established and the relay holds two node ids.
fn bothAdmitted(cast: *const Cast) bool {
    return cast.relay.clientCount() == 2 and
        cast.first.stats.relay_established == 1 and
        cast.second.stats.relay_established == 1;
}

/// The first client has been handed a datagram.
fn oneDelivered(cast: *const Cast) bool {
    return cast.first.delivered().len >= 1;
}

/// The second client has been handed a datagram.
fn oneHanded(cast: *const Cast) bool {
    return cast.second.delivered().len >= 1;
}

/// The duplicate has displaced the first connection and the first was told.
fn displaced(cast: *const Cast) bool {
    return cast.relay.stats.relay_told_displaced == 1 and
        cast.first.stats.relay_displaced == 1;
}

/// The second client has been told it was displaced by a later connection.
fn toldDisplaced(cast: *const Cast) bool {
    return cast.second.stats.relay_displaced == 1;
}

test "a peer holding a relay URL reaches a relay, and a datagram crosses both ways" {
    var scratch: [80]u8 = undefined;
    var cast = try stand(&scratch, .{ .clients = 2, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();

    try t.expect(cast.first.nodeId().order(cast.second.nodeId()) != .eq);
    try t.expect(cast.first.nodeId().order(cast.relay.nodeId()) != .eq);

    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // The handshake each client ran, from the relay's side and the client's.
    // The mechanism is `.signed_challenge` on both ends: this transport has no
    // key material to offer, so a challenge is the only way in.
    try t.expectEqual(@as(usize, 2), cast.relay.clientCount());
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(u64, 2), cast.relay.stats.attempts);
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_dials);
    try t.expectEqual(@as(u64, 1), cast.second.stats.relay_dials);
    try t.expectEqual(@as(u64, 0), cast.first.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 0), cast.second.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), cast.second.stats.relay_auth_sent);
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
    try cast.first.sendThrough(cast.second.nodeId(), "first-to-second!!");
    try cast.drive("the second client to be handed the first's datagram", oneHanded);
    try t.expectEqual(@as(usize, 1), cast.second.delivered().len);
    try t.expectEqual(cast.first.nodeId(), cast.second.delivered()[0].src);
    try t.expectEqualStrings("first-to-second!!", cast.second.delivered()[0].data);

    try cast.second.sendThrough(cast.first.nodeId(), "second-to-first!!");
    try cast.drive("the first client to be handed the second's datagram", oneDelivered);
    try t.expectEqual(@as(usize, 1), cast.first.delivered().len);
    try t.expectEqual(cast.second.nodeId(), cast.first.delivered()[0].src);
    try t.expectEqualStrings("second-to-first!!", cast.first.delivered()[0].data);

    // Each client counted the one datagram it was handed, so the counters say
    // the two frames arrived at two different nodes rather than one node
    // seeing its own twice.
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_datagrams_out);
    try t.expectEqual(@as(u64, 1), cast.second.stats.relay_datagrams_out);
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
    try cast.first.sendThrough(stranger, "no such peer");
    try cast.drive("the first client to be told that peer is not at the relay", toldPeerGone);
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_peer_gone);
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_unknown_target);
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_queue_full);

    // ── admission is once, however many passes follow ──
    var quiet: usize = 0;
    while (quiet < 32) : (quiet += 1) {
        try cast.pass();
    }
    try t.expectEqual(@as(u64, 2), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), cast.relay.clientCount());
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);

    // ── and every departure is reported exactly once ──
    try cast.close();
    try t.expectEqual(@as(usize, 0), cast.relay.clientCount());
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
    // (`Node.serveAdmit`'s own reason) — which would be a test measuring the
    // wrong refusal.
    var cast = try stand(&scratch, .{ .clients = 3, .queue_depth = 8, .drain_room = 4 });
    defer cast.deinit();
    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // A fourth node holding the *first* node's identity: the same seed, so the
    // same certificate, so the relay sees the same node id over a second
    // connection. It is given the URL's socket and the node id, exactly as the
    // first was, and it binds its own socket and dials the relay itself.
    const again = try duplicateOf(&cast, 0xa1, 0xa1a2);
    cast.again = again;

    // ── admitted again, and no second entry ──
    //
    // Three handshakes have run and two of them proved the same node id, so
    // the registry holds two node ids and not three — a repeated handshake
    // takes the entry rather than making one. `relay_admitted` counts
    // *connections*, which is why it is three and the registry's count is not.
    try cast.drive("the duplicate to be admitted and the first to be told", displaced);
    try t.expectEqual(@as(u64, 3), cast.relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), cast.relay.clientCount());
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_replaced);
    try t.expectEqual(@as(u64, 1), again.stats.relay_established);
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_established);

    // The displaced connection was told over its **control** queue, which is
    // the queue a full data queue would have nothing to do with.
    try t.expectEqual(@as(u64, 1), cast.relay.stats.relay_told_displaced);
    try t.expectEqual(@as(u64, 1), cast.first.stats.relay_displaced);

    // And the relay forwards to whichever connection is now the active one: a
    // datagram the duplicate sends reaches the second client carrying the node
    // id of the identity it re-presented.
    try again.sendThrough(cast.second.nodeId(), "after-the-replacement");
    try cast.drive("the second client to be handed the replacement's datagram", oneHanded);
    try t.expectEqual(@as(usize, 1), cast.second.delivered().len);
    try t.expectEqual(cast.first.nodeId(), cast.second.delivered()[0].src);
    try t.expectEqualStrings("after-the-replacement", cast.second.delivered()[0].data);

    // ── three connections, three reports, none twice ──
    try cast.close();
    try t.expectEqual(@as(usize, 0), cast.relay.clientCount());

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
    // at the start of every `serveRead` and never gets refused itself — which
    // freezes `relay_queue_full` for the rest of the drive. Anything that
    // moves it from here is something that had to share the data queue's
    // room, and the control frame below is the candidate.
    const refused_while_full = cast.relay.stats.relay_queue_full;
    // How many datagrams the relay had accepted when the flood stopped, and so
    // how long the run of payloads the second client is holding is before the
    // top-ups start. The queue refused a few *between* accepted ones rather
    // than only at the end — it fills inside a round, so the last round of a
    // flood takes seven and refuses one — so the split is this count and not
    // the queue's depth.
    const filled_before_top_up = cast.relay.stats.relay_forwarded;
    // A fourth node presenting the *second* node's identity, so the connection
    // it displaces is the one whose data queue is at capacity. Its generator
    // seed is deliberately *not* the second node's: two nodes drawing from one
    // generator pick the same connection ids, collide in the relay's CID map,
    // and neither handshake finishes. That is a collision in the fixture, not
    // a finding about the relay.
    const again = try duplicateOf(&cast, 0xb2, 0xb3b3);
    cast.again = again;
    // The loop's condition is the **relay's** counter, not the client's, and
    // that is load-bearing twice over. `relay_told_displaced` moves in the same
    // pass the duplicate is registered, and the last datagram fed before then
    // is read on that same pass and before it — `serveRead` walks the flood's
    // client first. So the queue is at capacity at the instant the status is
    // queued, and not one datagram is routed to the connection that replaced
    // it, which is what keeps the second client's list a gap-free run.
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
    try t.expectEqual(@as(u64, 1), cast.second.stats.relay_displaced);

    // And it did not wait for the backlog to drain: the relay still owed this
    // client hundreds of queued datagrams when the status reached it. How
    // *far* ahead of them it went is not readable from outside — the relay's
    // queues are its own storage and nothing publishes their order — so the
    // claim is pinned to what is: the frame went out, and it went out without
    // the backlog having to move first. See the module doc's "What cannot be
    // measured here".
    try t.expect(cast.second.delivered().len < depth);

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
        @as(u64, cast.second.delivered().len),
    );
    // What the client is holding is every payload the relay accepted, and the
    // queue accepted some and refused others *interleaved* — it fills inside a
    // round, so the last round of the flood takes seven and refuses one. The
    // assertion walks that sequence rather than pretending nothing was ever
    // refused, and every payload carries its own index twice, so a dropped,
    // duplicated or reordered datagram is a difference in the bytes and not
    // only a count.
    for (cast.second.delivered(), 0..) |item, index| {
        try t.expectEqual(cast.first.nodeId(), item.src);
        const want = if (index < filled_before_top_up) index else index + refused_while_full;
        try t.expectEqualSlices(u8, &payload(want), item.data);
    }
    // At least a whole queue's worth of them, so the depth this test is about
    // was really reached and really drained, and nothing was oversized on the
    // way in or out.
    try t.expect(cast.second.delivered().len >= depth);
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
/// again even once. Every payload here is a whole `max_datagram`, so a frame is
/// 1535 bytes and this is over six and a half megabytes on the wire.
const burst_datagrams = 4_200;

/// A burst payload: its own index at both ends over a pattern between them, so
/// a datagram that arrives twice, out of order or short is a difference in the
/// bytes and not only a count.
fn wide(index: usize) [node_mod.max_datagram]u8 {
    var out: [node_mod.max_datagram]u8 = @splat(0x3c);
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
    try cast.drive("both clients to be admitted by the relay", bothAdmitted);

    // ── the burst, written before a single pass runs ──
    //
    // Nothing here is paced, and that is the whole of what this test is: the
    // third test above writes its flood a round at a time and reads a frame at a
    // time, which is the shape that let the defect this file found through.
    for (0..burst_datagrams) |index| {
        try cast.first.sendThrough(cast.second.nodeId(), &wide(index));
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
        @as(u64, cast.second.delivered().len),
    );
    // A queue takes datagrams in the order they arrive and gives room back from
    // its head, so what it accepted is a gap-free prefix of the burst: the
    // datagram at index `n` is the one written at index `n`, and no offset is
    // needed to say which datagrams the refusals fell on.
    for (cast.second.delivered(), 0..) |item, index| {
        try t.expectEqual(cast.first.nodeId(), item.src);
        try t.expectEqualSlices(u8, &wide(index), item.data);
    }

    // ── and the pass is still serving afterwards ──
    //
    // "Survived the burst" and "stopped serving" are not the same claim, and
    // only a datagram written after the burst tells them apart.
    try cast.first.sendThrough(cast.second.nodeId(), "after-the-burst");
    try cast.drive(
        "the second client to be handed a datagram after the burst",
        afterBurst,
    );
    const held = cast.second.delivered();
    try t.expectEqualStrings("after-the-burst", held[held.len - 1].data);

    try cast.close();
    try t.expectEqual(@as(u64, 0), cast.relay.stats.relay_double_reports);
}

/// Write `count` more datagrams at the second client, numbered from `*sent`.
fn feed(cast: *Cast, sent: *usize, count: usize) !void {
    for (0..count) |offset| {
        try cast.first.sendThrough(cast.second.nodeId(), &payload(sent.* + offset));
    }
    sent.* += count;
}

/// The relay has read every datagram the burst held.
fn burstRead(cast: *const Cast) bool {
    return cast.relay.stats.relay_datagrams_in >= burst_datagrams;
}

/// The second client is holding the datagram written after the burst.
fn afterBurst(cast: *const Cast) bool {
    const held = cast.second.delivered();
    if (held.len == 0) return false;
    return std.mem.eql(u8, held[held.len - 1].data, "after-the-burst");
}

/// The second client has been handed everything the relay ever accepted.
fn allAccepted(cast: *const Cast) bool {
    return cast.second.delivered().len >= cast.relay.stats.relay_forwarded;
}

/// The first client has been told that a peer is not at the relay.
fn toldPeerGone(cast: *const Cast) bool {
    return cast.first.stats.relay_peer_gone == 1;
}
