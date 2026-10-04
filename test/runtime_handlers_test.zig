//! Per-protocol handlers on a real accept path, driven over real sockets.
//!
//! # Why this file exists
//!
//! `src/node/node.zig` registered **one** `ProtocolHandler` for every ALPN in
//! `Config.alpns` and counted the connections it was handed. The negotiated
//! ALPN chose the router *lane* and nothing else: the handler a connection
//! reached was the same value whichever protocol the handshake picked, and the
//! connection it was handed was `*Node` rather than the connection at all. A
//! node configured with two protocols therefore had two lanes and one handler,
//! and "which protocol is this connection?" had an answer that could not be
//! wrong — which is the same shape `docs/PLAN.md` put "ALPN selection and
//! refusal" in wave 1 to remove.
//!
//! Every other seam for this claim was already real and is deliberately *not*
//! used here: `test/loopback_alpn_test.zig` drives the pure `router` machines,
//! which proves the table but never a socket, and a `Socket` + `Bridge` +
//! `Dialer` consumer proves the wire but writes its own `switch` over
//! `negotiatedAlpn`. Neither is the production accept loop. This file is the
//! production accept loop: a `Node` with real sockets, real peers that speak
//! real QUIC over real UDP, and one handler per configured protocol.
//!
//! # The peers
//!
//! Each peer is a `Socket`, a `Bridge` and a `Dialer` — the three seams the node
//! is built from, driven one pass at a time against a clock this file advances.
//! A `Node` peer could not be used for the payload half: `Node`'s only byte
//! surface is `sendThrough`, which a relay client needs and nothing else, so a
//! peer that has to *send* a payload cannot be a `Node`. That is a fact about
//! `Node`, not a reason to fake the peer's bytes: every byte in this file was
//! written by a peer and read by the handler over a socket.
//!
//! # What is asserted
//!
//! 1. **Dispatch is per protocol and the payload is visible.** A peer offering
//!    only the gossip ALPN reaches the gossip lane and nothing else; a peer
//!    offering only a caller's own ALPN reaches that caller's handler, and the
//!    handler reads the bytes that peer wrote. One assertion covers both halves:
//!    if the node dispatched by lane rather than by protocol the payload could
//!    not arrive, and if it dispatched by protocol but handed over `*Node` there
//!    would be nothing to read it from.
//! 2. **Retiring one lane leaves the other serving, and reaches the wire.** The
//!    custom protocol is retired — its ALPN leaves the node's offers, its
//!    handler's shutdown runs once, its accept task is cancelled, its lane stops
//!    claiming — and a *new* connection on the gossip ALPN is still accepted
//!    afterwards. A second connection offering the retired ALPN never gets past
//!    the handshake, so nothing on this node had to drop it.
//! 3. **A protocol this node is not serving cannot be spoken to.** A peer
//!    offering one it never configured, and a peer arriving after the node's
//!    *last* protocol was retired, are both refused by the handshake — RFC 7301
//!    §3.2 says a server that supports none of what a client advertised SHALL
//!    fail with `no_application_protocol`, and an empty offer list is that case.
//!    The last-lane case is a permanent regression: the client presents an ALPN
//!    extension, but the server's offer list is empty after all protocols are
//!    withdrawn. The handshake must fail with `no_application_protocol`, not
//!    establish without a selected ALPN. The assertions observe the peer's wire
//!    handshake rather than a handler counter. A peer that advertises no ALPN
//!    extension at all is claim 6 below. No handler is reached.
//! 4. **Every handler's shutdown runs exactly once.** Both on an orderly
//!    `close` and for a protocol already retired before it: a retired lane is
//!    shut down by its own close and must not be shut down again by the
//!    endpoint-wide one.
//! 5. **The configuration boundary refuses before anything is built.** A list
//!    naming one ALPN twice, and a protocol asking for the built-in handler when
//!    there is no built-in handler for its ALPN, are both refused by `create`
//!    with a named error and no socket — not an assertion half way through
//!    registration.
//! 6. **A handshake that negotiated no protocol reaches no lane.** A peer whose
//!    ClientHello carries no ALPN extension is a handshake the core *completes*
//!    — RFC 7301 §3.2's `no_application_protocol` is a refusal of an empty
//!    intersection of an offer that was made, and there was no offer — so this
//!    node holds an established connection with no protocol on it and has to
//!    make the refusal itself. It gets exactly the outcome an unroutable
//!    connection gets: counted in `protocols_refused`, dropped without a peer
//!    response, no task left, and no handler given the connection. That last
//!    half is what has teeth: `Connection.negotiatedAlpn` answers this node's
//!    *own first configured protocol* whenever nothing was selected
//!    (`vendor/quic/src/quic/tls13.zig:2060-2063`), which is the gossip lane's,
//!    so an accept path that dispatched on its answer would hand this
//!    connection to the gossip handler. A peer that does negotiate is still
//!    served afterwards, so the refusal is this connection's and not this
//!    node's.
//!
//! # The refusal logs at error level, twice
//!
//! **Two deliberate refusals, and each is logged once.** The vendored core
//! reports a failed handshake step with
//! `std.log.err("TLS 1.3 handshake error: {}", ...)`
//! (`vendor/quic/src/quic/connection.zig:3178`), and
//! `test/expected_log_runner.zig` fails any artifact that logged one it was not
//! told about. The refusal scenarios are:
//!
//! 1. the peer that offers a protocol this node has withdrawn, in "retiring one
//!    protocol…" — the handshake has no protocol in common, so alert 120; and
//! 2. the peer that offers a protocol this node never configured, in "a
//!    protocol this node never offered reaches no handler" — the same empty
//!    intersection, refused the same way; and
//! 3. the peer arriving after the last lane retires — an empty server offer
//!    list must fail the handshake rather than establish without an ALPN.
//!
//! **Once each, and only on the refusing side.** The refusal happens on the
//! node, which is the server: its selection walk over its own list finds nothing
//! the peer also offered, it logs, and it goes straight to
//! `closeWithTransportError(cryptoError(120))`
//! (`vendor/quic/src/quic/connection.zig:3201`) **without ever sending a
//! ServerHello**. The peer therefore receives a CONNECTION_CLOSE and no ALPN
//! extension, its own selection walk never runs, and none of the core's
//! `log.err` sites (1812, 1887, 2194, 2804, 2820, 3178) is a received close — so
//! it logs nothing at all.
//!
//! So this artifact needs **one row** — `scope = "default"`, text
//! `TLS 1.3 handshake error: error.NoApplicationProtocol`, with a count the
//! first real run decides. A second row with the same text would be refused by
//! the runner before any test runs (`expected_log_runner.zig` refuses duplicate
//! rows, and `expected_log_verdict_test.zig` pins that), which is what
//! `build_support.ExpectLog.count` exists to express instead.
//!
//! All three scenarios exercise the same error log. The runner's count must
//! match the completed run: a count that is too low reports an unaccounted line,
//! and one that is too high reports a stale expectation. An earlier assertion
//! failure can stop the retirement scenario before its last-lane refusal.
//!
//! **The refusal in claim 6 is not one of these.** Its handshake *completes*,
//! so there is no core error to report, and the refusal is `node_accept`'s own
//! `std.log.warn` on a connection it drops — warning level, and not a row here.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const node_mod = ozai.node;
// The node is split by responsibility: `node` keeps the data every caller reads
// off a node, and each group of operations is named by the module that owns it.
// `node_protocol` is the contract a handler is written against; the three
// operation groups are construction and disposal, the runtime loop, and the
// close.
const node_protocol = ozai.node_protocol;
const node_lifecycle = ozai.node_lifecycle;
const node_runtime = ozai.node_runtime;
const node_close = ozai.node_close;
const router = ozai.router;
// The router is split by responsibility: `router` keeps the protocol set and
// the values callers pass around (which is all this file needs of it — a
// handler's error set), and the endpoint-wide close is named by the module that
// owns it.
const router_shutdown = ozai.router_shutdown;
const Node = node_mod.Node;
const Connection = node_protocol.Connection;
const Turn = node_protocol.Turn;
const Handler = node_protocol.Handler;

const bridge = ozai.transport_quic_bridge;
const quic_conn = ozai.transport_quic_conn;
const quic_stream = ozai.transport_quic_stream;
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;
const batch = ozai.transport_batch;

const Instant = quic_conn.Instant;
const Conn = quic_conn.Conn;

/// A real loopback socket for a peer and for the node under test.
const loopback: ozai.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// The same clock the node's own tests drive real sockets with: an instant this
/// file owns, advancing by a fixed quantum, so a run's ordering does not depend
/// on how fast the machine is.
const start_ns: Instant = 1_000 * std.time.ns_per_s;
const time_quantum: Instant = 1_000_000;

/// A whole flight fits; a run that needs more says so rather than hanging.
const max_passes = 256;
const max_peers = 4;

/// How many passes a peer gets to fail to establish before the test calls it a
/// refusal. Shorter than `max_passes` on purpose: a handshake that is going to
/// succeed says so in a few passes over a loopback socket, and a test that
/// waits the full bound for a refusal it expects at once is a test that hangs
/// for a reason nobody can read.
const refused_passes = 32;

/// Room for every datagram one drain may produce, and the core's own scratch.
const max_egress = 8;
const max_datagram = 1500;
const send_room: usize = max_egress * max_datagram;
const scratch_room: usize = 2 * max_datagram;
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// A protocol this file's own caller serves. It is not the gossip and it is not
/// the relay, which is the point: a node with a protocol of its own has to name
/// a handler for it.
const bytes_alpn = "/iroh-runtime-bytes/1";

/// A protocol nobody in this file serves, for the handshake that must refuse it.
const absent_alpn = "/iroh-runtime-absent/1";

/// What the peer writes and the handler must read back, byte for byte. Long
/// enough that a partial read is visible as one rather than as a shorter
/// success.
const payload = "runtime-handlers: the payload a protocol's own handler reads.";

/// One caller-supplied protocol handler, with everything it saw on it.
///
/// The three counters are the claims this file makes about a handler that is
/// given a connection by the *production* accept loop: how many turns it was
/// given, how many of those ended the connection, and how many times its own
/// shutdown ran.
const Recorder = struct {
    /// Turns the handler was given. **More than one per connection is normal
    /// and is the point**: a handler that answers `.more` is called again on a
    /// later pass with the same connection.
    turns: u64 = 0,
    /// Turns that ended a connection, which is one per connection this handler
    /// was given.
    finished: u64 = 0,
    /// Turns that asked for another pass. Never zero for a connection whose peer
    /// writes afterwards, which is every connection in this file.
    waits: u64 = 0,
    shutdowns: u64 = 0,
    /// Connections whose payload this handler read to its end.
    payloads: u64 = 0,
    /// The last payload read, in the order the core handed the runs over.
    last: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn deinit(self: *Recorder) void {
        self.last.deinit(self.gpa);
        self.* = undefined;
    }

    /// `Handler.accept`: one turn on one connection.
    ///
    /// **This is the long-lived handler shape, on the production accept path.**
    /// It runs inside a `node_runtime.step` pass, so a turn may read the
    /// connection, write on it and answer — nothing else. A peer cannot have
    /// written anything before this handler's first turn (its stream does not
    /// exist until the handshake it is waiting for completes), so the first turn
    /// finds nothing and answers `.more`; the accept task stays live and the next
    /// pass brings the same connection back here. A body that looped until the
    /// bytes arrived would be a spin inside one pass, and a body that returned at
    /// once would end the connection before the peer's payload was ever read.
    fn accept(ptr: *anyopaque, connection: Connection) router.AcceptError!Turn {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.turns += 1;

        // The handle names the connection and the registration that claimed it,
        // so a handler serving two protocols can tell their connections apart
        // without a socket or a peer address. A claim outside the table is not a
        // claim this handler was given, and refusing it says so rather than
        // reading a connection somebody else owns.
        if (connection.protocol >= node_protocol.max_alpns) return error.NotAllowed;

        // A stream exists only once the peer has opened one, and this handler's
        // job is to read what is on it. No cursor: this end accepted the
        // connection, so the peer's first bidirectional stream is id zero and a
        // cursor of `0` would skip the stream the peer wrote.
        const opened = connection.peerStream(null) orelse {
            self.waits += 1;
            return .more;
        };
        var stream = opened;
        // **An allocation failure here is this handler failing to serve the
        // connection, and it is named as such rather than swallowed.** `drain`
        // reserves before it reads, so `error.OutOfMemory` means the run was
        // never taken and the bytes are still pending on the stream — answering
        // `.finished` here would end a connection over a payload nobody read.
        // `router.AcceptError` is the handler's whole vocabulary and it has no
        // out-of-memory arm, so it becomes the arm it does have, `Connection`,
        // with the cause logged beside it: widening the production error set for
        // one fixture's allocator is not worth it, and losing the cause would be.
        // The bool is not this fixture's to read: the branch below it already
        // decides the turn's answer from `stream.finished()`, which is the fact
        // that matters (has the peer said everything?), and a second decision
        // taken from `moved` would be the same decision twice. Discarding a
        // bool is not discarding an error — the `catch` above is the whole of
        // the error handling, and the handler's next turn re-reads the same
        // stream, whose bytes are still pending.
        _ = stream.drain(self.gpa, &self.last) catch |err| switch (err) {
            error.OutOfMemory => {
                std.log.warn(
                    "runtime handlers: connection {d} payload was not read: {t}",
                    .{ connection.id(), err },
                );
                return error.Connection;
            },
        };
        // One drain takes one contiguous run, so "the payload arrived" is the
        // peer's FIN and not the length of what happened to be ready.
        if (!stream.finished()) {
            self.waits += 1;
            return .more;
        }
        if (std.mem.eql(u8, self.last.items, payload)) self.payloads += 1;

        self.finished += 1;
        return .finished;
    }

    /// `Handler.shutdown`: this protocol's own close, once.
    fn shutdown(ptr: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.shutdowns += 1;
    }

    fn asHandler(self: *Recorder) Handler {
        return .{ .ptr = @ptrCast(self), .accept = accept, .shutdown = shutdown };
    }
};

/// A real peer: a socket, a bridge over it, and a dialer, driven one pass at a
/// time.
///
/// This is the shape `docs` calls the consumer shape, and it is here rather
/// than `test/loopback_link.zig`'s because that harness stands up *both* ends
/// itself: this one has to reach a `Node` that owns its own socket, which means
/// dialling an address this file did not bind.
const Peer = struct {
    socket: socket_mod.Socket,
    bridge: *bridge.Bridge,
    dialer: *dial_mod.Dialer,
    map: addr_map.MappedAddrs,
    engine: std.Random.DefaultPrng,
    secret: ozai.SecretKey,
    egress: []quic_conn.Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    /// `Socket.tryReceive` hands the control messages out of this, and it is
    /// the socket's own type rather than one of the bridge's.
    control: socket_mod.ControlBuffer,
    /// Resolve the dialled id afresh: a sweep invalidates borrowed handles.
    conn_id: ?u64 = null,
    /// Copied from the peer's close before timers can reap its connection.
    remote_close: ?struct { application: bool, code: u64 } = null,
    /// What this peer still has to write, because a stream could not be opened
    /// on an earlier pass.
    owed: []const u8 = &.{},

    /// Built in place, and returned by value only once every field is real.
    ///
    /// **The errdefers below read `self`, so `self` is a value and not a
    /// pointer.** A `var self: Peer = undefined` is already the storage; `self.*`
    /// would dereference a `Peer` as if it were one. Allocation is separate and
    /// stays where it is: the bridge, the dialer and the four buffers are built
    /// after the struct literal, so a failure in any of them unwinds through
    /// these errdefers against the same storage the caller will hold.
    fn init(seed: u8, engine_seed: u64, alpns: []const []const u8) !Peer {
        var self: Peer = .{
            .socket = undefined,
            .bridge = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = std.Random.DefaultPrng.init(engine_seed),
            .secret = try ozai.SecretKey.fromSeed(@splat(seed)),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.secret.deinit();
        errdefer self.map.deinit(t.allocator);

        // **Each errdefer is registered after the thing it releases exists**, so
        // a failure inside `Socket.create` cannot unwind into a `close` of a
        // descriptor that was never opened. The earlier ordering — every
        // errdefer up front — reads tidier and is a use of undefined memory on
        // the first failure.
        self.socket = try socket_mod.Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a run
        // whose Retry key differs on every run has failures that move.
        self.bridge = try bridge.Bridge.create(t.allocator, t.io, .{
            .secret = self.secret,
            .alpns = alpns,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.dialer = try dial_mod.Dialer.create(t.allocator, self.bridge, .{
            .secret = self.secret,
            .alpns = alpns,
        });
        errdefer self.dialer.destroy() catch @panic("a new dialer has no live connections");
        self.egress = try t.allocator.alloc(quic_conn.Egress, max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, send_room);
        errdefer t.allocator.free(self.out);
        self.scratch = try t.allocator.alloc(u8, scratch_room);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, receive_room);
        return self;
    }

    /// The one teardown order that works: the dialled connections leave the
    /// manager before the dialer that opened them goes, backwards, because
    /// `removeConnection` swap-removes.
    fn deinit(self: *Peer) void {
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        self.dialer.destroy() catch @panic("dialer retained a connection after removal");
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

    fn random(self: *Peer) std.Random {
        return self.engine.random();
    }

    fn dial(self: *Peer, target: ozai.SocketAddr, expect: ozai.NodeId, at: Instant) !void {
        const dialled = try self.dialer.dial(
            // A direct address, so nothing here is about a synthetic path: the
            // subject is the accept loop and a relay path would test the map.
            .{ .ip = target },
            expect,
            self.socket.address,
            &self.map,
            at,
            self.random(),
        );
        self.conn_id = dialled.conn.id();
    }

    fn connection(self: *const Peer) ?Conn {
        const id = self.conn_id orelse return null;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.id() == id) return conn;
        }
        return null;
    }

    fn established(self: *const Peer) bool {
        const conn = self.connection() orelse return false;
        return conn.established();
    }

    /// Write `bytes` on a fresh stream, and keep them owed if the peer has not
    /// finished its handshake yet — `quic_stream.openBidi` is refused with
    /// `error.NoStreamRoom` until the server's transport parameters are read,
    /// and that is a fact about the wire rather than a failure.
    fn offer(self: *Peer, at: Instant) void {
        if (self.owed.len == 0) return;
        const conn = self.connection() orelse return;
        var stream = quic_stream.openBidi(conn.entry.conn) catch return;
        const written = stream.write(self.owed) catch return;
        if (written == 0) return;
        self.owed = self.owed[written..];
        stream.close();
        _ = at;
    }

    /// One pass: the kernel, the core, and the timers.
    fn pump(self: *Peer, at: Instant) !void {
        self.offer(at);
        while (true) {
            const sock = &self.socket;
            const got = sock.tryReceive(t.io, self.buf, &self.control) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try self.bridge.recv(&self.map, .{
                    // The loop's bound is `datagramCount` and the accessor goes
                    // null past it.
                    // zwanzig-disable-next-line: optional-unwrap
                    .bytes = recv.datagram(position).?,
                    .from = got.from,
                    .local = self.socket.address,
                    .ecn = recv.ecn,
                }, self.scratch, at, self.random());
                switch (ingress.outcome) {
                    .processed => {},
                    .reply => |reply| _ = try sock.send(t.io, ingress.source.socket, reply),
                    .dropped, .foreign => {},
                }
            }
        }
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (self.conn_id) |id| {
                if (conn.id() == id and conn.entry.conn.isDraining()) {
                    if (conn.entry.conn.local_err) |closed| {
                        self.remote_close = .{ .application = closed.is_app, .code = closed.code };
                    }
                }
            }
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                _ = try self.socket.send(t.io, egress.to, egress.send);
            }
            _ = self.bridge.tick(conn, at, self.random());
        }
        self.bridge.sweep();
    }
};

/// The node under test and every peer talking to it, driven together.
const Harness = struct {
    node: *Node,
    recorder: *Recorder,
    peers: [max_peers]Peer = undefined,
    peer_count: usize = 0,
    at: Instant = start_ns,

    /// One pass of everything: the node's loop, then each peer's.
    ///
    /// The node goes first so a datagram a peer writes in this pass is already
    /// in the kernel when the node's pass runs — the node never blocks, so the
    /// order only decides who sees what in the same pass and never whether a
    /// handshake completes.
    fn round(self: *Harness) !void {
        self.at += time_quantum;
        _ = try node_runtime.step(t.io, self.node, self.at, node_mod.generator(self.node));
        var index: usize = 0;
        while (index < self.peer_count) : (index += 1) {
            try self.peers[index].pump(self.at);
        }
    }

    fn driveUntil(self: *Harness, goal: fn (*const Harness) bool) bool {
        var passes: usize = 0;
        while (passes < max_passes) : (passes += 1) {
            self.round() catch |err| {
                std.debug.print("\nruntime handlers: pass {d} failed: {t}\n", .{ passes, err });
                return false;
            };
            if (goal(self)) return true;
        }
        return false;
    }

    fn addPeer(self: *Harness, seed: u8, alpns: []const []const u8) !*Peer {
        try t.expect(self.peer_count < self.peers.len);
        self.peers[self.peer_count] = try Peer.init(seed, 0xa5a5 + self.peer_count, alpns);
        const peer = &self.peers[self.peer_count];
        self.peer_count += 1;
        try peer.dial(
            node_mod.address(self.node),
            node_mod.nodeId(self.node),
            self.at,
        );
        return peer;
    }
};

/// Every peer's socket, then the node's own close, then the node.
///
/// **The close is not optional and it is not tidiness.** `node_lifecycle.deinit`
/// gives up the endpoint lease without closing the accept loop and reports that
/// at error level, because upstream logs the same thing when an `EndpointInner`
/// is dropped without `close()` (`iroh/src/socket.rs:220-230`) — and this
/// artifact runs under a runner that fails on any error-level log it was not
/// told about. A test that closed the node itself finds the phase already
/// `.closed` and nothing here runs twice.
fn teardown(harness: *Harness) void {
    var index = harness.peer_count;
    while (index > 0) {
        index -= 1;
        harness.peers[index].deinit();
    }
    harness.peer_count = 0;
    if (harness.node.accept.shutdown.phase != .closed) {
        node_close.close(
            t.io,
            harness.node,
            harness.at,
            node_mod.generator(harness.node),
        ) catch |err| std.log.err(
            "runtime handlers: node {f} could not be closed at teardown: {t}",
            .{ node_mod.nodeId(harness.node), err },
        );
    }
    node_lifecycle.deinit(harness.node);
}

/// A node serving the gossip protocol with this file's own built-in handler on a
/// second protocol, which is the shape every other test in this file builds.
fn servingNode(recorder: *Recorder) !*Node {
    return node_lifecycle.create(t.allocator, t.io, .{
        .secret = try ozai.SecretKey.fromSeed(@splat(0x51)),
        .listen = loopback,
        .protocols = &.{
            // The built-in gossip protocol, reached through the one construction
            // path that names a built-in handler.
            .{ .alpn = node_protocol.gossip_alpn },
            // A protocol of this file's own, with this file's own handler.
            .{ .alpn = bytes_alpn, .handler = .{ .custom = recorder.asHandler() } },
        },
    });
}

/// **Both lanes served the one connection each was given.** Counted in
/// `finished`, not in turns: a handler that waits for a peer's bytes is turned
/// more than once for one connection, and the number of connections is what this
/// goal is about.
const bothServed = struct {
    fn goal(harness: *const Harness) bool {
        const gossip = node_close.laneStats(harness.node, 0) orelse return false;
        const bytes = node_close.laneStats(harness.node, 1) orelse return false;
        return gossip.finished == 1 and bytes.finished == 1;
    }
}.goal;

/// The caller's handler has read one payload end to end. One, not two: only
/// the peer on that protocol writes bytes, and the gossip lane's built-in
/// handler has no wire of its own.
const payloadRead = struct {
    fn goal(harness: *const Harness) bool {
        return harness.recorder.payloads == 1;
    }
}.goal;

/// The gossip lane served its first connection, which is the only one it is ever
/// given in the tests that reach for it.
const gossipServed = struct {
    fn goal(harness: *const Harness) bool {
        const gossip = node_close.laneStats(harness.node, 0) orelse return false;
        return gossip.finished == 1;
    }
}.goal;

/// The caller's handler is holding one connection open: it has been given a
/// turn, answered `.more`, and the accept task for it is still live under that
/// lane — which is what makes the retirement below a cancellation rather than a
/// tidy-up after the fact.
const handlerWaiting = struct {
    fn goal(harness: *const Harness) bool {
        const bytes = node_close.laneStats(harness.node, 1) orelse return false;
        return harness.recorder.waits >= 1 and bytes.live == 1;
    }
}.goal;

/// The first peer's handshake is done — the connection claim 6 is about exists
/// and this node is holding it, which is what makes the refusal below the
/// accept loop's own rather than a wire one.
const quietEstablished = struct {
    fn goal(harness: *const Harness) bool {
        return harness.peers[0].established();
    }
}.goal;

/// The node refused a connection's protocol, which is the outcome a connection
/// that negotiated none is given. Read off the counter rather than a handler:
/// the refusal happens before any handler could see the connection.
const protocolRefused = struct {
    fn goal(harness: *const Harness) bool {
        return harness.node.stats.protocols_refused == 1;
    }
}.goal;

test "a connection reaches the handler its ALPN claims, and the payload arrives" {
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    const node = try servingNode(&recorder);
    var harness: Harness = .{ .node = node, .recorder = &recorder };
    defer teardown(&harness);

    // The registration is the claim this file makes about the table itself: one
    // lane per configured protocol, in configuration order, and the two
    // handlers are not the same value.
    try t.expectEqual(@as(usize, 2), node_close.protocols(node));
    try t.expectEqualStrings(node_protocol.gossip_alpn, node_close.laneStats(node, 0).?.alpn);
    try t.expectEqual(
        node_protocol.Standard.gossip,
        node_close.laneStats(node, 0).?.standard.?,
    );
    try t.expectEqualStrings(bytes_alpn, node_close.laneStats(node, 1).?.alpn);
    // A caller's own protocol has no built-in handler behind it.
    try t.expectEqual(@as(?node_protocol.Standard, null), node_close.laneStats(node, 1).?.standard);

    // Two peers, two protocols, and each peer offers exactly one: the ALPN a
    // handshake settles on is the one the peer named, so a node that dispatched
    // by its own preference order would send both connections to one handler.
    const gossip_peer = try harness.addPeer(0x61, &.{node_protocol.gossip_alpn});
    const bytes_peer = try harness.addPeer(0x62, &.{bytes_alpn});
    bytes_peer.owed = payload;

    if (!harness.driveUntil(bothServed)) std.debug.print(
        "\nstalled: attempts {d} routed {d} handler {d}\n" ++
            "  lanes: gossip {d}/{d} bytes {d}/{d}\n" ++
            "  recorder: turns {d} waits {d} payloads {d} bytes {d}\n",
        .{
            node.stats.attempts,
            node.stats.tasks_routed,
            node.stats.handler_connections,
            node_close.laneStats(node, 0).?.finished,
            node_close.laneStats(node, 0).?.turns,
            node_close.laneStats(node, 1).?.finished,
            node_close.laneStats(node, 1).?.turns,
            recorder.turns,
            recorder.waits,
            recorder.payloads,
            recorder.last.items.len,
        },
    );
    try t.expect(harness.driveUntil(bothServed));

    // **One connection each, and each on the lane its ALPN claimed.** The
    // gossip peer's handler is the built-in one, so "and nothing else" is the
    // caller's handler's connection count, which is one and belongs to the other
    // peer.
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 0).?.finished);
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 1).?.finished);
    try t.expectEqual(@as(u64, 2), node.stats.handler_connections);
    try t.expect(gossip_peer.established());
    try t.expect(bytes_peer.established());

    // **And the payload is visible**: the handler read the bytes this peer's
    // socket put on the wire, off the connection the production accept loop
    // handed it.
    try t.expect(harness.driveUntil(payloadRead));
    try t.expectEqualStrings(payload, recorder.last.items);
    try t.expectEqual(@as(u64, 1), recorder.payloads);
    // More turns than connections, and at least one of them a wait. A peer
    // cannot have written anything before this handler's first turn — its stream
    // does not exist until the handshake this handler is waiting behind has
    // completed — so the first turn found nothing, answered `.more`, and the
    // accept task came back on a later pass with the same connection. That is the
    // continuation seam, on the wire, not in a table.
    try t.expect(recorder.turns > 1);
    try t.expect(recorder.waits >= 1);
}

test "retiring one protocol leaves the other serving and the retired one unanswered" {
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    const node = try servingNode(&recorder);
    var harness: Harness = .{ .node = node, .recorder = &recorder };
    defer teardown(&harness);

    // **A connection this lane's handler is still serving.** The peer writes
    // only once its own stream exists, which is after the handshake the handler
    // is waiting behind, so the first turn finds nothing, answers `.more`, and
    // leaves the accept task live. Retiring into that state is the whole claim:
    // a lane that is closed with work under it must cancel that work.
    const held = try harness.addPeer(0x71, &.{bytes_alpn});
    held.owed = payload;
    try t.expect(harness.driveUntil(handlerWaiting));
    try t.expectEqual(@as(usize, 1), node_close.laneStats(node, 1).?.live);
    try t.expectEqual(@as(u64, 0), recorder.finished);
    const turns_before_retire = recorder.turns;

    // Retire the custom protocol. This is the per-protocol close, in the order
    // `lifetime.Lifetime` enforces: the handler's shutdown, then this protocol's
    // accepts, then the lane is closed.
    try node_close.retire(t.io, node, bytes_alpn, harness.at);

    const retired = node_close.laneStats(node, 1).?;
    try t.expect(!retired.serving);
    try t.expectEqual(@as(u64, 1), retired.shutdowns);
    try t.expectEqual(@as(usize, 0), retired.live);
    // And it ran the handler's own shutdown exactly once, not once through the
    // lane and once through the node.
    try t.expectEqual(@as(u64, 1), recorder.shutdowns);
    // The other lane is untouched by any of it.
    try t.expect(node_close.laneStats(node, 0).?.serving);

    // The peer received the application close, independently of the core's
    // three-PTO draining timer. Requiring termination here would test that timer
    // instead of the retirement's wire effect.
    var closed_passes: usize = 0;
    while (closed_passes < refused_passes and held.remote_close == null) : (closed_passes += 1) {
        try harness.round();
    }
    const closed = held.remote_close orelse return error.TestExpectedEqual;
    try t.expect(closed.application);
    try t.expectEqual(@as(u64, 0), closed.code);
    try t.expect(!held.established());
    try t.expectEqual(turns_before_retire, recorder.turns);
    try t.expectEqual(@as(usize, 0), node.accept.live);

    // A new connection on the *other* protocol is still accepted, which is the
    // whole claim: retiring one lane is not this node's shutdown.
    _ = try harness.addPeer(0x72, &.{node_protocol.gossip_alpn});
    try t.expect(harness.driveUntil(gossipServed));
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 0).?.finished);

    // The retirement reached the wire, not just the router: this node no longer
    // offers the protocol, which is read off the bridge's own list rather than
    // inferred from the table.
    const wire = node.bridge.tlsConfig().alpn;
    try t.expectEqual(@as(usize, 1), wire.len);
    try t.expectEqualStrings(node_protocol.gossip_alpn, wire[0]);

    // So a new connection offering the *retired* protocol does not get as far as
    // a router: the handshake has no protocol in common, so the core answers
    // RFC 8446 alert 120 and neither end establishes. That is a different
    // refusal from the one below, and asserting only "no handler ran" would pass
    // against a node that accepted everything and hung up.
    const after = try harness.addPeer(0x73, &.{bytes_alpn});
    var passes: usize = 0;
    while (passes < refused_passes and !after.established()) : (passes += 1) {
        try harness.round();
    }
    // Never established, on this peer or on the node: the handshake died before
    // either end had a protocol.
    try t.expect(!after.established());
    try t.expectEqual(@as(u64, 0), recorder.finished);
    try t.expectEqual(turns_before_retire, recorder.turns);
    try t.expectEqual(@as(u64, 1), recorder.shutdowns);
    // Nothing reached a router that could claim it, so nothing was dropped after
    // the fact either — this refusal cost the wire, not the handler.
    try t.expectEqual(@as(u64, 0), node.stats.protocols_refused);

    // **And the last lane.** RFC 7301 §3.2: a server that supports none of the
    // protocols a client advertised SHALL fail the handshake with
    // `no_application_protocol`. That is exactly what retiring the node's last
    // protocol leaves behind — an offer list with nothing in it — so this peer
    // must not establish either. This regression detects the old
    // `if (!matched and self.config.alpn.len > 0)` guard, which let an empty
    // server offer list establish without selecting a protocol. The evidence
    // is the peer's handshake, not merely a handler counter.
    try node_close.retire(t.io, node, node_protocol.gossip_alpn, harness.at);
    try t.expect(!node_close.laneStats(node, 0).?.serving);
    try t.expectEqual(@as(u64, 2), node.stats.handler_shutdowns);
    const last = try harness.addPeer(0x74, &.{node_protocol.gossip_alpn});
    var last_passes: usize = 0;
    while (last_passes < refused_passes and !last.established()) : (last_passes += 1) {
        try harness.round();
    }
    // Never established, and no handler anywhere near it: this node serves no
    // protocol at all, so there is nothing to hand a connection to.
    try t.expect(!last.established());
    try t.expectEqual(@as(u64, 0), recorder.finished);
    try t.expectEqual(turns_before_retire, recorder.turns);
    // And the shutdown this refusal sat behind ran once, with the retire.
    try t.expectEqual(@as(u64, 2), node.stats.handler_shutdowns);
}

test "a protocol this node never offered reaches no handler" {
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    const node = try servingNode(&recorder);
    var harness: Harness = .{ .node = node, .recorder = &recorder };
    defer teardown(&harness);

    // A wrong protocol fails the handshake with RFC 8446 alert 120. Its pending
    // accept must be released when that failure closes the transport, without
    // waiting for the core's three-PTO connection reclamation.
    const stranger = try harness.addPeer(0x81, &.{absent_alpn});
    var passes: usize = 0;
    while (passes < refused_passes and
        (stranger.remote_close == null or node.accept.live != 0)) : (passes += 1)
    {
        try harness.round();
    }

    try t.expect(!stranger.established());
    const refused = stranger.remote_close orelse return error.TestExpectedEqual;
    try t.expect(!refused.application);
    try t.expectEqual(@as(u64, 0x100 + 120), refused.code);
    try t.expectEqual(@as(u64, 0), recorder.turns);
    try t.expectEqual(@as(u64, 0), node.stats.handler_connections);
    try t.expectEqual(@as(u64, 0), node.stats.protocols_refused);
    try t.expectEqual(@as(usize, 0), node.accept.live);

    // A peer that *can* be served is served, so the refusal above is a refusal
    // and not a node that serves nobody.
    _ = try harness.addPeer(0x82, &.{node_protocol.gossip_alpn});
    try t.expect(harness.driveUntil(gossipServed));
}

test "a peer that negotiates no protocol reaches no handler" {
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    const node = try servingNode(&recorder);
    var harness: Harness = .{ .node = node, .recorder = &recorder };
    defer teardown(&harness);

    // **A peer whose ClientHello carries no ALPN extension at all**, which is
    // a peer `Dialer.create` cannot be asked for: `validateAlpns` refuses an
    // empty offer list by name (`src/transport/quic_config.zig:84-91`), because
    // a first-party dialer always has something to offer. What a dialer writes
    // into a ClientHello is `tlsConfigFor`'s `alpn`, which is
    // `alpn_list[0..alpn_count]` (`src/transport/dial.zig:462-493`), so the
    // count is emptied here — after the check that guards the configuration API
    // has run, and past the field's own note that a zero count belongs to a
    // `create` that was refused (`dial.zig:383-384`).
    //
    // **Only that one field, and what it buys is the wire shape and nothing
    // else**: the ClientHello this puts on the wire is written by the vendored
    // core's own `buildClientHello`, which omits the extension for an empty
    // offer list (`vendor/quic/src/quic/tls13.zig:4338-4339`), and every other
    // byte of this peer is this file's ordinary `Socket` + `Bridge` +
    // `Dialer`. A peer that names no protocol is something a *remote* peer can
    // be — that is the whole reachability claim — and nothing in this project
    // configures one into being.
    //
    // The bridge keeps its own real list: it is this peer's listener half, and
    // no connection on it is accepted in this test.
    try t.expect(harness.peer_count == 0);
    harness.peers[0] = try Peer.init(0x91, 0xa5a5, &.{bytes_alpn});
    harness.peer_count = 1;
    const quiet = &harness.peers[0];
    quiet.dialer.alpn_count = 0;
    try quiet.dial(node_mod.address(node), node_mod.nodeId(node), harness.at);

    // **The handshake completes**, and that is the whole reason this node has
    // to refuse the connection itself. The core's `no_application_protocol` is
    // a refusal of an empty intersection of an offer that *was* made
    // (`vendor/quic/src/quic/tls13.zig:3169-3178`), and it lives inside the
    // ALPN extension's parse, which a ClientHello carrying no extension never
    // reaches (`tls13.zig:3100-3114`) — the core says so in its own terms at
    // `tls13.zig:1432-1435`, "neither end fails". So what arrives below is an
    // established connection with no protocol on it, admitted by the filter and
    // holding an accept task.
    try t.expect(harness.driveUntil(quietEstablished));
    try t.expectEqual(@as(u64, 1), node.stats.attempts);
    try t.expectEqual(@as(u64, 1), node.stats.spawned);

    // **And the accept path refuses it**, which is the outcome an unroutable
    // connection already gets.
    if (!harness.driveUntil(protocolRefused)) std.debug.print(
        "\nruntime handlers: unnegotiated peer — attempts {d} spawned {d} routed {d}" ++
            " handler {d} refused {d} live {d}\n",
        .{
            node.stats.attempts,
            node.stats.spawned,
            node.stats.tasks_routed,
            node.stats.handler_connections,
            node.stats.protocols_refused,
            node.accept.live,
        },
    );
    try t.expect(harness.driveUntil(protocolRefused));

    // Counted where every refusal is counted, dropped without a peer response,
    // and the connection is the core's to close and drain.
    try t.expectEqual(@as(u64, 1), node.stats.protocols_refused);
    try t.expectEqual(@as(usize, 0), node.accept.live);
    // **A claim and not a report**: nothing claimed this connection, so no task
    // ever carried a protocol and the routed counter never moved.
    try t.expectEqual(@as(u64, 0), node.stats.tasks_routed);
    try t.expectEqual(@as(u64, 0), node.stats.handler_connections);
    try t.expectEqual(@as(u64, 0), recorder.turns);
    // **And not only the caller's lane — this is the half with teeth.**
    // `Connection.negotiatedAlpn` answers `config.alpn[0]` when nothing was
    // selected (`vendor/quic/src/quic/tls13.zig:2060-2063`), and this node's
    // `config.alpn[0]` is the gossip ALPN, so an accept path that dispatched
    // on that answer would have handed this connection to the gossip handler
    // on a protocol this peer never named.
    try t.expectEqual(@as(u64, 0), node_close.laneStats(node, 0).?.finished);
    try t.expectEqual(@as(u64, 0), node_close.laneStats(node, 0).?.turns);

    // **And a peer that does negotiate is still served**, so what was refused
    // is this connection and not this node.
    _ = try harness.addPeer(0x92, &.{node_protocol.gossip_alpn});
    try t.expect(harness.driveUntil(gossipServed));
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 0).?.finished);
}

test "every handler's shutdown runs exactly once, retired or not" {
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    const node = try servingNode(&recorder);
    var harness: Harness = .{ .node = node, .recorder = &recorder };

    // Retire one protocol first, so the close below meets a lane that has
    // already been shut down: the endpoint-wide close must not shut it down a
    // second time.
    try node_close.retire(t.io, node, bytes_alpn, harness.at);
    try t.expectEqual(@as(u64, 1), recorder.shutdowns);

    try node_close.close(t.io, node, harness.at, node_mod.generator(node));
    try t.expectEqual(router_shutdown.Shutdown.Phase.closed, node.accept.shutdown.phase);

    // One per configured protocol, and the retired one counted once in total.
    try t.expectEqual(@as(u64, 2), node.stats.handler_shutdowns);
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 0).?.shutdowns);
    try t.expectEqual(@as(u64, 1), node_close.laneStats(node, 1).?.shutdowns);
    try t.expectEqual(@as(u64, 1), recorder.shutdowns);

    teardown(&harness);
}

test "the configuration boundary refuses a duplicate and a protocol with no handler" {
    // Two registrations naming one ALPN is a configuration fact and not
    // something to discover in an assertion half way through building the
    // table: nothing is allocated, so nothing has to be given back.
    try t.expectError(error.DuplicateProtocol, node_lifecycle.create(t.allocator, t.io, .{
        .secret = try ozai.SecretKey.fromSeed(@splat(0x91)),
        .listen = loopback,
        .protocols = &.{
            .{ .alpn = node_protocol.gossip_alpn },
            .{ .alpn = node_protocol.gossip_alpn },
        },
    }));

    // Asking for the built-in handler on a protocol this node has no built-in
    // handler for is the same kind of mistake, and it is refused by name rather
    // than served by a counter that means nothing.
    try t.expectError(error.NoStandardProtocol, node_lifecycle.create(t.allocator, t.io, .{
        .secret = try ozai.SecretKey.fromSeed(@splat(0x92)),
        .listen = loopback,
        .protocols = &.{.{ .alpn = bytes_alpn }},
    }));

    // Both built-ins are reachable through that one path, which is what makes
    // the refusal above a fact about the ALPN rather than a missing feature.
    const both = try node_lifecycle.create(t.allocator, t.io, .{
        .secret = try ozai.SecretKey.fromSeed(@splat(0x93)),
        .listen = loopback,
        .protocols = &.{
            .{ .alpn = node_protocol.gossip_alpn },
            .{ .alpn = node_protocol.relay_alpn },
        },
    });
    // Closed before it is dropped, for the reason `teardown` gives: a node whose
    // accept loop is still serving when it goes is a misuse, and this node says
    // so at error level — which this artifact's runner fails on.
    try node_close.close(t.io, both, start_ns, node_mod.generator(both));
    defer node_lifecycle.deinit(both);
    try t.expectEqual(node_protocol.Standard.gossip, node_close.laneStats(both, 0).?.standard.?);
    try t.expectEqual(node_protocol.Standard.relay, node_close.laneStats(both, 1).?.standard.?);

    // Retiring a protocol this node does not serve is refused rather than
    // silently doing nothing, for the same reason.
    try t.expectError(error.NoSuchProtocol, node_close.retire(t.io, both, absent_alpn, start_ns));
}
