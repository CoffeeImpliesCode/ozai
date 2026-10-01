//! The first application protocol over a real connection: gossip between ozai
//! endpoints, and the plan's blob property over the same socket.
//!
//! `test/loopback_test.zig` proved two endpoints can finish a handshake and
//! move bytes. What it moved was a question and an answer the test chose
//! itself, so the protocol was never asked whether its half of the stack fits
//! the other half's. Nothing in this project has yet sent a *protocol message*
//! across a kernel socket. This file does, and it starts with the layer
//! `docs/PLAN.md` names first: `src/gossip/`.
//!
//! # What is asserted, and what is not
//!
//! The bar is the plan's own — "two Zig nodes must agree with the reference on
//! membership convergence, not merely exchange bytes" — and the reference bar
//! is the one `src/gossip/hyparview.zig` already holds itself to in
//! "a bootstrapped swarm converges". So the assertions here are:
//!
//! 1. **Nobody is left out.** Every node's active view is non-empty, and
//!    every count is inside the configured capacity. A node left with no
//!    neighbour is named by index, with the peers it *is* adjacent to.
//! 2. **The disagreement stops.** `asymmetricLinks` — a link one end believes
//!    in and the other has no record of — is measured once the swarm has
//!    settled and again at the end, and the two must be equal. It is not
//!    required to be zero, because the simulator's own doc says it is not
//!    always zero and that the cause is upstream rather than a port defect.
//! 3. **The broadcast reaches everybody, once.** One PlumTree broadcast from
//!    one node arrives at every other node exactly once, with no duplicate,
//!    and leaves the membership it was built on untouched.
//! 4. **The transport really is six sockets.** Every link is a completed TLS
//!    handshake, every node's peer identity was proved by the pin the dialer
//!    carried, and the six ports are six distinct ephemeral ports.
//!
//! No message count is an assertion. `frames_read` and `frames_written` are
//! printed by `Mesh.report` and never checked: a protocol that delivered every
//! message to a machine that disagreed about membership would fail above.
//!
//! # The codec in this file is the test's own
//!
//! `src/gossip/hyparview.zig` says so itself: "this module has no wire codec".
//! A protocol message cannot cross a socket without bytes, so this file
//! supplies them, and they are **not** the project's wire format — they are one
//! plausible encoding, chosen so the state machines' own types can be
//! exercised unchanged. Nothing under `src/` depends on them and no golden
//! vector claims otherwise. A real codec belongs to the milestone that ships
//! the protocol; what is under test here is the *stack*, not the encoding.
//!
//! Two things about it are deliberate rather than accidental. Every
//! discriminant is an explicit tag byte rather than a union's declaration
//! order, so reordering an arm in `src/gossip/` cannot silently change these
//! bytes. And every slice a decoded message carries is borrowed out of the
//! frame it was decoded from and consumed inside the same call, which is the
//! borrow rule both gossip layers document — so the harness copies every
//! outgoing message into a queue before the next `handle` on the same state.
//!
//! # The transport under the protocol
//!
//! Four nodes, each with its own socket, its own `Bridge` and its own
//! `Dialer`. Node `i` dials node `j` for every `j > i`, so every pair has
//! exactly one connection with the lower index as the client: six connections,
//! six ephemeral ports, and a link whose two ends agree on who opened what
//! without either being told.
//!
//! A connection carries exactly two bidirectional streams, one per direction:
//! stream `0` is the client's, stream `1` is the server's. That is not a
//! convention this file invented — RFC 9000 §2.1 numbers a client-initiated
//! bidirectional stream `4n` and a server-initiated one `4n + 1`, so with one
//! stream opened per side the ids are determined by role alone. Each side
//! writes only its own and reads only its peer's, which is what makes a
//! length-prefixed frame on a byte stream the whole of the framing.
//!
//! # Time is virtual and moves only when the test says so
//!
//! Every call into the QUIC core takes an `Instant` and every call into the
//! gossip state machines takes a `now`. This file owns one counter and
//! advances it by one millisecond per round. No clock is ever read and nothing
//! sleeps anywhere in this file. The bound is on rounds, so a run that never
//! converges ends by saying where it stopped rather than by hanging. The total
//! virtual time stays far below the core's 30 s idle timeout, so a connection
//! is never reaped by the clock — a reaped connection would be a finding about
//! time and not about gossip.
//!
//! # `disconnect_peer`, and the one thing this harness does differently
//!
//! Membership asks the application to close a connection in three places. The
//! reference simulator (`sim.Network::tick`) answers with `killConnection`,
//! which does two things: it removes the pair from a bookkeeping table, and it
//! delivers `peer_disconnected` to the far end. Its *message* path never
//! consults that table — `send_message` enqueues whether or not the pair is in
//! it.
//!
//! So the faithful port here keeps the descriptor and delivers the event, and
//! that is what `handleOut` does. Tearing the QUIC connection down as well
//! would be *less* faithful to the reference than keeping it, because the
//! reference keeps sending. The count of teardowns asked for is printed by
//! `Mesh.report` so a reader can see how often it happened.
//!
//! # Ordering, and why it is not the simulator's ordering
//!
//! The simulator's queue is ordered by `(time, insertion order)`. This file's
//! is ordered by round, and a `disconnect_peer` is delivered at the end of the
//! round that produced it rather than one microsecond later. The two are not
//! event-for-event comparable, and `src/gossip/hyparview.zig` says why: the
//! reference seeds `ChaCha12` and this port seeds `xoshiro256`, so "the same
//! bits" was never on offer. What is on offer, and what is asserted, is the
//! outcome — the same neighbour sets, the same delivery counts, the same
//! synchrony. That is the claim the module makes, and this file holds the port
//! to it against a kernel instead of against itself.
//!
//! # Blobs, and what is deliberately not proved here
//!
//! The plan's property for blobs is "**missing data is EOF, not an error
//! frame**". This file proves the transport half: a `get` runs to the end of
//! its stream, the provider that has nothing closes the stream without writing
//! a byte, and the getter sees zero bytes with its FIN set and no reset — and a
//! reset is what an error would have cost this layer, because
//! `src/blobs/protocol.zig` has no error frame and says so in its own doc. A
//! second stream, answered with bytes, shows the getter's read path is not
//! vacuously empty.
//!
//! What is **not** proved: that those bytes are valid bao data. This project
//! has no bao encoder, so the provider's answer is opaque bytes and only the
//! framing is under test. `src/blobs/protocol.zig`'s own tests cover the
//! request codecs, and this file adds the socket they had never met.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;
const plumtree = ozai.gossip_plumtree;
const postcard = ozai.postcard;
const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;
const batch = ozai.transport_batch;
const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;

const Bridge = bridge_mod.Bridge;
const Conn = bridge_mod.Conn;
const Egress = bridge_mod.Egress;
const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine
/// has to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

/// Where every socket binds, with port zero: the kernel picks, so a socket
/// left over from the last run cannot collide with this one.
const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. See the module doc: it only ever moves by
/// `time_quantum`.
const start_ns: gossip.Nanos = 1_000 * std.time.ns_per_s;

/// How far the clock moves per round. A round is a handful of syscalls, so this
/// is a clock and not a delay: nothing in this file waits for it to elapse.
const time_quantum: gossip.Nanos = gossip.nanos_per_milli;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small.
const max_egress = 8;

/// Room for every datagram one drain may produce.
const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: the datagram is copied into its front and a
/// stateless reply is written behind it.
const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How many rounds a phase may take before it is called stalled.
///
/// Generous, because a round is a few syscalls and nothing here can block: the
/// bound is a backstop against a run that never converges, not a timer.
const max_rounds = 512;

/// Nodes in the gossip mesh. More than two, and small enough that every node
/// can hold every other in its active view under the default capacity of five,
/// so a converged swarm is a statement about membership and not about capacity.
const node_count = 4;
const max_nodes = node_count;

/// The ALPN both ends of a gossip link speak. Upstream's is
/// `b"/iroh-gossip/1"`; the gossip module carries no ALPN of its own, and this
/// is the one `docs/PLAN.md` names at M9.
const gossip_alpn = "/iroh-gossip/1";

/// The largest frame this codec will produce or accept.
///
/// A `Shuffle` is the biggest membership message: `max_shuffle_nodes` peer
/// records of up to `peer_data_max` bytes each, plus the fixed fields. 8 KiB
/// leaves room for every arm of both layers' message sets with the project's
/// own bounds in force, and a frame over it is reported rather than truncated.
const max_frame = 8 * 1024;

/// How many unread bytes one link's receive buffer may hold when a round ends.
/// A bound, not a policy: over it, the reader is not keeping up, which is a
/// finding and not something to grow around.
const max_backlog = max_frame * 64;

/// The codec's scratch, and the one decoded frame at a time. Every borrow out
/// of `frame` is consumed before the next one lands in it.
const codec_room = 2 * max_frame;

// ---------------------------------------------------------------------------
// The codec
// ---------------------------------------------------------------------------

/// What this codec refuses. `postcard.Error` and `KeyError` are included
/// rather than restated: a varint that does not end and a node id that is not
/// on the curve are both refusals a peer can provoke.
const WireError = postcard.Error || ozai.KeyError || gossip.Error || plumtree.Error ||
    error{
        /// A frame declared more bytes than `max_frame` allows.
        FrameTooLong,
        /// A tag byte this build has no arm for.
        UnknownVariant,
        /// A peer list longer than `max_shuffle_nodes`.
        PeerListTooLong,
        /// An `IHave` list longer than `max_ihaves_per_message`.
        IHaveListTooLong,
    };

/// The two arms of `hyparview.Message`, named rather than derived from the
/// union's field order.
const msg_swarm: u8 = 0;
const msg_gossip: u8 = 1;

/// The arms of `hyparview.SwarmMessage`.
const swarm_join: u8 = 0;
const swarm_forward_join: u8 = 1;
const swarm_shuffle: u8 = 2;
const swarm_shuffle_reply: u8 = 3;
const swarm_neighbor: u8 = 4;
const swarm_disconnect: u8 = 5;

/// The arms of `plumtree.Message`.
const tree_gossip: u8 = 0;
const tree_prune: u8 = 1;
const tree_graft: u8 = 2;
const tree_i_have: u8 = 3;

/// `hyparview.Priority`, as a tag byte.
const priority_high: u8 = 0;
const priority_low: u8 = 1;

/// `plumtree.DeliveryScope`, as a tag byte.
const scope_neighbors: u8 = 0;
const scope_swarm: u8 = 1;

/// Encode a protocol message into `out`, and return what it wrote.
fn encodeMessage(message: gossip.Message, out: []u8) WireError![]const u8 {
    var w = postcard.Writer.init(out);
    switch (message) {
        .swarm => |swarm| {
            try w.writeU8(msg_swarm);
            try encodeSwarm(&w, swarm);
        },
        .gossip => |tree| {
            try w.writeU8(msg_gossip);
            try encodeTree(&w, tree);
        },
    }
    return w.finish();
}

/// Decode a protocol message from `frame`.
///
/// Every slice the returned value carries is borrowed from `frame` and is only
/// valid until the caller reuses it. That is the borrow rule both gossip
/// layers document, and it is why the mesh consumes a frame inside one call.
fn decodeMessage(frame: []const u8) WireError!gossip.Message {
    var r = postcard.Reader.init(frame);
    return switch (try r.readU8()) {
        msg_swarm => .{ .swarm = try decodeSwarm(&r) },
        msg_gossip => .{ .gossip = try decodeTree(&r) },
        else => error.UnknownVariant,
    };
}

fn encodeSwarm(w: *postcard.Writer, message: gossip.SwarmMessage) WireError!void {
    switch (message) {
        .join => |data| {
            try w.writeU8(swarm_join);
            try encodeData(w, data);
        },
        .forward_join => |forward| {
            try w.writeU8(swarm_forward_join);
            try encodeInfo(w, forward.peer);
            try w.writeU16(forward.ttl.value);
        },
        .shuffle => |shuffle| {
            try w.writeU8(swarm_shuffle);
            try encodeId(w, shuffle.origin);
            try encodeInfos(w, shuffle.nodes);
            try w.writeU16(shuffle.ttl.value);
        },
        .shuffle_reply => |reply| {
            try w.writeU8(swarm_shuffle_reply);
            try encodeInfos(w, reply.nodes);
        },
        .neighbor => |neighbor| {
            try w.writeU8(swarm_neighbor);
            try w.writeU8(switch (neighbor.priority) {
                .high => priority_high,
                .low => priority_low,
            });
            try encodeData(w, neighbor.data);
        },
        .disconnect => |disconnect| {
            try w.writeU8(swarm_disconnect);
            try w.writeBool(disconnect.alive);
        },
    }
}

fn decodeSwarm(r: *postcard.Reader) WireError!gossip.SwarmMessage {
    return switch (try r.readU8()) {
        swarm_join => .{ .join = try decodeData(r) },
        swarm_forward_join => .{ .forward_join = .{
            .peer = try decodeInfoOf(r),
            .ttl = .{ .value = try r.readU16() },
        } },
        swarm_shuffle => .{ .shuffle = .{
            .origin = try decodeId(r),
            .nodes = try decodeInfos(r),
            .ttl = .{ .value = try r.readU16() },
        } },
        swarm_shuffle_reply => .{ .shuffle_reply = .{ .nodes = try decodeInfos(r) } },
        swarm_neighbor => .{ .neighbor = .{
            .priority = switch (try r.readU8()) {
                priority_high => .high,
                priority_low => .low,
                else => return error.UnknownVariant,
            },
            .data = try decodeData(r),
        } },
        swarm_disconnect => .{ .disconnect = .{ .alive = try r.readBool() } },
        else => error.UnknownVariant,
    };
}

fn encodeTree(w: *postcard.Writer, message: plumtree.Message) WireError!void {
    switch (message) {
        .gossip => |payload| {
            try w.writeU8(tree_gossip);
            try w.writeArray(plumtree.id_length, &payload.id.bytes);
            try w.writeBytes(payload.content);
            switch (payload.scope) {
                .neighbors => try w.writeU8(scope_neighbors),
                .swarm => |round| {
                    try w.writeU8(scope_swarm);
                    try w.writeU16(round.value);
                },
            }
        },
        .prune => try w.writeU8(tree_prune),
        .graft => |graft| {
            try w.writeU8(tree_graft);
            try w.writeOption(graft.id != null);
            if (graft.id) |id| try w.writeArray(plumtree.id_length, &id.bytes);
            try w.writeU16(graft.round.value);
        },
        .i_have => |ihaves| {
            try w.writeU8(tree_i_have);
            const items = ihaves.slice();
            try w.writeLen(items.len);
            for (items) |have| {
                try w.writeArray(plumtree.id_length, &have.id.bytes);
                try w.writeU16(have.round.value);
            }
        },
    }
}

fn decodeTree(r: *postcard.Reader) WireError!plumtree.Message {
    return switch (try r.readU8()) {
        tree_gossip => blk: {
            const id = plumtree.MessageId{ .bytes = try r.readArray(plumtree.id_length) };
            const content = try r.readBytes();
            const scope: plumtree.DeliveryScope = switch (try r.readU8()) {
                scope_neighbors => .neighbors,
                scope_swarm => .{ .swarm = .{ .value = try r.readU16() } },
                else => return error.UnknownVariant,
            };
            break :blk .{ .gossip = .{ .id = id, .content = content, .scope = scope } };
        },
        tree_prune => .{ .prune = {} },
        tree_graft => blk: {
            var id: ?plumtree.MessageId = null;
            if (try r.readOption()) {
                id = .{ .bytes = try r.readArray(plumtree.id_length) };
            }
            break :blk .{ .graft = .{
                .id = id,
                .round = .{ .value = try r.readU16() },
            } };
        },
        tree_i_have => blk: {
            const count = try r.readLen();
            if (count > plumtree.max_ihaves_per_message) return error.IHaveListTooLong;
            var items: [plumtree.max_ihaves_per_message]plumtree.IHave = undefined;
            for (items[0..count]) |*have| {
                have.* = .{
                    .id = .{ .bytes = try r.readArray(plumtree.id_length) },
                    .round = .{ .value = try r.readU16() },
                };
            }
            break :blk .{ .i_have = try plumtree.IHaves.init(items[0..count]) };
        },
        else => error.UnknownVariant,
    };
}

fn encodeId(w: *postcard.Writer, id: NodeId) WireError!void {
    try w.writeArray(NodeId.byte_length, &id.toBytes());
}

fn decodeId(r: *postcard.Reader) WireError!NodeId {
    return NodeId.fromBytes(try r.readArray(NodeId.byte_length));
}

fn encodeData(w: *postcard.Writer, data: ?[]const u8) WireError!void {
    try w.writeOption(data != null);
    if (data) |bytes| try w.writeBytes(bytes);
}

fn decodeData(r: *postcard.Reader) WireError!?[]const u8 {
    if (!try r.readOption()) return null;
    const bytes = try r.readBytes();
    return bytes;
}

fn encodeInfo(w: *postcard.Writer, info: gossip.PeerInfo) WireError!void {
    try encodeId(w, info.id);
    try encodeData(w, info.data);
}

fn encodeInfos(w: *postcard.Writer, list: gossip.PeerInfos) WireError!void {
    const items = list.slice();
    try w.writeLen(items.len);
    for (items) |info| try encodeInfo(w, info);
}

fn decodeInfoOf(r: *postcard.Reader) WireError!gossip.PeerInfo {
    return .{ .id = try decodeId(r), .data = try decodeData(r) };
}

fn decodeInfos(r: *postcard.Reader) WireError!gossip.PeerInfos {
    const count = try r.readLen();
    if (count > gossip.max_shuffle_nodes) return error.PeerListTooLong;
    var items: [gossip.max_shuffle_nodes]gossip.PeerInfo = undefined;
    for (items[0..count]) |*info| {
        info.* = .{ .id = try decodeId(r), .data = try decodeData(r) };
    }
    return gossip.PeerInfos.init(items[0..count]);
}

/// A frame around a message: a `varint(u64)` length, then that many bytes.
///
/// The length prefix is the whole of the framing, and it is postcard's own —
/// `writeBytes` writes a `varint(u64)` length and then the bytes verbatim,
/// which is exactly the frame, and `readLen` is its reader. Nothing here
/// invents a width, and the prefix is what makes a byte stream a message
/// stream: a stream can then carry many messages, and a frame split across two
/// packets is a frame the reader waits for rather than a message it guessed.
fn encodeFrame(
    message: gossip.Message,
    body: []u8,
    out: []u8,
) WireError![]const u8 {
    const payload = try encodeMessage(message, body);
    if (payload.len > max_frame) return error.FrameTooLong;
    var w = postcard.Writer.init(out);
    try w.writeBytes(payload);
    return w.finish();
}

/// One timer either layer asked for, with the instant it comes due.
///
/// The `Timer` is a copy rather than a borrow: the union carries a `MessageId`
/// and a `NodeId` by value, so nothing here points into a state that moves.
const PendingTimer = struct {
    due: gossip.Nanos,
    timer: gossip.Timer,
};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One endpoint's transport: an identity, a socket on an ephemeral loopback
/// port, the bridge that runs its connections, and the buffers both seams need.
///
/// It carries no protocol state, because the gossip mesh and the blobs pair
/// want different state on top of exactly this.
const Wire = struct {
    name: []const u8,
    index: usize,
    id: NodeId,
    secret: SecretKey,
    socket: Socket,
    bridge: *Bridge,
    dialer: *Dialer,
    map: addr_map.MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,

    fn init(
        self: *Wire,
        name: []const u8,
        index: usize,
        secret: SecretKey,
        expect_peer: ?NodeId,
        alpn: []const u8,
        seed: u64,
    ) !void {
        self.* = .{
            .name = name,
            .index = index,
            .id = secret.nodeId(),
            .secret = secret,
            .socket = undefined,
            .bridge = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.map.deinit(t.allocator);
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a
        // test whose Retry key differs on every run has failures that move.
        self.bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = secret,
            .expect_peer = expect_peer,
            .alpn = alpn,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.dialer = try Dialer.create(t.allocator, self.bridge, .{
            .secret = secret,
            .alpn = alpn,
        });
        errdefer self.dialer.destroy() catch @panic("new dialer has no live connections");
        // A bridge that was created a moment ago has no entry for `destroy` to
        // refuse, so this fires only on an allocation that followed it.
        self.egress = try t.allocator.alloc(Egress, max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, send_room);
        errdefer t.allocator.free(self.out);
        self.scratch = try t.allocator.alloc(u8, scratch_room);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, receive_room);
    }

    /// Unwind order matters, and it is `Dialer.destroy`'s: a dialled
    /// connection's handshake points at the dialer's own seed, so every
    /// connection this dialer opened has to leave the manager before the
    /// dialer goes, and the manager has to outlive both.
    fn deinit(self: *Wire) void {
        // Backwards, because `removeConnection` swap-removes and a forward walk
        // would skip an entry and leave a freed one behind.
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        // Only server entries can survive: the bridge never dials, and no code
        // between the removal walk and destroy can add another connection.
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

    fn random(self: *Wire) std.Random {
        return self.engine.random();
    }

    /// Take everything queued on this socket and hand it to the bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into one
    /// buffer, so the stride is what says how many packets there are and the
    /// bridge is handed them one at a time.
    fn take(self: *Wire, at: Instant, stats: *Counters) !bool {
        var moved = false;
        while (true) {
            const sock = &self.socket;
            const got = sock.tryReceive(t.io, self.buf, &self.control) catch |err| switch (err) {
                // The socket is non-blocking from the moment it was created,
                // and an empty queue is a fact the loop acts on.
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            stats.in += recv.datagramCount();
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try self.bridge.recv(&self.map, .{
                    // The loop's bound is `recv.datagramCount()`, and
                    // `Recv.datagram` answers null only past that count.
                    // zwanzig-disable-next-line: optional-unwrap
                    .bytes = recv.datagram(position).?,
                    .from = got.from,
                    .local = self.socket.address,
                    .ecn = recv.ecn,
                }, self.scratch, at, self.random());
                moved = true;
                switch (ingress.outcome) {
                    // Nothing to do here: this connection is drained by the
                    // next `flush`, which finds it by index.
                    .processed => {},
                    // A stateless reply is a send, back out of the same socket
                    // to the address the datagram came from.
                    .reply => |reply| {
                        stats.out += 1;
                        _ = try sock.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// Drain every connection and write each datagram out, then run the timers.
    fn flush(self: *Wire, at: Instant, stats: *Counters) !bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                stats.out += 1;
                _ = try self.socket.send(t.io, egress.to, egress.send);
                moved = true;
            }
        }
        var scan: usize = 0;
        while (self.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) stats.finished += 1;
        }
        return moved;
    }

    /// One pass of the whole link: everything this side has, then everything
    /// its peer has.
    fn exchange(self: *Wire, at: Instant, stats: *Counters) !bool {
        const mine = try self.take(at, stats);
        return (try self.flush(at, stats)) or mine;
    }
};

/// What one side moved, for the stall report. Counters and nothing else: the
/// assertions are about membership, and these are what say what the
/// transport underneath was doing.
const Counters = struct {
    out: usize = 0,
    in: usize = 0,
    finished: usize = 0,
};

// ---------------------------------------------------------------------------
// The gossip mesh
// ---------------------------------------------------------------------------

/// One endpoint of the mesh: its transport, its `TopicState`, and the framing
/// bookkeeping that turns the state machine's sends into bytes.
const Node = struct {
    wire: Wire,
    topic: gossip.TopicState,
    /// What this node advertises as its own contact data, and the bytes the
    /// assertions compare a peer's copy against.
    advert: []u8,
    port_buf: [6]u8 = undefined,

    /// The `Conn` a dial returned, for the peers this node dialled.
    dialled: [max_nodes]?Conn,

    /// Encoded frames waiting for a stream on the link to this peer.
    outbound: [max_nodes]std.ArrayList(u8),
    /// Bytes read off that peer's stream and not yet framed out.
    inbound: [max_nodes]std.ArrayList(u8),
    timers: std.ArrayList(PendingTimer),

    /// The first payload this node was delivered, copied out of the frame it
    /// arrived in, so a second delivery of the same payload is visible.
    delivered_content: [plumtree.max_content]u8 = undefined,
    delivered_len: usize = 0,
    stats: Counters = .{},
    frames_written: usize = 0,
    frames_read: usize = 0,
    peer_data_seen: usize = 0,
    neighbor_up: usize = 0,
    neighbor_down: usize = 0,
    delivered: usize = 0,
    duplicated: usize = 0,

    fn init(
        self: *Node,
        index: usize,
        alpn: []const u8,
        rng: gossip.Rng,
        config: gossip.TopicConfig,
        seed: u64,
    ) !void {
        var identity: [SecretKey.seed_length]u8 = @splat(0x5e);
        identity[0] = @intCast(index);
        var secret = try SecretKey.fromSeed(identity);
        // `Wire.init` copies the key: it keeps this one in `self.secret`, and
        // `Bridge.create` and `Dialer.create` each derive their own seed bytes
        // from the `Config` they are handed. So this stack copy is the one no
        // owner shares, and `defer` rather than `errdefer` is its guard — an
        // errdefer wiped a copy nothing else pointed at, and left the key live
        // in this stack slot on every run that succeeded.
        defer secret.deinit();
        self.* = .{
            .wire = undefined,
            .topic = undefined,
            .advert = undefined,
            .dialled = [_]?Conn{null} ** max_nodes,
            .outbound = [_]std.ArrayList(u8){.empty} ** max_nodes,
            .inbound = [_]std.ArrayList(u8){.empty} ** max_nodes,
            .timers = .empty,
        };
        errdefer self.deinitBuffers();
        // `expect_peer` is null: this bridge accepts from every node with a
        // higher index, and one pin cannot name three peers. The pin that is
        // enforced is the dialer's, which is per-dial, and the identity
        // assertions read it off the handshake.
        try self.wire.init(nodeName(index), index, secret, null, alpn, seed);
        // The wire is up from here, and it owns everything `Wire.init`
        // allocated: a socket, a bridge, a dialer, an address map and four
        // buffers. Every step below unwinds through it, because the only other
        // unwind this function has is the buffer list — and a config the state
        // machine refuses is an error it can return with a whole wire live.
        errdefer self.wire.deinit();

        // A `u16` port is at most five digits and `port_buf` is six, so the only
        // way `bufPrint` refuses here is a format this file owns.
        self.advert = try std.fmt.bufPrint(&self.port_buf, "{d}", .{
            self.wire.socket.address.port,
        });
        const data = try gossip.PeerData.fromBytes(self.advert);
        self.topic = try gossip.TopicState.init(self.wire.id, data, config, rng);
    }

    fn deinitBuffers(self: *Node) void {
        for (&self.outbound) |*queue| queue.deinit(t.allocator);
        for (&self.inbound) |*queue| queue.deinit(t.allocator);
        self.timers.deinit(t.allocator);
    }

    fn deinit(self: *Node) void {
        self.deinitBuffers();
        self.wire.deinit();
        self.* = undefined;
    }

    /// This node is the client on every link to a higher index, which is what
    /// makes the two stream ids a function of role rather than of bookkeeping.
    fn clientOf(self: *const Node, peer: usize) bool {
        return self.wire.index < peer;
    }

    /// The stream this side writes, and the one it reads.
    ///
    /// RFC 9000 §2.1: a client-initiated bidirectional stream is `4n` and a
    /// server-initiated one is `4n + 1`. One stream per side makes those ids
    /// `0` and `1`, so both ends can name both without either being told.
    fn sendStream(self: *const Node, peer: usize) u64 {
        return if (self.clientOf(peer)) 0 else 1;
    }

    fn recvStream(self: *const Node, peer: usize) u64 {
        return if (self.clientOf(peer)) 1 else 0;
    }

    /// The connection to the node at `index`.
    ///
    /// Found by the peer address on the active path rather than held: an
    /// accepted connection has no other way in, and each peer holds a distinct
    /// ephemeral port, so the port *is* the peer's identity on this mesh.
    fn connTo(self: *Node, index: usize, ports: [max_nodes]u16) ?Conn {
        if (index == self.wire.index) return null;
        if (self.dialled[index]) |conn| return conn;
        var walk: usize = 0;
        while (self.wire.bridge.connectionAt(walk)) |conn| : (walk += 1) {
            const peer = conn.peer() orelse continue;
            if (peer.port == ports[index]) return conn;
        }
        return null;
    }

    fn up(self: *Node, index: usize, ports: [max_nodes]u16) bool {
        const conn = self.connTo(index, ports) orelse return false;
        return conn.established();
    }
};

fn nodeName(index: usize) []const u8 {
    return switch (index) {
        0 => "node-0",
        1 => "node-1",
        2 => "node-2",
        else => "node-3",
    };
}

/// A swarm of endpoints, each one dialling every peer with a higher index.
///
/// Six connections for four nodes, and every pair has exactly one connection
/// with the lower index as the client.
const Mesh = struct {
    nodes: [max_nodes]Node,
    ports: [max_nodes]u16,
    now: gossip.Nanos = start_ns,
    /// The codec's scratch, and the one decoded frame at a time.
    codec: []u8,
    frame: []u8,
    wire_out: []u8,
    /// Peers a `disconnect_peer` named, delivered at the end of the round that
    /// produced them.
    disconnects: [max_nodes]std.ArrayList(NodeId),
    teardowns: usize = 0,
    peer_data_mismatch: usize = 0,
    /// The first contact-data mismatch, copied out so the report can print it
    /// long after the frame it arrived in is gone. `null` until one happens.
    mismatch: ?Mismatch = null,

    /// One peer's contact data as this node received it, and as that peer
    /// advertised it.
    const Mismatch = struct {
        peer: usize,
        holder: usize,
        got: [gossip.peer_data_max]u8,
        got_len: usize,
        want: [gossip.peer_data_max]u8,
        want_len: usize,
    };

    fn noteMismatch(
        mesh: *Mesh,
        got: []const u8,
        want: []const u8,
        peer: usize,
        holder: usize,
    ) void {
        if (mesh.mismatch != null) return;
        var recorded: Mismatch = .{
            .peer = peer,
            .holder = holder,
            .got = [_]u8{0} ** gossip.peer_data_max,
            .got_len = @min(got.len, gossip.peer_data_max),
            .want = [_]u8{0} ** gossip.peer_data_max,
            .want_len = @min(want.len, gossip.peer_data_max),
        };
        @memcpy(recorded.got[0..recorded.got_len], got[0..recorded.got_len]);
        @memcpy(recorded.want[0..recorded.want_len], want[0..recorded.want_len]);
        mesh.mismatch = recorded;
    }

    fn init(mesh: *Mesh, seed: u64) !void {
        mesh.* = .{
            .nodes = undefined,
            .ports = [_]u16{0} ** max_nodes,
            .codec = undefined,
            .frame = undefined,
            .wire_out = undefined,
            .disconnects = [_]std.ArrayList(NodeId){.empty} ** max_nodes,
        };
        errdefer for (&mesh.disconnects) |*queue| queue.deinit(t.allocator);
        // Short intervals, so the `shuffle` and `pending_neighbor_request`
        // paths are on the wire inside the round bound rather than sitting on
        // a timer the run never reaches. Nothing else about the config moves:
        // the capacity is the upstream default and the walk lengths are the
        // paper's.
        const config: gossip.TopicConfig = .{
            .membership = .{
                .shuffle_interval = 12 * gossip.nanos_per_milli,
                .neighbor_request_timeout = 4 * gossip.nanos_per_milli,
            },
        };
        var rng = gossip.Rng.init(seed);
        var live: usize = 0;
        errdefer for (mesh.nodes[0..live]) |*node| node.deinit();
        for (0..max_nodes) |index| {
            // `live` after the `try`, not before it: a node whose `init`
            // refused has already unwound itself, and counting it here would
            // tear down a struct it never finished building.
            try mesh.nodes[index].init(index, gossip_alpn, rng.child(), config, seed + index);
            live = index + 1;
            mesh.ports[index] = mesh.nodes[index].wire.socket.address.port;
        }
        mesh.codec = try t.allocator.alloc(u8, codec_room);
        errdefer t.allocator.free(mesh.codec);
        mesh.frame = try t.allocator.alloc(u8, max_frame);
        errdefer t.allocator.free(mesh.frame);
        mesh.wire_out = try t.allocator.alloc(u8, codec_room);
    }

    fn deinit(mesh: *Mesh) void {
        for (&mesh.disconnects) |*queue| queue.deinit(t.allocator);
        for (&mesh.nodes) |*node| node.deinit();
        // Allocation order, then unwind order: `codec`, `frame`, `wire_out`.
        t.allocator.free(mesh.codec);
        t.allocator.free(mesh.frame);
        t.allocator.free(mesh.wire_out);
        mesh.* = undefined;
    }

    /// Dial every peer with a higher index, each with its own pin.
    fn dialAll(mesh: *Mesh) !void {
        for (0..max_nodes) |index| {
            const node = &mesh.nodes[index];
            for (index + 1..max_nodes) |peer| {
                const target = &mesh.nodes[peer];
                const dialed = (try node.wire.dialer.dial(
                    .{ .ip = target.wire.socket.address },
                    target.wire.id,
                    node.wire.socket.address,
                    &node.wire.map,
                    @intCast(mesh.now),
                    node.wire.random(),
                )).conn;
                node.dialled[peer] = dialed;
            }
        }
    }

    /// One round: the clock, the kernel on every socket, the protocol on every
    /// stream, and the timers that came due.
    fn round(mesh: *Mesh) !bool {
        mesh.now += time_quantum;
        const at: Instant = @intCast(mesh.now);
        var moved = false;
        for (&mesh.nodes) |*node| {
            if (try node.wire.exchange(at, &node.stats)) moved = true;
        }
        if (try mesh.protocol()) moved = true;
        if (try mesh.fireTimers()) moved = true;
        return moved;
    }

    /// Move gossip: frame what arrived on each stream, hand it to the state
    /// machine, and put what the state machine asked for on the wire.
    fn protocol(mesh: *Mesh) !bool {
        var moved = false;
        for (0..max_nodes) |index| {
            const node = &mesh.nodes[index];
            for (0..max_nodes) |peer| {
                if (peer == index) continue;
                if (try mesh.readStream(node, peer)) moved = true;
                if (try mesh.flushStream(node, peer)) moved = true;
            }
        }
        // The `peer_disconnected` events membership asked for. See the module
        // doc: the reference's message path ignores its link table, so keeping
        // the descriptor and delivering the event is the faithful port.
        for (0..max_nodes) |index| {
            for (mesh.disconnects[index].items) |peer| {
                moved = true;
                try mesh.feed(&mesh.nodes[index], .{
                    .peer_disconnected = peer,
                }, index);
            }
            mesh.disconnects[index].clearRetainingCapacity();
        }
        return moved;
    }

    /// Fire every timer that has come due, in the order it was asked for.
    fn fireTimers(mesh: *Mesh) !bool {
        var moved = false;
        for (0..max_nodes) |index| {
            const node = &mesh.nodes[index];
            var position: usize = 0;
            while (position < node.timers.items.len) {
                if (node.timers.items[position].due > mesh.now) {
                    position += 1;
                    continue;
                }
                const due = node.timers.orderedRemove(position);
                moved = true;
                mesh.feed(node, .{ .timer_expired = due.timer }, index) catch |err| {
                    std.debug.print(
                        "\n  {s} refused a timer it had asked for: {t}\n",
                        .{ node.wire.name, err },
                    );
                    return err;
                };
            }
        }
        return moved;
    }

    /// Copy whatever a peer wrote on its stream into this link's receive
    /// buffer. Nothing is decoded here: a stream delivers whatever chunks the
    /// packets held, and a frame boundary is not a packet boundary.
    fn readStream(mesh: *Mesh, node: *Node, peer: usize) !bool {
        const conn = node.connTo(peer, mesh.ports) orelse return false;
        if (!conn.established()) return false;
        const stream = conn.entry.conn.streams.getStream(node.recvStream(peer)) orelse
            return false;
        var moved = false;
        while (stream.recv.read()) |chunk| {
            // `read` hands the chunk over rather than lending it, and the
            // append below is its last reader. Armed ahead of the `try`, so
            // the backlog return and a refused append give it back too.
            defer t.allocator.free(chunk);
            moved = true;
            try node.inbound[peer].appendSlice(t.allocator, chunk);
            if (node.inbound[peer].items.len > max_backlog) {
                std.debug.print(
                    "\n  {s} holds {d} bytes from {s} it has not framed\n",
                    .{ node.wire.name, node.inbound[peer].items.len, mesh.nodes[peer].wire.name },
                );
                return error.ReceiveBacklog;
            }
        }
        return moved;
    }

    /// Frame out everything complete in the receive buffer and hand each frame
    /// to the state machine, then write this link's queued frames onto the
    /// stream.
    ///
    /// The two halves are separate calls on purpose: a decoded message borrows
    /// `mesh.frame`, so it is consumed by `feed` before the next frame is
    /// copied in, and every send the state machine produced has been encoded
    /// into a queue by then.
    fn flushStream(mesh: *Mesh, node: *Node, peer: usize) !bool {
        const moved = try mesh.drainFrames(node, peer);
        if (node.outbound[peer].items.len == 0) return moved;
        const conn = node.connTo(peer, mesh.ports) orelse return moved;
        if (!conn.established()) return moved;
        const id = node.sendStream(peer);
        if (conn.entry.conn.streams.getStream(id) == null) {
            _ = try conn.entry.conn.openStream();
        }
        const stream = conn.entry.conn.streams.getStream(id) orelse return error.NoStream;
        const payload = node.outbound[peer].items;
        try stream.send.writeData(payload);
        node.frames_written += countFrames(payload);
        node.outbound[peer].clearRetainingCapacity();
        return true;
    }

    /// Hand every complete frame in the link's receive buffer to this node.
    fn drainFrames(mesh: *Mesh, node: *Node, peer: usize) !bool {
        var moved = false;
        while (true) {
            const items = node.inbound[peer].items;
            if (items.len == 0) return moved;
            var reader = postcard.Reader.init(items);
            // A varint that has not finished arriving is the ordinary case of a
            // frame split across two packets, and it is not a refusal: the
            // bytes are still coming. The other two ways a `u64` varint fails
            // are not, and a peer can send one — swallowing those would park
            // the frame on the link until `max_backlog` fires rather than
            // saying what it was.
            const length = reader.readU64() catch |err| switch (err) {
                error.UnexpectedEnd => return moved,
                else => return err,
            };
            if (length > max_frame) {
                std.debug.print(
                    "\n  {s} was told a frame of {d} bytes from {s}\n",
                    .{ node.wire.name, length, mesh.nodes[peer].wire.name },
                );
                return error.FrameTooLong;
            }
            const whole = std.math.cast(usize, length) orelse return error.FrameTooLong;
            if (whole > reader.remaining()) return moved;
            const payload = reader.buffer[reader.offset..][0..whole];
            reader.offset += whole;
            const consumed = reader.offset;
            @memcpy(mesh.frame[0..whole], payload);
            moved = true;
            node.frames_read += 1;

            _ = try mesh.feed(node, .{
                .recv_message = .{
                    .from = mesh.nodes[peer].wire.id,
                    .message = try decodeMessage(mesh.frame[0..whole]),
                },
            }, node.wire.index);

            // Re-read the slice: `feed` may have reallocated another link's
            // queue, and this one only ever shrinks here.
            const rest = node.inbound[peer].items.len - consumed;
            @memmove(node.inbound[peer].items[0..rest], node.inbound[peer].items[consumed..]);
            node.inbound[peer].items.len = rest;
        }
    }

    /// Hand one event to a node's state machine and dispatch what it asks for.
    fn feed(mesh: *Mesh, node: *Node, event: gossip.InEvent, self_index: usize) !void {
        var out: gossip.Actions(gossip.OutEvent) = .init(t.allocator);
        defer out.deinit();
        try node.topic.handle(event, mesh.now, &out);
        try mesh.dispatch(node, out.slice(), self_index);
    }

    fn dispatch(
        mesh: *Mesh,
        node: *Node,
        events: []const gossip.OutEvent,
        self_index: usize,
    ) !void {
        for (events) |produced| switch (produced) {
            .send_message => |send| {
                const peer = mesh.indexOf(send.to) orelse continue;
                if (peer == self_index) continue;
                // Framed through one shared buffer and then copied into the
                // link's queue: the queue's spare capacity is zero on the
                // first send, and a frame that outlives its encode buffer
                // would be a frame pointing at the next message's bytes.
                const frame = try encodeFrame(send.message, mesh.codec, mesh.wire_out);
                try node.outbound[peer].appendSlice(t.allocator, frame);
            },
            .schedule_timer => |schedule| try node.timers.append(t.allocator, .{
                .due = mesh.now + schedule.after,
                .timer = schedule.timer,
            }),
            .disconnect_peer => |peer| {
                mesh.teardowns += 1;
                try mesh.disconnects[self_index].append(t.allocator, peer);
            },
            .emit_event => |reported| switch (reported) {
                .neighbor_up => node.neighbor_up += 1,
                .neighbor_down => node.neighbor_down += 1,
                .received => |got| noteDelivery(node, got.content),
            },
            .peer_data => |data| {
                node.peer_data_seen += 1;
                const peer = mesh.indexOf(data.peer) orelse continue;
                // Compared against what the peer advertised, not against what
                // this node already held: a codec that dropped or reordered
                // the contact data is a finding, and this is where it shows.
                if (std.mem.eql(u8, data.data, mesh.nodes[peer].advert)) continue;
                mesh.peer_data_mismatch += 1;
                mesh.noteMismatch(data.data, mesh.nodes[peer].advert, peer, self_index);
            },
        };
    }

    /// Record one delivery, and whether it is the second of the same payload.
    ///
    /// The content is copied out of the frame it arrived in, because the borrow
    /// dies with the frame and the duplicate check has to outlive it.
    fn noteDelivery(node: *Node, content: []const u8) void {
        if (node.delivered_len == 0) {
            const held = @min(content.len, node.delivered_content.len);
            @memcpy(node.delivered_content[0..held], content[0..held]);
            node.delivered_len = content.len;
            node.delivered = 1;
            return;
        }
        const held = @min(content.len, node.delivered_len);
        if (std.mem.eql(u8, content[0..held], node.delivered_content[0..held])) {
            node.duplicated += 1;
            return;
        }
        // A second, different payload: the deduplication table let it through,
        // which is the one thing it exists to prevent.
        node.duplicated += 1;
    }

    /// Which node this `NodeId` is, by the identity each one presents.
    fn indexOf(mesh: *const Mesh, id: NodeId) ?usize {
        for (0..max_nodes) |index| {
            if (mesh.nodes[index].wire.id.order(id) == .eq) return index;
        }
        return null;
    }

    // -- the properties the assertions are about -------------------------

    /// How many nodes have no neighbour at all. A converged swarm has none,
    /// and upstream's bootstrap asserts exactly this.
    fn peersWithoutNeighbors(mesh: *const Mesh) usize {
        var count: usize = 0;
        for (&mesh.nodes) |*node| {
            if (node.topic.swarm.activeView().len == 0) count += 1;
        }
        return count;
    }

    /// Links one end still believes in and the other end does not.
    ///
    /// A healthy converged swarm has none, and this is the number that says so
    /// more honestly than "no node is alone". It is not always zero, and
    /// `sim.Network.asymmetricLinks` says why: `on_neighbor` takes a `Neighbor`
    /// for a reply whenever the sender is in `pending_neighbor_requests`, and a
    /// reply is not answered, so an evicted peer can be put back silently.
    /// Upstream has the identical code path. What must hold — and what this is
    /// for — is that the count does not grow: a swarm that has stopped joining
    /// stops disagreeing.
    fn asymmetricLinks(mesh: *const Mesh) usize {
        var count: usize = 0;
        for (0..max_nodes) |index| {
            for (mesh.nodes[index].topic.swarm.activeView()) |peer| {
                const other = mesh.indexOf(peer) orelse continue;
                if (holdsNeighbor(mesh, other, mesh.nodes[index].wire.id)) continue;
                count += 1;
            }
        }
        return count;
    }

    /// Whether the node at `index` lists `id` in its active view.
    fn holdsNeighbor(mesh: *const Mesh, index: usize, id: NodeId) bool {
        for (mesh.nodes[index].topic.swarm.activeView()) |held| {
            if (held.order(id) == .eq) return true;
        }
        return false;
    }

    /// This node's neighbours as indices, for the report.
    fn neighbours(mesh: *const Mesh, index: usize, out: *[max_nodes]usize) usize {
        var count: usize = 0;
        for (mesh.nodes[index].topic.swarm.activeView()) |peer| {
            const other = mesh.indexOf(peer) orelse continue;
            out[count] = other;
            count += 1;
        }
        return count;
    }

    /// Print what a stall looks like from the inside.
    ///
    /// "Convergence failed" on four nodes that exchanged bytes is not a
    /// diagnosis. This is: the node that is alone, the three it *is* adjacent
    /// to, every connection's state, the frames each direction moved, and how
    /// many teardowns the protocol asked for on the way.
    fn report(mesh: *Mesh, reason: []const u8) void {
        std.debug.print("\ngossip wire stalled: {s}\n", .{reason});
        for (0..max_nodes) |index| {
            const node = &mesh.nodes[index];
            var found: [max_nodes]usize = undefined;
            const count = neighbours(mesh, index, &found);
            std.debug.print(
                "  {s} ({f}) at {f}: {d} datagrams out, {d} in, {d} finished\n",
                .{
                    node.wire.name,
                    node.wire.id,
                    node.wire.socket.address,
                    node.stats.out,
                    node.stats.in,
                    node.stats.finished,
                },
            );
            std.debug.print(
                "    frames {d} written, {d} read; active view {d}/{d}, passive {d}\n",
                .{
                    node.frames_written,
                    node.frames_read,
                    node.topic.swarm.activeView().len,
                    node.topic.swarm.config.active_view_capacity,
                    node.topic.swarm.passiveView().len,
                },
            );
            std.debug.print(
                "    neighbor up {d}, down {d}; contact data {d}; delivered {d}, duplicate {d}\n",
                .{
                    node.neighbor_up,
                    node.neighbor_down,
                    node.peer_data_seen,
                    node.delivered,
                    node.duplicated,
                },
            );
            std.debug.print("    adjacent to:", .{});
            for (found[0..count]) |peer| {
                std.debug.print(" {s}", .{mesh.nodes[peer].wire.name});
            }
            if (count == 0) std.debug.print(" nobody — this node is the one left out", .{});
            std.debug.print("\n", .{});
            for (0..max_nodes) |peer| {
                const conn = node.connTo(peer, mesh.ports) orelse continue;
                std.debug.print(
                    "    conn to {s}: id {d}, state {t}, established {}\n",
                    .{
                        mesh.nodes[peer].wire.name,
                        conn.id(),
                        conn.entry.conn.state,
                        conn.established(),
                    },
                );
            }
            for (0..max_nodes) |peer| {
                if (peer == index) continue;
                std.debug.print(
                    "    link to {s}: {d} bytes waiting out, {d} bytes waiting in\n",
                    .{
                        mesh.nodes[peer].wire.name,
                        node.outbound[peer].items.len,
                        node.inbound[peer].items.len,
                    },
                );
            }
        }
        std.debug.print(
            "  asymmetric links {d}; teardowns asked for {d}; contact-data mismatches {d}; " ++
                "virtual time {d} ms; round bound {d}\n",
            .{
                mesh.asymmetricLinks(),
                mesh.teardowns,
                mesh.peer_data_mismatch,
                mesh.now / gossip.nanos_per_milli,
                max_rounds,
            },
        );
        if (mesh.mismatch) |found| {
            var got_hex: [2 * gossip.peer_data_max]u8 = undefined;
            var want_hex: [2 * gossip.peer_data_max]u8 = undefined;
            std.debug.print(
                "  first contact-data mismatch: {s} holds {s} as '{s}', " ++
                    "and {s} advertised '{s}'\n",
                .{
                    mesh.nodes[found.holder].wire.name,
                    mesh.nodes[found.peer].wire.name,
                    writeHex(&got_hex, found.got[0..found.got_len]),
                    mesh.nodes[found.peer].wire.name,
                    writeHex(&want_hex, found.want[0..found.want_len]),
                },
            );
        }
    }
};

/// How many frames a run of encoded bytes holds, for the report only. It stops
/// at the first thing it cannot read rather than refusing: it is a counter in
/// a diagnostic, not a decoder.
fn countFrames(bytes: []const u8) usize {
    var reader = postcard.Reader.init(bytes);
    var count: usize = 0;
    while (reader.remaining() > 0) {
        const length = reader.readU64() catch break;
        if (length > reader.remaining()) break;
        reader.offset += @intCast(length);
        count += 1;
    }
    return count;
}

/// `bytes` as lower-case hex written into `out`, and the digits it wrote.
///
/// `std.fmt.bytesToHex` takes its width from the type, and this printout's
/// width is a run's answer — how many contact bytes crossed the socket — so
/// it needs the form the format string can bound. `out` must be twice
/// `bytes.len`.
fn writeHex(out: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, at| {
        out[2 * at] = digits[byte >> 4];
        out[2 * at + 1] = digits[byte & 15];
    }
    return out[0 .. 2 * bytes.len];
}

test "a swarm of ozai endpoints converges on one membership over real sockets" {
    var mesh: Mesh = undefined;
    try mesh.init(0x5eed);
    defer mesh.deinit();
    try mesh.dialAll();

    // Every peer answered with a distinct ephemeral port, so the six links
    // cannot have collapsed into fewer.
    var ports = mesh.ports;
    std.mem.sort(u16, &ports, {}, std.sort.asc(u16));
    for (ports) |port| try t.expect(port != 0);
    for (ports[1..], 1..) |port, position| {
        try t.expect(port != ports[position - 1]);
    }

    // Node 0 is the contact node and starts ready to be asked; the other three
    // each ask it for an introduction. This is the shape `BootstrapMode.single`
    // brings up in the simulator, and the shape that makes the convergence
    // below non-trivial: nobody is adjacent to anybody at the start.
    for (1..max_nodes) |index| {
        var bootstrap: [gossip.max_bootstrap]NodeId = undefined;
        bootstrap[0] = mesh.nodes[0].wire.id;
        try mesh.feed(&mesh.nodes[index], .{
            .command = .{ .join = try gossip.Peers.init(bootstrap[0..1]) },
        }, index);
    }
    try mesh.feed(&mesh.nodes[0], .{
        .command = .{ .join = try gossip.Peers.init(&.{}) },
    }, 0);

    // The handshakes have to finish before any of this means anything, and one
    // that does not is a transport finding rather than a gossip one.
    try driveTo(&mesh, "every gossip link completed its handshake", allUp);

    // And then the membership has to settle. The bound is rounds; nothing here
    // sleeps and the clock moves only because a round moved it.
    try driveTo(&mesh, "the swarm never reached a membership", settled);

    // The disagreement is measured once the swarm has settled, and again at the
    // end: what has to hold is that it does not grow.
    const early = mesh.asymmetricLinks();

    // ── the transport, which the protocol runs on ──
    //
    // Six links, all established, and every one of them proved the peer it
    // reached. The pin is the dialer's, because `Bridge.Config.expect_peer` is
    // one node id and this mesh has three peers per bridge; the handshake's
    // `peerNodeId` is where the pin a dial carried comes back out.
    for (0..max_nodes) |index| {
        for (index + 1..max_nodes) |peer| {
            const dialed = mesh.nodes[index].dialled[peer] orelse return error.NoConnection;
            try t.expect(dialed.established());
            const carried = dialed.entry.conn.tls13_hs orelse return error.NoHandshakeState;
            try t.expectEqual(
                mesh.nodes[peer].wire.id.toBytes(),
                carried.peerNodeId().?,
            );
            try t.expectEqual(
                mesh.nodes[peer].wire.id.toBytes(),
                carried.config.expect_peer_node_id.?,
            );
            // The accept side read the dialler's certificate off the wire and
            // compared it against an SPKI built here from the DER encoding,
            // rather than against the configuration that produced it.
            const accepted = mesh.nodes[peer].connTo(index, mesh.ports) orelse
                return error.NoConnection;
            try t.expectEqualSlices(
                u8,
                &spkiOf(mesh.nodes[index].wire.id),
                accepted.entry.conn.peerCertificate().?,
            );
            try t.expectEqualStrings(gossip_alpn, dialed.entry.conn.negotiatedAlpn());
        }
    }

    // ── nobody is left out ──
    //
    // The property is membership and not message delivery: no frame count is
    // asserted anywhere above. `frames_read` is printed by `report` and never
    // checked.
    for (0..max_nodes) |index| {
        const node = &mesh.nodes[index];
        var found: [max_nodes]usize = undefined;
        const count = mesh.neighbours(index, &found);
        if (count == 0) {
            mesh.report("a node ended the run with no neighbour at all");
            std.debug.print("  {s} is the node left out\n", .{node.wire.name});
            return error.LeftOut;
        }
        // Every count is inside the capacity the config asked for: a view that
        // grew past it would mean the state machine ignored its own bound.
        try t.expect(count <= node.topic.swarm.config.active_view_capacity);
        try t.expect(count <= node.topic.swarm.passiveView().len + count);
        // And each node knows at least one peer by contact data that crossed
        // the socket: the peer view and the contact table cannot disagree
        // about who this node is talking to.
        try t.expect(node.peer_data_seen >= count);
    }
    try t.expectEqual(@as(usize, 0), mesh.peersWithoutNeighbors());

    // Every node's copy of every peer's contact data matched what the peer
    // advertised. A mismatch is a codec that lost or reordered bytes, and it is
    // counted rather than tolerated.
    if (mesh.peer_data_mismatch != 0) {
        mesh.report("contact data crossed the socket and did not match");
        return error.ContactDataMismatch;
    }

    // ── one broadcast, over the same sockets ──
    //
    // Membership that agrees is the plan's bar for gossip. A broadcast is what
    // the membership is *for*, and it is the second protocol layer's turn: a
    // `plumtree.Message` crosses the same framed streams, so this is what
    // proves the codec's other arm is live rather than merely present.
    const before = blk: {
        var extent: [max_nodes]usize = undefined;
        for (0..max_nodes) |index| {
            var found: [max_nodes]usize = undefined;
            extent[index] = mesh.neighbours(index, &found);
        }
        break :blk extent;
    };
    for (&mesh.nodes) |*node| {
        node.delivered = 0;
        node.duplicated = 0;
        node.delivered_len = 0;
    }

    try mesh.feed(&mesh.nodes[0], .{
        .command = .{ .broadcast = .{
            .content = "ozai, over a socket, on a real descriptor",
            .scope = .swarm,
        } },
    }, 0);

    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        var complete = true;
        for (1..max_nodes) |index| {
            if (mesh.nodes[index].delivered == 0) complete = false;
        }
        if (complete) break;
        _ = try mesh.round();
    }

    for (1..max_nodes) |index| {
        if (mesh.nodes[index].delivered == 0) {
            mesh.report("a broadcast never reached a node");
            std.debug.print(
                "  {s} received nothing broadcast by {s}\n",
                .{ mesh.nodes[index].wire.name, mesh.nodes[0].wire.name },
            );
            return error.BroadcastStalled;
        }
        // Delivered once. `duplicated` counts a second arrival of the same
        // payload, which the payload cache's id table exists to prevent, and a
        // different payload arriving at all — the only other thing that can
        // land here — is counted as the same kind of failure.
        try t.expectEqual(@as(usize, 0), mesh.nodes[index].duplicated);
    }
    // The origin delivered to nobody: a broadcast is not an echo.
    try t.expectEqual(@as(usize, 0), mesh.nodes[0].delivered);

    // And the broadcast left the membership it was built on untouched.
    for (0..max_nodes) |index| {
        var found: [max_nodes]usize = undefined;
        try t.expectEqual(before[index], mesh.neighbours(index, &found));
    }

    // ── the disagreement did not grow ──
    //
    // Settled, broadcast, and still the same count. Upstream's position is
    // written down in `sim.Network.asymmetricLinks`: `check_synchronicity` is
    // a helper and not a property it claims, and its own convergence test
    // asserts only that the count stops growing.
    try driveTo(&mesh, "membership did not settle after the broadcast", stable);
    try t.expectEqual(early, mesh.asymmetricLinks());
    try t.expectEqual(@as(usize, 0), mesh.peersWithoutNeighbors());
}

/// Every node holds every other, and holds no link the other end denies.
///
/// The full mesh is what four nodes and a capacity of five converge to — the
/// note on `node_count` says so — and it is a stronger bar than "nobody is
/// alone", which a half-built swarm passes. A membership that is merely
/// non-empty is still growing, and the broadcast below is built on one
/// membership and compared against it afterwards, so capturing a moving one
/// compares it against itself a few rounds later. Nothing can be added past
/// the full mesh either: three peers under a capacity of five is all there is.
fn settled(mesh: *Mesh) bool {
    if (mesh.asymmetricLinks() != 0) return false;
    for (&mesh.nodes) |*node| {
        if (node.topic.swarm.activeView().len < node_count - 1) return false;
    }
    return true;
}

/// The same, one round later: membership has stopped changing.
fn stable(mesh: *Mesh) bool {
    return settled(mesh);
}

/// Every link on every node has a completed handshake.
fn allUp(mesh: *Mesh) bool {
    for (0..max_nodes) |index| {
        for (0..max_nodes) |peer| {
            if (peer == index) continue;
            if (!mesh.nodes[index].up(peer, mesh.ports)) return false;
        }
    }
    return true;
}

/// Run rounds until `goal` holds, or until the bound is reached.
fn driveTo(mesh: *Mesh, phase: []const u8, goal: fn (*Mesh) bool) !void {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        if (goal(mesh)) return;
        _ = try mesh.round();
    }
    if (goal(mesh)) return;
    mesh.report(phase);
    return error.Stalled;
}

// A wire outlives the step that hands the key over, so the step after that one
// is what has to unwind it.
//
// `Config.validate` refuses `shuffle_active_view_count == 0`, and
// `TopicState.init` calls it *after* `Wire.init` has built a socket, a bridge,
// a dialer, an address map and four buffers. Nothing here calls `Node.deinit` —
// `init` refused, so there is no node to tear down — which is the whole point:
// whatever that error path failed to release is what `std.testing.allocator`
// reports when this test ends.
test "a node that refuses its topic config releases the wire it had built" {
    var node: Node = undefined;
    const refused: gossip.TopicConfig = .{
        .membership = .{ .shuffle_active_view_count = 0 },
    };
    try t.expectError(
        error.ShuffleNodeListTooLong,
        node.init(0, gossip_alpn, gossip.Rng.init(1), refused, 7),
    );
}

// ---------------------------------------------------------------------------
// Blobs over a socket
// ---------------------------------------------------------------------------

/// The two endpoints a blobs exchange needs, and the bookkeeping a stall wants.
const BlobLink = struct {
    getter: Wire,
    provider: Wire,
    now: gossip.Nanos = start_ns,
    /// What the provider read off each stream, and whether each saw its FIN.
    provider_bytes: std.AutoHashMap(u64, std.ArrayList(u8)),
    provider_fin: std.AutoHashMap(u64, bool),
    getter_bytes: std.AutoHashMap(u64, std.ArrayList(u8)),
    getter_fin: std.AutoHashMap(u64, bool),
    /// What `scratch` and `body` were taken from. A field rather than the
    /// global `t.allocator` so a test can hand `init` an allocator that
    /// refuses: the steps *after* a wire is up are the ones whose unwind is
    /// worth proving, and without a refusal they are never taken.
    alloc: std.mem.Allocator,
    scratch: []u8,
    body: []u8,
    sent: [2]usize = .{ 0, 0 },
    received: [2]usize = .{ 0, 0 },
    /// The connection the getter's dial opened. Held so the assertions can read
    /// the identity the pin produced off the handshake.
    dialled: Conn,

    fn init(link: *BlobLink, alloc: std.mem.Allocator) !void {
        link.* = .{
            .getter = undefined,
            .provider = undefined,
            .dialled = undefined,
            .provider_bytes = .init(t.allocator),
            .provider_fin = .init(t.allocator),
            .getter_bytes = .init(t.allocator),
            .getter_fin = .init(t.allocator),
            .scratch = undefined,
            .body = undefined,
            .alloc = alloc,
        };
        errdefer link.deinitBuffers();
        // Both ends pin the other, because a pair has one peer and
        // `Bridge.Config.expect_peer` is a value rather than a list.
        const getter_seed: [SecretKey.seed_length]u8 = @splat(0xb1);
        const provider_seed: [SecretKey.seed_length]u8 = @splat(0xb2);
        var getter_secret = try SecretKey.fromSeed(getter_seed);
        var provider_secret = try SecretKey.fromSeed(provider_seed);
        // Both wires *copy* their key: `Wire.init` keeps it in `self.secret`,
        // and the bridge and the dialer each derive their own seed bytes from
        // the `Config` they are handed. These two stack copies are therefore
        // the ones no owner shares, which makes `defer` — not `errdefer` — their
        // guard. The errdefer this replaced wiped a copy nothing else pointed
        // at, and left both keys live on every path that succeeded.
        defer getter_secret.deinit();
        defer provider_secret.deinit();
        try link.getter.init("getter", 0, getter_secret, null, blobs.alpn, 21);
        // From here each wire owns a socket, a bridge, a dialer, an address map
        // and four buffers, so every step below unwinds through the wires that
        // are already up.
        errdefer link.getter.deinit();
        try link.provider.init(
            "provider",
            1,
            provider_secret,
            getter_secret.nodeId(),
            blobs.alpn,
            22,
        );
        errdefer link.provider.deinit();
        link.scratch = try alloc.alloc(u8, codec_room);
        errdefer alloc.free(link.scratch);
        link.body = try alloc.alloc(u8, codec_room);
        errdefer alloc.free(link.body);
        // One dial, pinned to the provider's node id, so the handshake proves
        // who was dialled rather than merely that somebody answered. The id is
        // named before the dial because the dial writes into `link` and both
        // keys are wiped when this function returns: a value read off a wiped
        // key is a value that has to have been read before, not after.
        const provider_id = provider_secret.nodeId();
        link.dialled = (try link.getter.dialer.dial(
            .{ .ip = link.provider.socket.address },
            provider_id,
            link.getter.socket.address,
            &link.getter.map,
            @intCast(link.now),
            link.getter.random(),
        )).conn;
    }

    fn deinitBuffers(link: *BlobLink) void {
        link.freeSides(&link.provider_bytes);
        link.freeSides(&link.getter_bytes);
        link.provider_fin.deinit();
        link.provider_bytes.deinit();
        link.getter_fin.deinit();
        link.getter_bytes.deinit();
    }

    fn freeSides(_: *BlobLink, map: *std.AutoHashMap(u64, std.ArrayList(u8))) void {
        var it = map.valueIterator();
        while (it.next()) |buffer| buffer.deinit(t.allocator);
    }

    fn deinit(link: *BlobLink) void {
        link.deinitBuffers();
        link.alloc.free(link.body);
        link.alloc.free(link.scratch);
        link.provider.deinit();
        link.getter.deinit();
        link.* = undefined;
    }

    fn round(link: *BlobLink) !bool {
        link.now += time_quantum;
        const at: Instant = @intCast(link.now);
        var getter_stats: Counters = .{};
        var provider_stats: Counters = .{};
        var moved = try link.getter.exchange(at, &getter_stats);
        moved = (try link.provider.exchange(at, &provider_stats)) or moved;
        link.sent[0] += getter_stats.out;
        link.received[0] += getter_stats.in;
        link.sent[1] += provider_stats.out;
        link.received[1] += provider_stats.in;
        moved = (try link.drain(&link.getter, &link.getter_bytes, &link.getter_fin)) or moved;
        moved = (try link.drain(&link.provider, &link.provider_bytes, &link.provider_fin)) or moved;
        return moved;
    }

    /// Copy every stream's readable bytes into a buffer per stream, and note
    /// which streams have seen their FIN.
    ///
    /// `allReceived` rather than `fin_received` alone: a FIN behind a hole is
    /// not the end of the stream, and treating it as one is how a `get` decodes
    /// a truncated request instead of waiting for the rest of it.
    fn drain(
        _: *BlobLink,
        side: *Wire,
        bytes: *std.AutoHashMap(u64, std.ArrayList(u8)),
        fin: *std.AutoHashMap(u64, bool),
    ) !bool {
        const conn = side.bridge.connectionAt(0) orelse return false;
        if (!conn.established()) return false;
        var moved = false;
        var it = conn.entry.conn.streams.streams.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;
            const gop = try bytes.getOrPut(id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            while (stream.recv.read()) |chunk| {
                // The same handover as `Mesh.readStream`: the append is what
                // copies, and the chunk is the caller's from the `try` on.
                defer t.allocator.free(chunk);
                moved = true;
                try gop.value_ptr.appendSlice(t.allocator, chunk);
            }
            if (stream.recv.allReceived()) try fin.put(id, true);
        }
        return moved;
    }

    fn finished(
        link: *BlobLink,
        fin: *const std.AutoHashMap(u64, bool),
        id: u64,
    ) bool {
        _ = link;
        return fin.get(id) orelse false;
    }

    /// Encode a request the way the getter writes it: one `postcard.Writer`
    /// into `scratch`, with `body` as the length-prefixed arm's scratch.
    fn writeRequest(link: *BlobLink, request: blobs.Request) ![]const u8 {
        var writer = postcard.Writer.init(link.scratch);
        try request.write(&writer, link.body);
        return writer.finish();
    }

    fn report(link: *BlobLink, reason: []const u8) void {
        std.debug.print("\nblobs wire stalled: {s}\n", .{reason});
        for (0..2) |which| {
            const side: *Wire = if (which == 0) &link.getter else &link.provider;
            std.debug.print(
                "  {s} ({f}) at {f}: {d} datagrams out, {d} in\n",
                .{
                    side.name,
                    side.id,
                    side.socket.address,
                    link.sent[which],
                    link.received[which],
                },
            );
            var index: usize = 0;
            while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
                std.debug.print(
                    "    conn {d}: state {t}, established {}\n",
                    .{ conn.id(), conn.entry.conn.state, conn.established() },
                );
                var it = conn.entry.conn.streams.streams.iterator();
                while (it.next()) |entry| {
                    const id = entry.key_ptr.*;
                    const held = if (which == 0)
                        link.getter_bytes.get(id)
                    else
                        link.provider_bytes.get(id);
                    const seen = if (which == 0)
                        link.getter_fin.get(id)
                    else
                        link.provider_fin.get(id);
                    std.debug.print(
                        "    stream {d}: {d} bytes, fin {}\n",
                        .{ id, if (held) |buffer| buffer.items.len else 0, seen orelse false },
                    );
                }
            }
        }
        std.debug.print("  virtual time {d} ms; round bound {d}\n", .{
            link.now / gossip.nanos_per_milli,
            max_rounds,
        });
    }
};

/// Scratch a blobs decode borrows into.
///
/// The counts are this file's own bounds, not the protocol's: a request longer
/// than any of them is a frame this artifact cannot hold, and
/// `RangeSpecSeq.parse` reports that as `error.BufferFull` rather than
/// pretending it read the request.
const decode_slots = 64;

const DecodeStorage = struct {
    /// The four buffers a blobs decode fills, and the `Storage` that borrows
    /// them. The arrays are fields rather than constants because a decode
    /// writes through them, and `Storage`'s slices have to point at the same
    /// memory — so `init` points them at `self` rather than returning one.
    items: [decode_slots]range_spec.Item = @splat(.{ .delta = 0, .spec = .empty }),
    widths: [decode_slots]u64 = @splat(0),
    hashes: [decode_slots][32]u8 = @splat(@splat(0)),
    boundaries: [decode_slots]u64 = @splat(0),
    inner: blobs.Storage = undefined,

    /// Point `inner` at this struct's own arrays, in place.
    ///
    /// `fn init() DecodeStorage` was the shape before, and it took the address
    /// of a returned value: the slices `Storage` carries were cut from the
    /// local `self` inside `init`, so every decode through them read a frame
    /// that had already unwound. A debug build still found the bytes there and
    /// a release build had reused the slot, which is the same failure the
    /// gossip module's own contact data had; see the module doc.
    fn init(self: *DecodeStorage) void {
        self.inner = .{
            .items = self.items[0..],
            .widths = self.widths[0..],
            .hashes = self.hashes[0..],
            .boundaries = self.boundaries[0..],
        };
    }
};

test "a blob the provider does not have is EOF on the wire, not an error frame" {
    var link: BlobLink = undefined;
    try link.init(t.allocator);
    defer link.deinit();

    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        const accepted = link.provider.bridge.connectionAt(0);
        if (link.dialled.established() and
            accepted != null and accepted.?.established()) break;
        _ = try link.round();
    }
    const getter_conn = link.dialled;
    const provider_conn = link.provider.bridge.connectionAt(0) orelse {
        link.report("the provider never saw a connection");
        return error.NoConnection;
    };
    if (!getter_conn.established() or !provider_conn.established()) {
        link.report("the blobs handshake did not finish");
        return error.Stalled;
    }
    // The pin both ends carried, proved by the handshake rather than by the
    // configuration: the getter's pin names the provider, and the provider's
    // `client_auth` pin names the getter.
    try t.expectEqual(
        link.provider.id.toBytes(),
        getter_conn.entry.conn.tls13_hs.?.peerNodeId().?,
    );
    try t.expectEqual(
        link.getter.id.toBytes(),
        provider_conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(blobs.alpn, getter_conn.entry.conn.negotiatedAlpn());

    // The getter asks for two hashes the provider has never heard of, on two
    // streams. Two rather than one because "EOF" and "some bytes" have to be
    // told apart, and one stream can only show one of them.
    const wanted = [_][32]u8{ @splat(0x5a), @splat(0x5b) };
    var requests: [2]u64 = undefined;
    for (wanted, 0..) |hash, position| {
        const frame = try link.writeRequest(.{
            .to_eof = .{ .get = blobs.GetRequest.blob(hash) },
        });
        const stream = try getter_conn.entry.conn.openStream();
        try stream.send.writeData(frame);
        // The `to_eof` framing is the whole stream: a `get` is closed by a FIN
        // and not by a length, which is what `EofFraming` documents.
        stream.send.close();
        requests[position] = stream.stream_id;
    }

    // The provider reads each request to the end of its stream and decodes it
    // with the one reader `Request.read` dispatches to.
    var answered: [2]bool = .{ false, false };
    var decoded: [2]blobs.Request = undefined;
    // One storage per request, and both outlive the loop that fills them. A
    // decoded `GetRequest` borrows its range sequence out of the `Storage` it
    // was read into, and `RangeSpecSeq.parse` writes into `items[0..count]` —
    // so one slot reused per iteration leaves request 0 pointing at request
    // 1's ranges, and a slot scoped to the iteration leaves both pointing at a
    // frame that ended with it. Debug hands back the bytes that frame happened
    // to keep; a release build has already reused the slot, and the assertion
    // below then reads a range the wire never carried. See the module doc: a
    // decoded message is borrowed out of the frame it was decoded from, and
    // here the frame has to be the one that outlives the comparison.
    var storages = [_]DecodeStorage{.{}} ** requests.len;
    for (&storages) |*storage| storage.init();
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.round();
        var position: usize = 0;
        while (position < requests.len) : (position += 1) {
            if (answered[position]) continue;
            if (!link.finished(&link.provider_fin, requests[position])) continue;
            const queued = link.provider_bytes.get(requests[position]) orelse
                return error.NoStream;
            var reader = postcard.Reader.init(queued.items);
            decoded[position] = try blobs.Request.read(&reader, &storages[position].inner);
            // The reader has to end at the end of it: a byte after a `get` is a
            // stream that carried something else, and `finish` is what makes
            // that different from a request read two ways.
            try reader.finish();
            answered[position] = true;

            const stream = provider_conn.entry.conn.streams.getStream(requests[position]) orelse
                return error.NoStream;
            // The first request is answered with bytes, the second has no
            // answer at all. `Closed.request_received` is upstream's own reason
            // for stopping: one request per stream.
            if (position == 0) try stream.send.writeData(answer_bytes);
            stream.send.close();
        }
        if (answered[0] and answered[1]) break;
    }
    if (!answered[0] or !answered[1]) {
        link.report("a blobs request never arrived whole");
        return error.RequestStalled;
    }

    // The requests survived the socket: the hash the getter wrote is the hash
    // the provider read, on both streams, byte for byte.
    for (decoded, 0..) |request, position| {
        try t.expect(request.discriminant() == .get);
        // The ranges the provider read live in the storage it read them into.
        // That is a claim about an address, so it is checked as one: a decode
        // through a `Storage` that was copied out of its own struct reads
        // whatever is in that dead frame now, and a debug build is the only
        // reason that can look like it worked.
        try t.expectEqual(
            @intFromPtr(&storages[position].items[0]),
            @intFromPtr(request.to_eof.get.ranges.items.ptr),
        );
        const want = try link.writeRequest(.{
            .to_eof = .{ .get = blobs.GetRequest.blob(wanted[position]) },
        });
        // `want` and `got` are both slices of one scratch buffer, and the
        // second `writeRequest` overwrites the first before the comparison
        // reads it: two encodings of the same length compared the buffer
        // against itself and checked nothing but the length. One side is
        // copied out first, so the comparison has two.
        var held: [max_frame]u8 = undefined;
        @memcpy(held[0..want.len], want);
        const got = try link.writeRequest(request);
        try t.expectEqualSlices(u8, held[0..want.len], got);
    }

    // The getter reads both answers to their ends.
    var fin: [2]bool = .{ false, false };
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.round();
        for (requests, 0..) |id, position| {
            fin[position] = link.finished(&link.getter_fin, id);
        }
        if (fin[0] and fin[1]) break;
    }
    if (!fin[0] or !fin[1]) {
        link.report("a blobs answer never reached the end of its stream");
        return error.AnswerStalled;
    }

    // ── missing data is EOF ──
    //
    // The stream the provider had nothing for arrived as zero bytes with its
    // FIN set and no reset — and a reset is what an error would have cost this
    // layer, because `protocol.zig` has no error frame and says so in its own
    // doc: a provider that does not have the data stops writing.
    const missing_stream = getter_conn.entry.conn.streams.getStream(requests[1]) orelse
        return error.NoStream;
    const missing_bytes = link.getter_bytes.get(requests[1]) orelse
        return error.NoStream;
    var missing_reader = postcard.Reader.init(missing_bytes.items);
    const missing = blobs.BaoResponse.read(&missing_reader);
    try t.expect(missing.isEof());
    try t.expectEqual(@as(usize, 0), missing.bytes.len);
    try t.expect(missing_stream.recv.fin_received);
    try t.expectEqual(@as(?u64, null), missing_stream.recv.reset_err);

    // And the getter's read path is not vacuously empty: the stream that was
    // answered carried bytes, and they are the ones the provider wrote.
    const present_bytes = link.getter_bytes.get(requests[0]) orelse
        return error.NoStream;
    var present_reader = postcard.Reader.init(present_bytes.items);
    const present = blobs.BaoResponse.read(&present_reader);
    try t.expect(!present.isEof());
    try t.expectEqualSlices(u8, answer_bytes, present.bytes);

    // The `to_eof` rule, checked on bytes that came off a socket: one byte
    // after the request and it is not a request any more. This is what makes
    // "read to EOF" mean what it says, and it is the difference between a
    // missing answer and a truncated request.
    const first = try link.writeRequest(.{
        .to_eof = .{ .get = blobs.GetRequest.blob(wanted[0]) },
    });
    var trailing: [codec_room]u8 = undefined;
    @memcpy(trailing[0..first.len], first);
    trailing[first.len] = 0;
    var trailing_reader = postcard.Reader.init(trailing[0 .. first.len + 1]);
    var storage: DecodeStorage = .{};
    storage.init();
    try t.expectError(
        error.TrailingBytes,
        blobs.Request.read(&trailing_reader, &storage.inner),
    );
    // Without that byte the same reader returns the request, so the byte is
    // what made the difference rather than the buffer being wrong.
    var clean_reader = postcard.Reader.init(first);
    var clean_storage: DecodeStorage = .{};
    clean_storage.init();
    const clean = try blobs.Request.read(&clean_reader, &clean_storage.inner);
    try t.expectEqual(blobs.RequestType.get, clean.discriminant());
}

/// What the provider writes for the request it can answer.
///
/// Opaque bytes, and the doc says so: this project has no bao encoder, so what
/// is under test is the framing and not the content hash. A real provider
/// writes bao data here and the getter's decode is a bao problem, not a
/// transport one.
const answer_bytes = "bao data, opaque to this layer";

/// The DER `SubjectPublicKeyInfo` an ed25519 key is presented as: a fixed
/// twelve-byte header and then the 32 bytes of public key.
///
/// The header is the encoding itself — a 42-byte SEQUENCE, a 5-byte
/// `AlgorithmIdentifier` naming OID 1.3.101.112, and a BIT STRING of 33 bytes
/// with no unused bits — written out here rather than read off the peer's own
/// certificate. A test that compares a value against the thing that produced it
/// proves nothing: this is the same 44 bytes `tls13.ed25519Spki` builds, built
/// a second time so the comparison has two sides.
fn spkiOf(node: NodeId) [bridge_mod.spki_length]u8 {
    const header = [_]u8{
        0x30, 0x2a, // SEQUENCE, 42 bytes
        0x30, 0x05, //   SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, //   OID 1.3.101.112, id-Ed25519
        0x03, 0x21, 0x00, //   BIT STRING, 33 bytes, no padding
    };
    var out: [bridge_mod.spki_length]u8 = undefined;
    @memcpy(out[0..header.len], &header);
    @memcpy(out[header.len..], &node.toBytes());
    return out;
}

// The same claim on the blobs pair, and the reason `BlobLink` carries its own
// allocator: a refused buffer is the only way to reach the steps *after* both
// wires are up, and every one of them unwinds through the two wires.
test "the blobs link releases both wires when its first buffer is refused" {
    var failing: t.FailingAllocator = .init(t.allocator, .{ .fail_index = 0 });
    var link: BlobLink = undefined;
    try t.expectError(error.OutOfMemory, link.init(failing.allocator()));
}

// One step further in, so the unwind has a buffer of its own to give back
// before it reaches the wires.
test "the blobs link releases both wires when its second buffer is refused" {
    var failing: t.FailingAllocator = .init(t.allocator, .{ .fail_index = 1 });
    var link: BlobLink = undefined;
    try t.expectError(error.OutOfMemory, link.init(failing.allocator()));
}
