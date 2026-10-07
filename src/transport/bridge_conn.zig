//! One connection's application-facing surface: the borrowed handle, the stream
//! on it, and the socket writes `Conn.drain` hands back.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over it
//! and five other named modules. The boundary is the altitude: this is the only
//! part of the bridge that runs *above* a datagram, where `bridge_manager`
//! moves them and `bridge_ingress` reads them. A caller that reached into
//! `Conn.entry.conn.streams` for a stream would be a second opinion on the
//! core, which is the thing the bridge exists to prevent, so the stream is
//! named in one file, the datagram in another, and neither grows into the
//! other.

const std = @import("std");
const quic = @import("quic");
const base_addr = @import("../base/addr.zig");
const batch = @import("batch.zig");
const bridge_address = @import("bridge_address.zig");
const bridge_config = @import("bridge_config.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");
const qad = @import("../net/qad.zig");

const SocketAddr = base_addr.SocketAddr;

const Entry = quic.connection_manager.ConnEntry;
const quic_stream = quic.stream;

const Error = bridge_config.Error;
const Instant = bridge_config.Instant;
const fromCoreAddress = bridge_address.fromCoreAddress;
const toCoreAddress = bridge_address.toCoreAddress;

pub const PathError = quic.connection.Connection.PathError;
pub const TraversalError = quic.connection.Connection.NatTraversalError;
pub const RoundState = quic.connection.Connection.RoundState;
pub const PathSnapshot = struct {
    id: u8,
    local: ?SocketAddr,
    peer: ?SocketAddr,
    validated: bool,
    selected: bool,
    status: quic.connection.Connection.PathStatus,
    state: quic.connection.PathValidationState,
    sent: u64,
    received: u64,
};
pub const ObservedRoles = struct { local: ?qad.Role, peer: ?qad.Role };

fn reportRole(role: quic.observed_address.Role) ?qad.Role {
    return switch (role) {
        .disabled => null,
        .send_only => .send_only,
        .receive_only => .receive_only,
        .both => .both,
    };
}

/// The room one datagram of egress needs, in bytes: RFC 9000 §14.1's padded
/// Initial, taken from the core that pads to it rather than written down
/// here, so a change to the core's floor moves this with it.
///
/// It is a floor and not a ceiling because of how the core builds a datagram:
/// it pads an Initial up to this size and does that arithmetic against the
/// buffer it was handed, so a shorter buffer is one where a packet has
/// already consumed the frames it packed and has nowhere to put them.
pub const min_datagram = quic.connection_manager.MIN_INITIAL_DATAGRAM;

/// One QUIC connection the core owns, as a borrowed handle.
///
/// The core heap-allocates the connection and frees it: in `Bridge.destroy`,
/// or in `Bridge.sweep` once `Bridge.tick` has said the connection is
/// finished. Nothing in this file owns the memory, and a handle past that
/// point reads freed bytes. The vendor's own comment calls the ~185 KB
/// connection a heap allocation for the same reason.
pub const Conn = struct {
    /// The core's entry. Read connection state off it; write none.
    entry: *Entry,

    /// The core's own id for this connection, unique per bridge and never
    /// reused. What a caller logs.
    pub fn id(self: Conn) u64 {
        return self.entry.id;
    }
    /// Proof on the opening Initial, not a later path-validation bit. The value
    /// remains unchanged for the lifetime of this borrowed connection.
    pub fn initialValidation(self: Conn) incoming_filter.TokenProvenance {
        return switch (self.entry.initial_validation) {
            .unvalidated => .unvalidated,
            .retry => .retry,
            .new_token => .new_token,
        };
    }


    /// The negotiated protocol, borrowed until this connection is destroyed.
    pub fn alpn(self: Conn) ?[]const u8 {
        if (!self.established()) return null;
        const negotiated = self.entry.conn.negotiatedAlpn();
        return if (negotiated.len == 0) null else negotiated;
    }

    pub fn pathSnapshot(self: Conn, path_id: u8) ?PathSnapshot {
        const snapshot = self.entry.conn.pathSnapshot(path_id) orelse return null;
        return .{
            .id = snapshot.id,
            .local = fromCoreAddress(&snapshot.local),
            .peer = fromCoreAddress(&snapshot.peer),
            .validated = snapshot.validated,
            .selected = snapshot.selected,
            .status = snapshot.status,
            .state = snapshot.state,
            .sent = snapshot.sent,
            .received = snapshot.received,
        };
    }

    pub fn openPath(
        self: Conn,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        at: Instant,
        random: std.Random,
    ) PathError!u8 {
        return self.entry.conn.openPath(
            toCoreAddress(local_addr), toCoreAddress(peer_addr), at, random,
        );
    }

    pub fn selectPath(self: Conn, path_id: u8) PathError!void {
        try self.entry.conn.selectPath(path_id);
    }

    pub fn probePath(self: Conn, path_id: u8, at: Instant, random: std.Random) PathError!void {
        try self.entry.conn.probePath(path_id, at, random);
    }

    pub fn addTraversalAddress(self: Conn, value: SocketAddr) TraversalError!void {
        try self.entry.conn.addNatTraversalAddress(toCoreAddress(value));
    }

    pub fn removeTraversalAddress(self: Conn, value: SocketAddr) TraversalError!void {
        try self.entry.conn.removeNatTraversalAddress(toCoreAddress(value));
    }

    pub fn initiateTraversal(self: Conn, at: Instant, random: std.Random) TraversalError!void {
        try self.entry.conn.initiateNatTraversalRound(at, random);
    }

    pub fn traversalState(self: Conn) RoundState {
        return self.entry.conn.roundState();
    }

    /// A copied snapshot in caller storage, not a borrow of changing candidate state.
    pub fn traversalCandidates(self: Conn, out: []SocketAddr) []const SocketAddr {
        var addresses: [32]quic.address.Address = undefined;
        const candidates = self.entry.conn.remoteTraversalCandidates(
            addresses[0..@min(addresses.len, out.len)],
        );
        var count: usize = 0;
        for (candidates) |candidate| {
            const value = fromCoreAddress(&candidate) orelse continue;
            out[count] = value;
            count += 1;
        }
        return out[0..count];
    }

    pub fn observedAddress(self: Conn, path_id: u8) ?qad.ObservedAddress {
        const report = self.entry.conn.observedAddress(path_id) orelse return null;
        return .{
            .sequence = report.sequence,
            .addr = fromCoreAddress(&report.address) orelse return null,
        };
    }

    pub fn observedRoles(self: Conn) ObservedRoles {
        const roles = self.entry.conn.observedRoles();
        return .{ .local = reportRole(roles.local), .peer = reportRole(roles.peer) };
    }

    /// The peer's address on the active path, in this project's address.
    ///
    /// Null when the path has no peer address yet; see
    /// `Error.NoPathAddress` for the one route there.
    pub fn peer(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.peerAddress());
    }

    /// This node's address on the active path.
    pub fn local(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.localAddress());
    }

    /// Whether the handshake is done and the connection carries stream data.
    pub fn established(self: Conn) bool {
        return self.entry.conn.isEstablished();
    }

    /// Whether the core has finished with it. A closed connection may still
    /// be drained once — `sweep` has not run.
    pub fn closed(self: Conn) bool {
        return self.entry.conn.isClosed();
    }

    /// Everything the core wants sent at `at`, as the send seam's values.
    ///
    /// `buffer` receives the datagrams back to back and `out` the socket
    /// writes they add up to; both are the caller's, so nothing here
    /// allocates. Each send borrows its bytes out of `buffer`, so a send is
    /// good until the next `drain` on this connection overwrites it.
    ///
    /// The bytes are exactly what `Connection.sendAt` wrote, in order, cut
    /// into runs at every change of datagram size, destination or ECN mark.
    /// A run of equal-sized datagrams is a `batch.Send` carrying a segment size and
    /// is what a socket with `UDP_SEGMENT` turns into one `sendmsg`; a run of
    /// one is `batch.Send.single`, which is what rule 7 of
    /// `docs/ARCHITECTURE.md` says a single datagram is. How many datagrams
    /// one run may hold is the caller's `Capability` to decide, not this
    /// function's: it hands over the payload and leaves `batch.Runs` to the
    /// caller, because only the caller knows what its socket can do.
    ///
    /// # What the room costs, and when it gets asked about
    ///
    /// `Connection.sendAt` consumes what it packs — a CRYPTO frame's bytes
    /// leave the send buffer, a packet number is spent, the packet goes into
    /// the retransmission ledger — and it does that before the caller learns
    /// anything. So the room is checked before the core is asked for a
    /// datagram, never after:
    ///
    /// - **No slot and no room for a datagram is `error.NoRoom`, or
    ///   `error.NoPathAddress` for a path with no peer address, and both are
    ///   raised with nothing built.** An empty `out`, a `buffer` under
    ///   `min_datagram` and a path no address reached are the whole of it. The
    ///   flight is exactly as it was, and the retry after a bigger buffer
    ///   emits the datagram this call refused.
    /// - **Room running out mid-flight is not a refusal.** The loop stops
    ///   between datagrams with everything it built already inside a run it is
    ///   about to hand back, so the returned slice is a prefix of what `out`
    ///   and `buffer` had room for, and the rest of the flight is still the
    ///   core's to send. Call `drain` again for the rest; an empty slice is
    ///   how a call says the connection has nothing left.
    ///
    /// A datagram the core refused to build is `Error.CoreRefused`, with the
    /// core's own answer logged before the refusal is named so nothing is
    /// dropped on the floor. It is the one failure here that is not a room
    /// question, and the one with a cost: a datagram already built in this
    /// pass is inside no returned send, because a function that returns
    /// either a refusal or a list cannot hand back both.
    pub fn drain(
        self: Conn,
        out: []Egress,
        buffer: []u8,
        at: Instant,
        random: std.Random,
    ) Error![]Egress {
        const conn = self.entry.conn;
        // The selected path must exist before packet assembly can consume frames.
        const core_peer = conn.peerAddress().*;
        if (core_peer == .unset) return error.NoPathAddress;
        const selected_peer = fromCoreAddress(&core_peer) orelse return error.NoPathAddress;
        if (out.len == 0 or buffer.len < min_datagram) return error.NoRoom;

        var filled: usize = 0;
        var used: usize = 0;
        // The run being accumulated: `run_size` is 0 when no run is open.
        var run_start: usize = 0;
        var run_size: usize = 0;
        var run_to = selected_peer;
        var run_ecn: ?batch.Ecn = null;
        while (true) {
            // A free slot for this datagram, before it is built. Two while a
            // run is open: one for the close this datagram may trigger, and
            // one owed either way to the close of whatever run this datagram
            // opens. Holding that second one back is what lets the loop stop
            // at any datagram boundary — the run it leaves open still has the
            // slot its close needs.
            const slots = out.len - used;
            if (slots == 0 or (run_size != 0 and slots < 2)) break;
            if (buffer.len - filled < min_datagram) break;

            const len = conn.sendAt(buffer[filled..], at, random) catch |err| {
                std.log.warn("quic bridge: the core refused to build a packet: {t}", .{err});
                return error.CoreRefused;
            };
            if (len == 0) break;
            const to = fromCoreAddress(conn.lastSendPeer()) orelse return error.NoPathAddress;
            const ecn = batch.Recv.ecnFromBits(conn.lastSendEcn());
            if (run_size == 0) {
                run_size = len;
                run_to = to;
                run_ecn = ecn;
            } else if (len != run_size or !std.meta.eql(to, run_to) or ecn != run_ecn) {
                // Segmented datagrams share size, destination and ECN treatment.
                used = try closeRun(
                    out, used, buffer, run_start, filled, run_size, run_ecn, run_to,
                );
                run_start = filled;
                run_size = len;
                run_to = to;
                run_ecn = ecn;
            }
            filled += len;
        }
        if (run_size != 0) {
            // Safe by the loop's own arithmetic rather than by hope: the slot
            // was reserved before the datagram that opened this run.
            used = try closeRun(out, used, buffer, run_start, filled, run_size, run_ecn, run_to);
        }
        return out[0..used];
    }

    /// The bidirectional stream this connection's *peer* opened, or null when
    /// it has not opened one.
    ///
    /// **A stream is read by whichever end opened it.** `Stream.drain` reads
    /// the stream it is called on and nothing else, so a protocol where both
    /// ends speak on one stream has only two shapes: this end opens one and
    /// finds the peer's, or the peer opens one and this end takes it. The
    /// relay protocol takes the second — the client opens one stream and the
    /// relay speaks on that same one — because the client is the end that
    /// dials, and the end that dials is the end that has to speak first.
    ///
    /// Null rather than a refusal: the peer simply has not got there yet, and
    /// a caller that read that as an error would fail a connection that is one
    /// round trip from working. How many peer streams a caller expects is the
    /// caller's own question and is not answered here.
    pub fn peerStream(self: Conn) ?Stream {
        var it = self.entry.conn.streams.streams.iterator();
        while (it.next()) |entry| {
            if (quic_stream.isLocal(entry.key_ptr.*, self.entry.conn.is_server)) continue;
            return .{ .entry = entry.value_ptr.*, .owner = &self.entry.conn.streams };
        }
        return null;
    }

    /// Peer-initiated bidirectional streams in the current map iteration order.
    /// Indices can change when streams are reclaimed; consumers retain stream IDs.
    pub fn incomingStream(self: Conn, index: usize) ?Stream {
        var incoming: usize = 0;
        var iterator = self.entry.conn.streams.streams.iterator();
        while (iterator.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (!quic_stream.isBidi(stream_id)) continue;
            if (quic_stream.isLocal(stream_id, self.entry.conn.is_server)) continue;
            if (incoming == index) {
                return .{ .entry = entry.value_ptr.*, .owner = &self.entry.conn.streams };
            }
            incoming += 1;
        }
        return null;
    }

    /// Borrow a live bidirectional stream by ID; reacquire after driving the connection.
    pub fn stream(self: Conn, stream_id: u64) ?Stream {
        const live = self.entry.conn.streams.streams.get(stream_id) orelse return null;
        return .{ .entry = live, .owner = &self.entry.conn.streams };
    }
};

/// One application stream on a connection, as a byte pipe in this project's
/// vocabulary.
///
/// **The seam for everything that runs above a datagram.** `Conn` reads state
/// and `Conn.drain` writes packets, and nothing in between was exposed: a
/// protocol carried *over* a connection — the relay protocol is the one this
/// project has — has to run on a stream, and a caller reaching into
/// `Conn.entry.conn.streams` for one would be a second opinion on the core,
/// which is the thing this file exists to prevent. So the stream is named
/// here, once, and `vendor/quic` is untouched: it opens a stream, carries
/// bytes and says when it is done, which is the whole of what a framed
/// protocol over QUIC asks of a transport.
///
/// It is not relay-specific and nothing in this file knows what rides on it.
/// A borrowed handle, valid until stream reclamation or connection destruction.
/// Pin it across connection processing, or reacquire it by ID afterward.
///
/// Copies share the same stream and cursor. Serialize access with the owning
/// bridge. `close` ends sending, but does not release the stream.
pub const Stream = struct {
    /// The core's own stream.
    entry: *quic_stream.Stream,
    /// Borrowed owner; it must outlive this handle and owns deferred reclamation.
    owner: *quic_stream.StreamsMap,

    /// Open a new bidirectional stream on `conn`.
    ///
    /// The core's error set here is `anyerror` — `Connection.openStream`
    /// (`connection.zig:3935`) carries no named set — so it is mapped onto this
    /// file's own two answers, for the reason each of those gives. A stream
    /// limit is `error.NoStreamRoom` and logs nothing, because it is the core
    /// saying "not yet" and a warning a pass later contradicted would be a log
    /// about a fact that has since changed. Anything else is
    /// `Error.CoreRefused`, with the core's own answer logged before the
    /// refusal is named, so nothing is dropped on the floor.
    pub fn open(conn: Conn) Error!Stream {
        const opened = conn.entry.conn.openStream() catch |err| switch (err) {
            error.StreamLimitError => return error.NoStreamRoom,
            else => {
                std.log.warn("quic bridge: the core refused to open a stream: {t}", .{err});
                return error.CoreRefused;
            },
        };
        return .{ .entry = opened, .owner = &conn.entry.conn.streams };
    }

    /// The core's own id for this stream.
    pub fn id(self: Stream) u64 {
        return self.entry.stream_id;
    }

    /// Write bytes, after everything written before them.
    pub fn write(self: *Stream, bytes: []const u8) Error!void {
        self.entry.send.writeData(bytes) catch |err| {
            std.log.warn("quic bridge: the core refused stream bytes: {t}", .{err});
            return error.CoreRefused;
        };
    }

    /// Say nothing more on this stream. A peer reads the end as a FIN.
    pub fn close(self: *Stream) void {
        self.entry.send.close();
    }

    /// Take up to 64 ready runs from this stream, appending them to `sink`.
    ///
    /// Returns whether anything was appended, so a caller can fold this into
    /// its own "did this pass move anything" answer without a second read.
    /// Nothing is ready is false rather than a refusal: a stream with nothing
    /// on it yet is a peer that has not spoken, not a fault.
    ///
    /// **The sink is the caller's and it grows, because a read has no length
    /// worth guessing.** The core hands back whatever contiguous run it holds —
    /// `FrameSorter.pop` returns a whole chunk, coalesced up to `MAX_COALESCED`
    /// (`stream.zig:72`) — so the size of a read is a function of what the peer
    /// sent and of nothing the caller can see coming. A caller that owned a
    /// fixed buffer had two answers and both were wrong: sized to a frame it
    /// refused the run *after* popping it, and the bytes were already gone
    /// (`stream.zig:390-396` hands over ownership), and sized to the ceiling it
    /// allocated the ceiling per stream for the whole life of the connection.
    /// A sink that grows pays for what actually arrived and nothing for what a
    /// peer might send.
    ///
    /// **One copy, not two.** The core hands its chunk to the application to
    /// free (`ReceiveStream.read`, `stream.zig:523`), so `gpa` is the allocator
    /// that made it — which is the bridge's own, and a caller passes the one it
    /// created the bridge with. The append is the copy, and it has to be one:
    /// a framed protocol parses a message in place and borrows into the bytes
    /// it was handed, and those bytes must outlive the message, which a borrow
    /// of the core's chunk cannot because the next read has already taken it.
    ///
    /// **The room is taken before the bytes, because the bytes are gone once
    /// the core has handed them over.** A read advances the stream's position,
    /// charges the peer for what it read, and transfers an owned allocation
    /// out; an allocator that then refuses the append has dropped a run the
    /// peer will never retransmit, because from the core's side it was
    /// delivered. So this asks the core how much the next read holds —
    /// `ReceiveStream.peekLen`, which consumes nothing — reserves exactly
    /// that, and reads afterwards.
    ///
    /// **What a refused allocation leaves.** Everything appended before the
    /// refusal stays in `sink`, which is the caller's, and every byte the sink
    /// did not take is still pending on the stream, in order. A retry with an
    /// allocator that answers appends exactly the bytes this call stopped at,
    /// and none of them twice. An error may leave a committed prefix: compare
    /// `sink.items.len` before and after the call to find it. `false` means
    /// that no bytes were appended and no run was ready.
    ///
    /// **A partial sink is rarer than the sentence above suggests.** Contiguous
    /// frames are coalesced into one run before it is read, and a second run is
    /// only readable once the gap before it is filled, so a drain in practice
    /// either moves one whole run or moves nothing: the common refusal is the
    /// first reserve, and the sink is untouched. The contract above is the one
    /// that holds either way.
    ///
    /// Each call consumes at most 64 ready runs. Drain again until `false`
    /// before treating the receive side as empty. `sink` must use the same
    /// allocator as the stream.
    pub fn drain(
        self: *Stream,
        gpa: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) std.mem.Allocator.Error!bool {
        var moved = false;
        // Bounded by what the stream can hold rather than by its data: a run is
        // taken per pass and each pass consumes what it took, so the loop ends
        // when the stream is drained. The bound is the backstop for a bug that
        // broke that, not a budget.
        var runs: usize = 0;
        while (runs < max_drain_runs) : (runs += 1) {
            const len = self.entry.recv.peekLen() orelse break;
            try sink.ensureUnusedCapacity(gpa, len);
            const chunk = self.entry.recv.read() orelse return error.OutOfMemory;
            sink.appendSliceAssumeCapacity(chunk);
            gpa.free(chunk);
            moved = true;
        }
        return moved;
    }

    /// Whether the peer has said everything it will say on this stream.
    pub fn finished(self: Stream) bool {
        return self.entry.recv.allReceived();
    }

    /// The peer has acknowledged every byte and the FIN this side sent.
    pub fn sentFinished(self: Stream) bool {
        return self.entry.send.fin_acked and
            self.entry.send.ack_offset >= self.entry.send.write_offset;
    }

    /// Keep this stream alive across connection processing until `unpin`.
    /// One consumer owns the pin; it does not extend the connection's lifetime.
    pub fn pin(self: Stream) error{AlreadyPinned}!void {
        if (self.entry.send.pinned) return error.AlreadyPinned;
        self.entry.send.pinned = true;
    }

    /// Release the borrow and offer a settled stream for next-cycle reclamation.
    pub fn unpin(self: Stream) void {
        std.debug.assert(self.entry.send.pinned);
        self.entry.send.pinned = false;
        self.owner.disposeIfSettled(self.entry);
    }
};

/// One socket write: where it goes and what the batcher is to be asked for.
pub const Egress = struct {
    /// The actual destination of these datagrams, including off-path NAT probes.
    to: SocketAddr,
    /// The payload. Feed it to `batch.Runs.init` with the socket's
    /// `Capability` and hand each run to `batch.cmsg`.
    send: batch.Send,
};

/// A run of equally sized datagrams, or one datagram.
///
/// The one datagram case is not a special case of the batch case: `Send` says
/// "one datagram" by carrying no segment size, and a hand-built value with a
/// segment size set and a payload no longer than it would hand a socket a
/// `UDP_SEGMENT` control message naming a single datagram. `batch.Runs.next`
/// refuses to propagate the size onto a run of one for the same reason.
pub fn group(contents: []const u8, size: usize, ecn: ?batch.Ecn) batch.Error!batch.Send {
    if (contents.len == size) return batch.Send.single(contents, ecn);
    return batch.Send.batch(contents, size, ecn);
}

/// Close the run that ended at `end` and start nothing.
///
/// `to` belongs to the emitted packet's route, not necessarily the selected path.
/// The `out.len` check is the slot the caller counted for this close; a run of
/// equal-size datagrams always divides by its size, so `group` cannot refuse it.
/// The capacity check protects that invariant; the caller reserves the close slot.
fn closeRun(
    out: []Egress,
    used: usize,
    buffer: []u8,
    begin: usize,
    end: usize,
    size: usize,
    ecn: ?batch.Ecn,
    to: SocketAddr,
) Error!usize {
    if (used == out.len) return error.NoRoom;
    out[used] = .{
        .to = to,
        .send = try group(buffer[begin..end], size, ecn),
    };
    return used + 1;
}

/// How many contiguous runs one `Stream.drain` takes. Each pass consumes the
/// run it took, so the loop ends when the stream is drained; this is the
/// backstop for a bug that broke that, not a budget.
const max_drain_runs = 64;

const t = std.testing;

// The bridge under test and the peer's half of a handshake, named here so the
// tests below stand as they were written.
const base_key = @import("../base/key.zig");
const addr_map = @import("addr_map.zig");
const Bridge = @import("bridge_manager.zig").Bridge;

const SecretKey = base_key.SecretKey;

const peer_mod = @import("bridge_peer.zig");
const server_seed = peer_mod.server_seed;
const client_seed = peer_mod.client_seed;
const client_addr = peer_mod.client_addr;
const alpn = peer_mod.alpn;
const start = peer_mod.start;
const Prng = peer_mod.Prng;
const max_datagram = peer_mod.max_datagram;
const max_egress = peer_mod.max_egress;
const max_rounds = peer_mod.max_rounds;
const Client = peer_mod.Client;
const exchange = peer_mod.exchange;

test "egress is the batcher's value, and a burst of one size is one send" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(5);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 6, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    try t.expectEqualStrings(alpn, conn.alpn() orelse return error.TestUnexpectedResult);
    const before = conn.peer() orelse return error.TestUnexpectedResult;
    try t.expectError(
        error.MultipathNotNegotiated,
        conn.openPath(peer_mod.server_addr, client_addr, start, engine.random()),
    );
    try t.expectError(error.InvalidPathId, conn.selectPath(2));
    try t.expectEqual(before, conn.peer().?);
    try t.expect(conn.pathSnapshot(2) == null);
    try t.expect(conn.observedAddress(0) == null);
    try t.expect(conn.incomingStream(0) == null);
    const first_incoming = try client.conn.openStream();
    const second_incoming = try client.conn.openStream();
    try first_incoming.send.writeData("first");
    try second_incoming.send.writeData("second");
    try exchange(&client, bridge, &map, start);
    const first = conn.incomingStream(0) orelse return error.TestUnexpectedResult;
    const second = conn.incomingStream(1) orelse return error.TestUnexpectedResult;
    try t.expect(first.id() != second.id());
    try t.expect(
        first.id() == first_incoming.stream_id or first.id() == second_incoming.stream_id,
    );
    try t.expect(
        second.id() == first_incoming.stream_id or second.id() == second_incoming.stream_id,
    );
    try t.expect(conn.incomingStream(2) == null);
    try t.expectEqual(first.id(), (conn.stream(first.id()) orelse
        return error.TestUnexpectedResult).id());
    try t.expect(conn.stream(std.math.maxInt(u64)) == null);
    try t.expect(!first.sentFinished());
    try first.pin();
    try t.expectError(error.AlreadyPinned, first.pin());
    first.unpin();

    // Enough payload for several datagrams, which is what makes the batching
    // observable at all: one datagram is one send whatever the code does.
    const payload = "ozai" ** 4096;
    const stream = try conn.entry.conn.openStream();
    try stream.send.writeData(payload);
    stream.send.close();

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var segmented: usize = 0;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        const sends = try conn.drain(egress[0..], out[0..], start, client.random());
        if (sends.len == 0) break;
        for (sends) |send| {
            // Every send is addressed to the peer address the core holds,
            // which is a synthetic address and survives the round trip.
            try t.expectEqual(client_addr, send.to);
            // And every send is a value the batcher can cut into socket
            // writes whose payload comes back whole.
            var runs = try batch.Runs.init(send.send, batch.Capability.linux_full);
            var rejoined: usize = 0;
            while (runs.next()) |run| rejoined += run.contents.len;
            try t.expectEqual(send.send.contents.len, rejoined);
            var cmsgs: [batch.max_cmsg]batch.Cmsg = undefined;
            const written = batch.cmsg(send.send, .v6, &cmsgs);
            try t.expectEqual(
                @as(usize, if (send.send.isSegmented()) batch.max_cmsg else 1),
                written.len,
            );
            if (send.send.isSegmented()) segmented += 1;
            var runs2 = try batch.Runs.init(send.send, batch.Capability.none);
            while (runs2.next()) |run| client.receive(run.contents, start);
        }
    }

    // The finding in its strongest form: a core datagram fits
    // `batch.Send` exactly, so a burst of equally sized QUIC packets comes
    // out of the bridge as one `UDP_SEGMENT` send rather than N.
    try t.expect(segmented > 0);
}

test "an allocator that refuses the sink leaves every byte pending for the next pass" {
    // A stream is the one thing in this file a test can drive without a
    // peer: the core hands out a receive half, and a STREAM frame is all it
    // takes to fill it.
    const message = "the relay frame this pass must not lose";
    var owner = quic_stream.StreamsMap.init(t.allocator, true);
    defer owner.deinit();
    const core = try owner.getOrCreateStream(0);
    try core.recv.handleStreamFrame(0, message, false);
    var stream: Stream = .{ .entry = core, .owner = &owner };

    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);

    // The sink's first allocation is the refusal: the run the peer sent is
    // already buffered and untouched, because the room is taken before the
    // read that would hand it over.
    var refusing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, stream.drain(refusing.allocator(), &sink));
    try t.expectEqual(@as(usize, 0), sink.items.len);

    // The retry yields the bytes the refusal interrupted at, once, in order.
    try t.expect(try stream.drain(t.allocator, &sink));
    try t.expectEqualStrings(message, sink.items);
    try t.expect(!try stream.drain(t.allocator, &sink));
}

test "receive copy-out OOM is not mistaken for a finished stream" {
    var refusing = std.testing.FailingAllocator.init(t.allocator, .{});
    const gpa = refusing.allocator();
    var owner = quic_stream.StreamsMap.init(gpa, true);
    defer owner.deinit();
    const core = try owner.getOrCreateStream(0);
    try core.recv.handleStreamFrame(5, "world", true);
    try core.recv.handleStreamFrame(0, "hello", false);
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    try sink.ensureTotalCapacity(gpa, 10);
    const ready = core.recv.peekLen().?;
    var stream: Stream = .{ .entry = core, .owner = &owner };
    refusing.fail_index = refusing.alloc_index;
    try t.expectError(error.OutOfMemory, stream.drain(gpa, &sink));
    try t.expectEqual(@as(usize, 0), sink.items.len);
    try t.expectEqual(ready, core.recv.peekLen().?);
    refusing.fail_index = std.math.maxInt(usize);
    try t.expect(try stream.drain(gpa, &sink));
    try t.expectEqualStrings("helloworld", sink.items);
}

test "unpin queues a stream that settled while pinned after guarded GC stood down" {
    // FIN and ACK callbacks cannot reclaim a borrowed stream until its owner releases it.
    var owner = quic_stream.StreamsMap.init(t.allocator, false);
    defer owner.deinit();
    owner.setMaxStreams(1, 0);
    const core = try owner.openBidiStream();
    var stream: Stream = .{ .entry = core, .owner = &owner };
    const stream_id = stream.id();
    try stream.pin();
    try stream.write("done");
    stream.close();
    core.send.send_window = 4;
    const sent = core.send.popStreamFrame(4).?.stream;
    try t.expect(sent.fin);
    try t.expectEqual(@as(u64, 4), sent.length);
    try core.recv.handleStreamFrame(0, "", true);
    owner.closeIfDone(core);
    try core.send.onAck(sent.offset, sent.length, sent.fin);
    owner.disposeIfSettled(core);
    owner.needs_gc_scan = true;
    owner.collectClosedStreams();
    try t.expect(stream.finished());
    try t.expect(stream.sentFinished());
    try t.expect(core.closed_for_gc);
    try t.expect(!core.disposal_queued);
    try t.expect(!owner.needs_gc_scan);
    try t.expectEqual(@as(usize, 0), owner.disposal_count);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == core);

    stream.unpin();
    try t.expect(!core.send.pinned);
    try t.expect(core.disposal_queued);
    try t.expectEqual(@as(usize, 1), owner.disposal_count);
    try t.expect(owner.streams.get(stream_id) == core);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == null);
}

test "unpin retains a closed stream until its FIN is acknowledged" {
    // Release must not discard a FIN that PTO still needs to retransmit.
    var owner = quic_stream.StreamsMap.init(t.allocator, false);
    defer owner.deinit();
    owner.setMaxStreams(1, 0);
    const core = try owner.openBidiStream();
    var stream: Stream = .{ .entry = core, .owner = &owner };
    const stream_id = stream.id();
    try stream.pin();
    stream.close();
    const sent = core.send.popStreamFrame(0).?.stream;
    try t.expect(sent.fin);
    try core.recv.handleStreamFrame(0, "", true);
    owner.closeIfDone(core);
    stream.unpin();
    try t.expect(!core.send.pinned);
    try t.expect(core.closed_for_gc);
    try t.expect(!core.disposal_queued);
    try t.expectEqual(@as(usize, 0), owner.disposal_count);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == core);

    try core.send.onAck(sent.offset, sent.length, sent.fin);
    owner.disposeIfSettled(core);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == null);
}

test "unpin uses the disposal queue overflow backstop" {
    // A full queue delays release through the existing manager, not a scan in unpin.
    var owner = quic_stream.StreamsMap.init(t.allocator, false);
    defer owner.deinit();
    owner.setMaxStreams(owner.disposal_queue.len + 1, 0);
    for (0..owner.disposal_queue.len) |_| {
        const queued = try owner.openBidiStream();
        owner.closeStream(queued.stream_id);
    }
    const core = try owner.openBidiStream();
    var stream: Stream = .{ .entry = core, .owner = &owner };
    const stream_id = stream.id();
    try stream.pin();
    stream.close();
    const sent = core.send.popStreamFrame(0).?.stream;
    try core.recv.handleStreamFrame(0, "", true);
    owner.closeIfDone(core);
    try core.send.onAck(sent.offset, sent.length, sent.fin);
    owner.disposeIfSettled(core);
    try t.expect(!owner.disposal_overflow);

    stream.unpin();
    try t.expect(!core.disposal_queued);
    try t.expect(owner.disposal_overflow);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == core);
    try t.expect(owner.needs_gc_scan);
    owner.collectClosedStreams();
    try t.expect(core.disposal_queued);
    owner.drainDisposalQueue();
    try t.expect(owner.streams.get(stream_id) == null);
}
