//! The first *transfer* over a real connection: a blob's bytes, from a provider
//! that has them to a getter that does not.
//!
//! `test/protocol_loopback_test.zig` sent a `get` across a kernel socket and
//! proved the plan's first blob property — missing data is EOF, not an error
//! frame — with an answer of thirty-one bytes the test wrote itself. Every
//! transfer in this project so far has been a negotiation: a request went out,
//! a request came back, and no content changed hands. This file moves content.
//!
//! # What is asserted
//!
//! 1. **A whole blob, by content.** `GetRequest.blob` over a real connection,
//!    compared byte for byte against the provider's own copy. There is no
//!    length-only assertion in this file: a transfer test that checks a length
//!    has checked nothing about the data.
//! 2. **Two disjoint ranges, and nothing else.** A `RangeSpec` of two
//!    selected runs with a gap either side of each. The answer is those two
//!    runs, in order, and the byte ranges the provider derived are asserted
//!    against chunk arithmetic before the content is.
//! 3. **A byte range that is not chunk-aligned.** `bytesToChunks` rounds
//!    *outward* at both ends, so a request for bytes 5000 through 20000 is a
//!    request for chunks 4 through 20 and the answer starts at byte 4096.
//!    That rounding is the conversion the type exists for, and a whole-blob
//!    fetch never reaches it.
//! 4. **The short last chunk.** `chunksToBytes` is exact only for a whole
//!    number of chunks, so the range that ends in this blob's last chunk comes
//!    back shorter than the chunk arithmetic alone says. The provider has to
//!    clip, and the assertion is on the clipped length.
//! 5. **`ChunkRangeSet` on the wire.** An `observe` answered with the
//!    provider's own availability, decoded by the getter, which then derives
//!    from the boundaries that arrived the byte ranges the answer must cover.
//! 6. **The two framings are not interchangeable, on the wire.** A `push` and
//!    its payload share a stream, so the payload must not be readable as part
//!    of a `get` body; and a `get` frame is not a `push` frame with the byte
//!    in front changed. Both are checked against bytes off a socket.
//! 7. **A short answer is not a complete transfer.** A provider that stops
//!    part way through and closes: the getter sees a FIN, the bytes it holds
//!    are the right ones, and there are fewer of them than the request asked
//!    for. A transfer that hands the short buffer back as if it were whole is
//!    worse than one that fails, so the completion test is a content
//!    comparison and it is asserted to fail.
//! 8. **The send seam segmented the transfer.** `batch.max_segments_linux` is
//!    64 and this blob's answer is more than 64 datagrams, so the batching ran
//!    off the end of what one `sendmsg` may carry: `UDP_SEGMENT` is on the
//!    wire, and at least one batch had to be cut to go out.
//! 9. **The batch boundary, at more than one segment size.** The core's
//!    datagram size on loopback does not move, so a transfer can only ever
//!    burst at one of them. A model that cut at the segment cap alone would
//!    pass that transfer and regress at every other size, so the sizes a
//!    connection cannot be made to produce are asserted on the seam directly:
//!    the most bytes one `sendmsg` may carry is a ratio of the payload limit to
//!    the segment size and not a constant.
//!
//! # What is not asserted
//!
//! That the bytes are *valid bao data*. This project has no bao encoder, so
//! the provider's answer is the blob's own bytes and what is under test is
//! the transport, the framing and the range algebra. Whether a bao decode
//! accepts them is a question for the milestone that brings a bao encoder,
//! and `test/protocol_loopback_test.zig` says the same about the bytes it
//! wrote itself.
//!
//! # Time is virtual and moves only when the test says so
//!
//! Every call into the QUIC core takes an `Instant`. This file owns one
//! counter and advances it by one millisecond per round. No clock is ever read
//! and nothing sleeps anywhere in this file, so a loaded machine cannot make
//! this test fail by being busy: the bound is on rounds, and a run that never
//! finishes ends by naming the request it was on, the ranges it had planned
//! and how many bytes had arrived. The total virtual time stays far below the
//! core's 30 s idle timeout, so a connection is never reaped by the clock —
//! a reaped connection would be a finding about time and not about blobs.
//!
//! # The provider is this file's own
//!
//! `src/blobs/protocol.zig` is a codec: it has `BaoResponse` and no server, so
//! the half of the protocol that *answers* a request is this file's. Every
//! step of its answer is the protocol's own and none of it is invented here —
//! the sequence walk is `RangeSpecSeq.iter`, the spans are `RangeSpec.resolve`
//! against the blob's chunk count, the bytes are `chunksToBytes`, and the
//! availability an `observe` reports is a `ChunkRangeSet` boundary list. The
//! one thing this file adds is the clip at the blob's real length, because
//! `chunksToBytes` is only exact for a whole number of chunks and this blob's
//! last chunk is short.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;
const postcard = ozai.postcard;
const batch = ozai.transport_batch;
const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;
const socket_mod = ozai.transport_socket;
const addr_map = ozai.addr_map;

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

/// Where virtual time starts. See the module doc: it only moves by `quantum`.
const start_ns: u64 = 1000 * std.time.ns_per_s;

/// How far the clock moves per round. A round is a handful of syscalls, so
/// this is a clock and not a delay: nothing in this file waits for it.
const quantum: u64 = std.time.ns_per_ms;

/// How many rounds a phase may take before it is called stalled.
///
/// Generous, because a round is a few syscalls and nothing here can block: the
/// bound is a backstop against a run that never finishes, not a timer.
const max_rounds = 512;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small, and the room for them.
///
/// A burst of this blob's answer is bounded by the sender's congestion window
/// rather than by a fixed count, so the room is sized for the whole answer and
/// not for a guess about how many packets a burst holds.
const max_egress = 512;
const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: the datagram is copied into its front and a
/// stateless reply is written behind it.
const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// The most byte ranges one answer may cover. A `RangeSpec` of a few widths
/// yields a few spans, and a bound keeps the plan a value rather than an
/// allocation.
const max_spans = 8;

/// The most jobs one link carries, and so the most decode storages.
const max_jobs = 8;

/// Room for one encoded request, and for the `push` arm's length-prefixed body
/// scratch. A `get` is 39 bytes and a `push` one varint more.
const request_room = 512;

/// Room for one encoded `ObserveItem` and for the length in front of it.
const observe_room = 256;

/// Slots one blobs decode borrows into.
///
/// The counts are this file's own bounds, not the protocol's: a request longer
/// than any of them is a frame this artifact cannot hold, and
/// `RangeSpecSeq.parse` reports that as `error.BufferFull` rather than
/// pretending it read the request.
const decode_slots = 16;

/// The provider's blob: 256 whole chunks and 700 bytes of a short one.
///
/// The size is chosen, not picked. Larger than one packet by three orders of
/// magnitude, and larger than `batch.max_segments_linux` datagrams, so the send
/// seam's segmentation is on the path rather than merely configured. The
/// remainder is 700 rather than 1024 so the last chunk is short, which is the
/// case `chunksToBytes` cannot answer exactly.
const blob_length: usize = 256 * 1024 + 700;

/// The blob's hash, and a request's hash is 32 raw bytes.
///
/// The first byte matters to one assertion in this file: overwriting a `get`
/// frame's discriminant with `push`'s makes that byte the declared body
/// length, and 0x5a is a one-byte varint for ninety — more than the frame has
/// left. See the framing test.
const blob_hash: [32]u8 = @splat(0x5a);

/// The seeds of the blob's bytes and the payload's. Two, so a payload cannot
/// be mistaken for a stretch of the blob.
const blob_seed: u32 = 0x243f_6a88;
const payload_seed: u32 = 0xb7e1_5162;

/// The bao data a `push` writes after its request, on the same stream. Big
/// enough that a reader which swallowed it into the request would hold more
/// bytes than the request declares.
const payload_length: usize = 1024;

/// How much of a whole-blob answer the truncating provider stops after.
const truncated_at: usize = 1000;

/// The widths of the disjoint range spec: two chunks off, three on, four off,
/// five on. Two selected runs that do not touch, which is the shape a
/// whole-blob fetch cannot express.
const disjoint_widths = [_]u64{ 2, 3, 4, 5 };

/// The widths of a range that starts in the blob's 255th chunk. The selected
/// run runs to the end of the walk and is cut by the blob's end, which is the
/// short last chunk.
const tail_widths = [_]u64{ 254, 3 };

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One endpoint's transport: an identity, a socket on an ephemeral loopback
/// port, the bridge that runs its connections, and the buffers both seams need.
///
/// It carries no protocol state, because the two halves of this test want
/// different state on top of exactly this.
const Wire = struct {
    name: []const u8,
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
    stats: Counters = .{},

    fn init(
        self: *Wire,
        name: []const u8,
        secret: SecretKey,
        expect_peer: ?NodeId,
        alpn: []const u8,
        seed: u64,
    ) !void {
        self.* = .{
            .name = name,
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
        self.bridge = try Bridge.create(t.io, t.allocator, .{
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
        errdefer self.dialer.destroy() catch unreachable;
        // A bridge created a moment ago has no entry for `destroy` to refuse,
        // so this fires only on an allocation that followed it.
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
        // Backwards, because `removeConnection` swap-removes and a forward
        // walk would skip an entry and leave a freed one behind.
        var index = self.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
        }
        self.bridge.sweep();
        // `catch unreachable`, and this is the why rather than a teardown with
        // nowhere to put an error: the loop above is the thing `destroy`
        // refuses, and the loop has already run.
        self.dialer.destroy() catch unreachable;
        self.bridge.destroy();
        t.allocator.free(self.egress);
        t.allocator.free(self.out);
        t.allocator.free(self.scratch);
        t.allocator.free(self.buf);
        self.map.deinit(t.allocator);
        self.socket.close();
        self.secret.deinit();
    }

    fn random(self: *Wire) std.Random {
        return self.engine.random();
    }

    /// Take everything queued on this socket and hand it to the bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into
    /// one buffer, so the stride is what says how many packets there are and
    /// the bridge is handed them one at a time.
    fn take(self: *Wire, at: Instant) !bool {
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
            self.stats.in += recv.datagramCount();
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try self.bridge.recv(&self.map, .{
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
                        self.stats.out += 1;
                        self.stats.note(reply, sock.caps);
                        _ = try sock.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// Drain every connection and write each datagram out, then run the timers.
    fn flush(self: *Wire, at: Instant) !bool {
        var moved = false;
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(self.egress, self.out, at, self.random())) |egress| {
                self.stats.out += 1;
                // Counted before the write, because the accounting is about
                // what the bridge handed over and not about whether the kernel
                // took it.
                self.stats.note(egress.send, self.socket.caps);
                const report = try self.socket.send(t.io, egress.to, egress.send);
                if (!report.ecnSurvived()) self.stats.dropped_ecn += 1;
                moved = true;
            }
        }
        var scan: usize = 0;
        while (self.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (self.bridge.tick(conn, at, self.random()) == .finished) self.stats.finished += 1;
        }
        return moved;
    }

    /// One pass of the whole link: everything this side has, then everything
    /// its peer has.
    fn exchange(self: *Wire, at: Instant) !bool {
        const mine = try self.take(at);
        return (try self.flush(at)) or mine;
    }
};

/// What one side moved, and how the send seam cut it up.
///
/// The datagram counts are not a claim about the protocol; they are the
/// measurement the plan asks for, because a transfer this size has to go out
/// as segmented sends and only the seam knows how many datagrams there were.
const Counters = struct {
    out: usize = 0,
    in: usize = 0,
    finished: usize = 0,
    /// `batch.Send` values handed to the socket.
    sends: usize = 0,
    /// `sendmsg` calls those sends were cut into, at the socket's own
    /// capability: a batch of more than `max_segments_linux` datagrams is more
    /// than one `sendmsg` may carry.
    runs: usize = 0,
    /// Datagrams inside those sends.
    datagrams: usize = 0,
    /// The most datagrams in one send, which is what says whether the batch
    /// boundary was crossed inside a single batch.
    widest: usize = 0,
    /// Sends the batcher segmented rather than passing as one datagram.
    segmented: usize = 0,
    /// Sends whose traffic class the kernel did not carry.
    dropped_ecn: usize = 0,

    /// Account for one `batch.Send`, cut with the capability the socket will
    /// use.
    fn note(counter: *Counters, send: batch.Send, caps: batch.Capability) void {
        counter.sends += 1;
        const datagrams = send.datagramCount();
        counter.datagrams += datagrams;
        counter.widest = @max(counter.widest, datagrams);
        if (send.isSegmented()) counter.segmented += 1;
        var runs = batch.Runs.init(send, caps) catch return;
        while (runs.next()) |_| counter.runs += 1;
    }
};

// ---------------------------------------------------------------------------
// The provider's half
// ---------------------------------------------------------------------------

/// What the provider holds: one blob, its hash, and the bao data a `push`
/// carries behind its request.
const Store = struct {
    bytes: []u8,
    payload: []u8,
    hash: [32]u8 = blob_hash,

    fn init(alloc: std.mem.Allocator) !Store {
        const bytes = try alloc.alloc(u8, blob_length);
        errdefer alloc.free(bytes);
        const payload = try alloc.alloc(u8, payload_length);
        errdefer alloc.free(payload);
        fill(bytes, blob_seed);
        fill(payload, payload_seed);
        return .{ .bytes = bytes, .payload = payload };
    }

    fn deinit(store: Store, alloc: std.mem.Allocator) void {
        alloc.free(store.payload);
        alloc.free(store.bytes);
    }

    /// How many chunks the blob has: the input every range walk is read
    /// against, and the protocol's own rounding rather than a ceiling written
    /// out here. `chunkAfterByte` is the first chunk at or past a byte offset,
    /// which for a blob's own length is its chunk count.
    fn chunkCount(store: Store) u64 {
        return blobs.chunkAfterByte(store.bytes.len);
    }
};

/// The bytes of `out`, from a xorshift32 rather than a repeated byte.
///
/// A transfer test that moved `0x5a` from one buffer to another would pass
/// against a send path that duplicated one byte 256 times, and against one
/// that wrote the first quarter over the last. The period here is 2^32 - 1,
/// so no alignment repeats inside a blob of this size.
fn fill(out: []u8, seed: u32) void {
    var state: u32 = seed;
    for (out) |*byte| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte.* = @truncate(state);
    }
}

/// The byte ranges one answer covers, and the chunk boundaries they came from.
///
/// The boundaries are kept beside the byte ranges because the two directions of
/// the conversion are the property: the plan goes chunks to bytes, and an
/// `observe` reports the same spans as a `ChunkRangeSet` for the getter to go
/// the other way.
const Plan = struct {
    ranges: [max_spans]blobs.ByteRange = @splat(.{ .start = 0, .end = 0 }),
    len: usize = 0,
    boundaries: [max_spans * 2]u64 = @splat(0),
    boundary_len: usize = 0,

    /// How many bytes the plan covers in total.
    fn total(plan: Plan) usize {
        var sum: usize = 0;
        for (plan.ranges[0..plan.len]) |range| sum += range.end - range.start;
        return sum;
    }

    fn boundariesSlice(plan: *const Plan) []const u64 {
        return plan.boundaries[0..plan.boundary_len];
    }
};

/// Walk a spec against the store and fill `plan`.
///
/// Every step is the protocol's own: `RangeSpec.resolve` is upstream's
/// `to_chunk_ranges` read against a blob, and `chunksToBytes` is the other
/// direction of the conversion. The clip at the end is this file's, and it is
/// required rather than tidy: a blob whose length is not a multiple of 1024
/// has a short last chunk, so the byte count the chunk arithmetic returns for
/// a range ending in it is the first byte *past* that chunk.
fn planSpec(plan: *Plan, spec: range_spec.RangeSpec, store: Store) error{TooManySpans}!void {
    plan.* = .{};
    var spans = spec.resolve(store.chunkCount());
    while (spans.next()) |span| {
        if (plan.len == max_spans) return error.TooManySpans;
        const end = span.offset +| span.size;
        const bytes = blobs.chunksToBytes(.{ .start = span.offset, .end = end });
        plan.ranges[plan.len] = .{
            .start = @min(bytes.start, store.bytes.len),
            .end = @min(bytes.end, store.bytes.len),
        };
        plan.len += 1;
        // The parity `ChunkRangeSet` documents: an even position starts a
        // range and an odd one ends it.
        plan.boundaries[plan.boundary_len] = span.offset;
        plan.boundary_len += 1;
        plan.boundaries[plan.boundary_len] = end;
        plan.boundary_len += 1;
    }
}

/// The byte ranges a boundary list names, read against the size it arrived
/// with.
///
/// The direction `planSpec` did not take, and the one a getter has to take to
/// know what an answer will cover. The clip is the same rule: the last chunk
/// of a blob is short and the boundary list does not know that.
fn planFromBoundaries(boundaries: []const u64, size: usize) Plan {
    var plan: Plan = .{};
    var slot: usize = 0;
    while (slot + 1 < boundaries.len) : (slot += 2) {
        if (plan.len == max_spans) break;
        const bytes = blobs.chunksToBytes(.{
            .start = boundaries[slot],
            .end = boundaries[slot + 1],
        });
        plan.ranges[plan.len] = .{
            .start = @min(bytes.start, size),
            .end = @min(bytes.end, size),
        };
        plan.len += 1;
    }
    return plan;
}

/// The spec a decoded `get`'s sequence puts on the store's one blob.
///
/// The walk is `RangeSpecSeq.iter`, upstream's `ChunkRangesSeqIter`: one spec
/// per blob, and a pair the walk has not reached yet leaves the current spec in
/// place. The store holds one blob, so the first pair is the whole of it — and
/// for a whole-blob request that first pair is followed by the terminator
/// naming a blob that is not here.
fn specOf(request: blobs.GetRequest) range_spec.RangeSpec {
    var walk = request.ranges.iter();
    return walk.next() orelse range_spec.RangeSpec.empty;
}

/// The spec a decoded request carries for the store's one blob, whatever
/// framing it arrived in. A `push` is a newtype over a `GetRequest`, so its
/// body is the same shape and its first pair is the same pair.
fn requestSpec(job: *const Job) error{GetManyUnsupported}!range_spec.RangeSpec {
    return switch (job.seen.?) {
        .to_eof => |request| switch (request) {
            .get => |value| specOf(value),
            .observe => |value| value.ranges,
            .get_many => return error.GetManyUnsupported,
        },
        .length_prefixed => |framed| framed.request.get.ranges.items[0].spec,
    };
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// Which of the four request types a job puts on the wire.
const Kind = enum {
    get,
    observe,
    push,

    fn discriminant(kind: Kind) blobs.RequestType {
        return switch (kind) {
            .get => .get,
            .observe => .observe,
            .push => .push,
        };
    }
};

/// One request the getter makes, what the provider made of it, and the
/// bookkeeping a stall report needs.
const Job = struct {
    /// Named in the stall report. A stall that does not say which request
    /// stalled is a stall that has to be reproduced before it can be read.
    name: []const u8,
    kind: Kind = .get,
    /// The widths of the range spec, in chunks. A `get` puts them in a
    /// sequence and an `observe` in a spec; both carry the same widths.
    widths: []const u64 = &.{},
    /// Write the module's own whole-blob sequence rather than a sequence of
    /// this file's, so the constructor upstream uses is on the path.
    whole: bool = false,
    /// How many bytes of the plan the provider writes, and null for all of
    /// them. A number below the total is the truncated case.
    truncate_to: ?usize = null,
    /// Write nothing at all, and close: the provider has nothing, which is EOF
    /// on the wire.
    empty: bool = false,

    /// The bytes the getter encoded, and the request the provider decoded off
    /// the socket from them.
    frame_len: usize = 0,
    frame: [request_room]u8 = undefined,
    seen: ?blobs.Request = null,
    /// Where the decode said the payload starts, for a `push`.
    payload_offset: usize = 0,
    /// The byte ranges the provider derived, and the ones the test expects.
    plan: Plan = .{},
    expected: Plan = .{},

    stream: u64 = 0,
    asked: bool = false,
    served: bool = false,
    storage: DecodeStorage = .{},

    /// The byte ranges this request must produce, as the test states them.
    fn expect(job: *Job, ranges: []const blobs.ByteRange) error{TooManySpans}!void {
        if (ranges.len > max_spans) return error.TooManySpans;
        job.expected = .{};
        job.expected.len = ranges.len;
        for (ranges, 0..) |range, index| job.expected.ranges[index] = range;
    }

    fn spec(job: *const Job) range_spec.RangeSpec {
        return .{ .widths = job.widths };
    }
};

/// Scratch a blobs decode borrows into.
///
/// The arrays are fields rather than constants because a decode writes through
/// them, and `Storage`'s slices have to point at the same memory — so `init`
/// points them at `self` rather than returning one. A `DecodeStorage` that was
/// returned by value and had its slices cut from the local copy left every
/// later decode reading a frame that had already unwound, which a debug build
/// hides and a release build does not.
const DecodeStorage = struct {
    items: [decode_slots]range_spec.Item = @splat(.{ .delta = 0, .spec = .empty }),
    widths: [decode_slots]u64 = @splat(0),
    hashes: [decode_slots][32]u8 = @splat(@splat(0)),
    boundaries: [decode_slots]u64 = @splat(0),
    inner: blobs.Storage = undefined,

    fn init(self: *DecodeStorage) void {
        self.inner = .{
            .items = self.items[0..],
            .widths = self.widths[0..],
            .hashes = self.hashes[0..],
            .boundaries = self.boundaries[0..],
        };
    }
};

/// One stream's received bytes, as a queue a caller may push to and read from
/// but never take the storage of.
///
/// A named type rather than a bare `ArrayList` so the storage cannot escape:
/// `push` and `slice` are the only ways in and out. `Link` used to answer a
/// reader with `list.items` and nothing else, which reads as a handover of the
/// list and is not one — and which is exactly the question `zbc` raised. The
/// answer is a borrow: the map owns the queue and `freeSides` frees it, so
/// `toOwnedSlice` would have been the bug rather than the fix, moving the
/// bytes out from under a map that still held the entry.
///
/// The count a reader sees is the count `push` advanced, never the room behind
/// it. `std.ArrayList` holds `items` as `ptr[0..len]` with `len` the written
/// count and keeps the allocation's length in a field of its own
/// (`lib/std/array_list.zig:31-35`); `allocatedSlice` at `:534` is what hands
/// back the room, and the comment above it says exactly that. So `room` and
/// `slice().len` are two different numbers and the test at the bottom of this
/// file is what holds them apart.
const StreamBytes = struct {
    queued: std.ArrayList(u8) = .empty,

    /// A queue holding nothing, which is what a `getOrPut` that missed leaves
    /// to be written to. Named so the two call sites say the same thing.
    const empty: StreamBytes = .{};

    fn deinit(self: *StreamBytes) void {
        self.queued.deinit(t.allocator);
    }

    fn push(self: *StreamBytes, chunk: []const u8) !void {
        try self.queued.appendSlice(t.allocator, chunk);
    }

    /// The bytes written so far.
    fn slice(self: *const StreamBytes) []const u8 {
        return self.queued.items;
    }

    /// How many more bytes fit without a reallocation. Never the count.
    fn room(self: *const StreamBytes) usize {
        return self.queued.capacity;
    }
};

/// The queue one side's copy of a stream sits in, or null for a stream that
/// has arrived nothing.
///
/// Null and an empty slice are two different answers and both are wanted: the
/// first says the stream is not in the map and the second says it is and
/// carried nothing, and a stall report that cannot tell them apart is a stall
/// report that has to be reproduced before it can be read.
fn queueOf(
    bytes: *const std.AutoHashMap(u64, StreamBytes),
    stream: u64,
) ?*const StreamBytes {
    return bytes.getPtr(stream);
}

/// The bytes a side has read off one stream, borrowed, or the empty slice.
fn received(
    bytes: *const std.AutoHashMap(u64, StreamBytes),
    stream: u64,
) []const u8 {
    const queued = queueOf(bytes, stream) orelse return &.{};
    return queued.slice();
}

/// Free every queue a side accumulated, before the map that holds them goes.
fn freeSides(map: *std.AutoHashMap(u64, StreamBytes)) void {
    var it = map.valueIterator();
    while (it.next()) |queued| queued.deinit();
}

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

/// The two endpoints a blobs transfer needs: a provider that has the bytes and
/// a getter that does not, one connection, one round loop.
const Link = struct {
    getter: Wire,
    provider: Wire,
    store: Store,
    jobs: [max_jobs]Job = @splat(.{ .name = "unused" }),
    now: u64 = start_ns,

    /// What the provider read off each stream, and whether each saw its FIN.
    provider_bytes: std.AutoHashMap(u64, StreamBytes),
    provider_fin: std.AutoHashMap(u64, bool),
    getter_bytes: std.AutoHashMap(u64, StreamBytes),
    getter_fin: std.AutoHashMap(u64, bool),

    /// The `push` arm's length-prefixed body scratch, which `Request.write`
    /// needs because a varint length cannot be backpatched once its width is
    /// known.
    body: [request_room]u8 = undefined,
    /// Scratch the getter decodes an `observe` run into. Separate from every
    /// job's, because the run's items are compared after the run is over and
    /// the job's storage belongs to the provider.
    seen: DecodeStorage = .{},

    /// The connection the getter's dial opened, held so the assertions can read
    /// the identity the pin produced off the handshake.
    dialled: Conn,

    fn init(link: *Link) !void {
        const store = try Store.init(t.allocator);
        errdefer store.deinit(t.allocator);
        link.* = .{
            .getter = undefined,
            .provider = undefined,
            .store = store,
            .provider_bytes = .init(t.allocator),
            .provider_fin = .init(t.allocator),
            .getter_bytes = .init(t.allocator),
            .getter_fin = .init(t.allocator),
            .dialled = undefined,
        };
        link.seen.init();
        for (&link.jobs) |*job| job.storage.init();
        errdefer link.deinitBuffers();
        // Both ends pin the other, because a pair has one peer and
        // `Bridge.Config.expect_peer` is a value rather than a list.
        const getter_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
        const provider_seed: [SecretKey.seed_length]u8 = @splat(0xc2);
        var getter_secret = try SecretKey.fromSeed(getter_seed);
        var provider_secret = try SecretKey.fromSeed(provider_seed);
        // Both wires *copy* their key: `Wire.init` keeps it in `self.secret`,
        // and the bridge and the dialer each derive their own seed bytes from
        // the `Config` they are handed. These two stack copies are therefore
        // the ones no owner shares, which makes `defer` — not `errdefer` —
        // their guard.
        defer getter_secret.deinit();
        defer provider_secret.deinit();
        try link.getter.init("getter", getter_secret, null, blobs.alpn, 31);
        // From here each wire owns a socket, a bridge, a dialer, an address map
        // and four buffers, so every step below unwinds through the wires that
        // are already up.
        errdefer link.getter.deinit();
        try link.provider.init(
            "provider",
            provider_secret,
            getter_secret.nodeId(),
            blobs.alpn,
            32,
        );
        errdefer link.provider.deinit();
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

    /// Put a job on the link and point its decode storage at its own arrays.
    ///
    /// Assigning a `Job` wholesale replaces the storage, so this is where the
    /// slices get pointed again; a decode through a `Storage` whose arrays are
    /// not the ones it names reads whatever is in a frame that has unwound.
    fn put(link: *Link, index: usize, job: Job) void {
        link.jobs[index] = job;
        link.jobs[index].storage.init();
    }

    fn deinitBuffers(link: *Link) void {
        freeSides(&link.provider_bytes);
        freeSides(&link.getter_bytes);
        link.provider_fin.deinit();
        link.provider_bytes.deinit();
        link.getter_fin.deinit();
        link.getter_bytes.deinit();
    }

    fn deinit(link: *Link) void {
        link.deinitBuffers();
        link.store.deinit(t.allocator);
        link.provider.deinit();
        link.getter.deinit();
    }

    /// One round: the clock moves, both sides take and flush, both sides drain
    /// their streams, and the provider answers whatever has arrived whole.
    fn round(link: *Link) !bool {
        link.now += quantum;
        const at: Instant = @intCast(link.now);
        var moved = try link.getter.exchange(at);
        moved = (try link.provider.exchange(at)) or moved;
        moved = (try link.drain(&link.getter, &link.getter_bytes, &link.getter_fin)) or moved;
        moved = (try link.drain(&link.provider, &link.provider_bytes, &link.provider_fin)) or moved;
        moved = (try link.serve()) or moved;
        return moved;
    }

    /// Copy every stream's readable bytes into a buffer per stream, and note
    /// which streams have seen their FIN.
    ///
    /// `allReceived` rather than `fin_received` alone: a FIN behind a hole is
    /// not the end of the stream, and treating it as one is how a `get` decodes
    /// a truncated request instead of waiting for the rest of it.
    fn drain(
        _: *Link,
        side: *Wire,
        bytes: *std.AutoHashMap(u64, StreamBytes),
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
                // The same handover `Wire.take` uses: the append is what
                // copies, and the chunk is the caller's from the `try` on.
                defer t.allocator.free(chunk);
                moved = true;
                try gop.value_ptr.push(chunk);
            }
            if (stream.recv.allReceived()) try fin.put(id, true);
        }
        return moved;
    }

    fn finished(
        _: *Link,
        fin: *const std.AutoHashMap(u64, bool),
        stream: u64,
    ) bool {
        return fin.get(stream) orelse false;
    }

    // -- the getter's half --------------------------------------------------

    /// The `Request` a job puts on the wire.
    ///
    /// The `get` and `push` bodies carry a one-pair sequence, and it borrows an
    /// array the caller owns, so it is built and encoded in the same call:
    /// nothing that outlives the frame keeps a pointer into it.
    fn buildRequest(
        job: *const Job,
        items: *[1]range_spec.Item,
        hash: [32]u8,
    ) blobs.Request {
        items[0] = .{ .delta = 0, .spec = job.spec() };
        return switch (job.kind) {
            .get => if (job.whole)
                .{ .to_eof = .{ .get = blobs.GetRequest.blob(hash) } }
            else
                .{ .to_eof = .{ .get = .{
                    .hash = hash,
                    .ranges = .{ .items = items[0..] },
                } } },
            .observe => .{ .to_eof = .{ .observe = .{
                .hash = hash,
                .ranges = job.spec(),
            } } },
            .push => .{ .length_prefixed = .{
                .request = blobs.PushRequest.new(hash, .{ .items = items[0..] }),
            } },
        };
    }

    /// Open a stream for `job`, write its request, and close the send side.
    fn ask(link: *Link, job: *Job) !void {
        const stream = try link.dialled.entry.conn.openStream();
        job.stream = stream.stream_id;
        var items: [1]range_spec.Item = undefined;
        var writer = postcard.Writer.init(&job.frame);
        try buildRequest(job, &items, link.store.hash).write(&writer, &link.body);
        job.frame_len = writer.finish().len;
        try stream.send.writeData(job.frame[0..job.frame_len]);
        // A `push` is the one request with bytes behind it, and they are on the
        // same stream: that is what `LengthPrefixedFraming` exists to make
        // unambiguous, and it is why the payload is written here rather than
        // after the provider has answered.
        if (job.kind == .push) try stream.send.writeData(link.store.payload);
        // The `to_eof` framing is the whole stream, and the `push` framing is
        // the stream minus its payload, so both are closed by a FIN and not by
        // a length.
        stream.send.close();
        job.asked = true;
    }

    // -- the provider's half ------------------------------------------------

    /// Answer every job whose request has arrived whole and has not been
    /// answered yet.
    fn serve(link: *Link) !bool {
        var moved = false;
        for (&link.jobs) |*job| {
            if (job.served or !job.asked) continue;
            if (!link.finished(&link.provider_fin, job.stream)) continue;
            const conn = link.provider.bridge.connectionAt(0) orelse continue;
            // The request as it came off the socket, decoded by the one reader
            // `Request.read` dispatches to.
            var reader = postcard.Reader.init(received(&link.provider_bytes, job.stream));
            job.seen = try blobs.Request.read(&reader, &job.storage.inner);
            const stream = conn.entry.conn.streams.getStream(job.stream) orelse
                return error.NoStream;
            job.served = true;
            moved = true;
            switch (job.seen.?) {
                .to_eof => |request| {
                    // The `to_eof` rule, and it applies to that arm alone: the
                    // request is the whole stream, so a byte after it is a
                    // stream that carried something else.
                    try reader.finish();
                    switch (request) {
                        .get => |get| {
                            try planSpec(&job.plan, specOf(get), link.store);
                            try link.writeAnswer(job, stream);
                        },
                        .observe => |observe| {
                            try planSpec(&job.plan, observe.ranges, link.store);
                            try link.writeObserve(job, stream);
                        },
                        .get_many => return error.GetManyUnsupported,
                    }
                },
                .length_prefixed => |framed| {
                    // No `finish` here, and that is the whole difference
                    // between the two framings: the reader is left on the
                    // payload, and that is where the bao data starts.
                    job.payload_offset = framed.payload_offset;
                    stream.send.close();
                },
            }
        }
        return moved;
    }

    /// The bao data of a `get`: the planned ranges, in order, and nothing else.
    fn writeAnswer(link: *Link, job: *Job, stream: anytype) !void {
        if (!job.empty) {
            var budget = job.truncate_to orelse std.math.maxInt(usize);
            for (job.plan.ranges[0..job.plan.len]) |range| {
                if (budget == 0) break;
                const take = @min(budget, range.end - range.start);
                try stream.send.writeData(link.store.bytes[range.start .. range.start + take]);
                budget -= take;
            }
        }
        stream.send.close();
    }

    /// A run of `ObserveItem`s: what the provider has, as a `ChunkRangeSet`.
    ///
    /// Length-prefixed, because a run has no other boundary — the same
    /// `write_length_prefixed` a `push` request is written with, and for the
    /// same reason. The body goes into its own buffer rather than being built
    /// inside the frame, because the two must not be the same bytes.
    fn writeObserve(link: *Link, job: *Job, stream: anytype) !void {
        var body_room: [observe_room]u8 = undefined;
        var framed_room: [observe_room]u8 = undefined;
        var body = postcard.Writer.init(&body_room);
        const item: blobs.ObserveItem = .{
            .size = link.store.bytes.len,
            .ranges = .{ .boundaries = job.plan.boundariesSlice() },
        };
        try item.write(&body);
        const framed = body.finish();
        var writer = postcard.Writer.init(&framed_room);
        try writer.writeU64(framed.len);
        @memcpy(writer.buffer[writer.length..][0..framed.len], framed);
        writer.length += framed.len;
        try stream.send.writeData(writer.finish());
        stream.send.close();
    }

    // -- the report ---------------------------------------------------------

    /// What a stall has to say. It names the request, the range and the byte
    /// count, because a stall without all three is a stall that has to be
    /// reproduced before it can be read.
    fn report(link: *Link, reason: []const u8) void {
        std.debug.print("\nblobs transfer stalled: {s}\n", .{reason});
        for (&link.jobs) |*job| {
            if (std.mem.eql(u8, job.name, "unused")) continue;
            std.debug.print(
                "  {s}: {t} {f} on stream {d}\n",
                .{ job.name, job.kind, job.spec(), job.stream },
            );
            std.debug.print("    plan:", .{});
            for (job.plan.ranges[0..job.plan.len]) |range| {
                std.debug.print(" [{d},{d})", .{ range.start, range.end });
            }
            std.debug.print(
                " ({d} bytes), asked {}, answered {}\n",
                .{ job.plan.total(), job.asked, job.served },
            );
            const got = received(&link.getter_bytes, job.stream);
            std.debug.print(
                "    {d} of {d} bytes arrived, fin {}\n",
                .{ got.len, job.expected.total(), link.finished(&link.getter_fin, job.stream) },
            );
        }
        for (0..2) |which| {
            const side: *Wire = if (which == 0) &link.getter else &link.provider;
            std.debug.print(
                "  {s} ({f}) at {f}: {d} datagrams out, {d} in," ++
                    " {d} runs in {d} sends, widest {d}, {d} segmented," ++
                    " {d} finished, {d} ecn dropped\n",
                .{
                    side.name,
                    side.id,
                    side.socket.address,
                    side.stats.out,
                    side.stats.in,
                    side.stats.runs,
                    side.stats.sends,
                    side.stats.widest,
                    side.stats.segmented,
                    side.stats.finished,
                    side.stats.dropped_ecn,
                },
            );
        }
        std.debug.print("  virtual time {d} ms; round bound {d}\n", .{
            link.now / std.time.ns_per_ms,
            max_rounds,
        });
    }
};

/// Run rounds until `goal` holds, or until the bound is reached.
fn drive(link: *Link, phase: []const u8, goal: fn (*Link) bool) !void {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        if (goal(link)) return;
        _ = try link.round();
    }
    if (goal(link)) return;
    link.report(phase);
    return error.Stalled;
}

fn handshaken(link: *Link) bool {
    const accepted = link.provider.bridge.connectionAt(0) orelse return false;
    return link.dialled.established() and accepted.established();
}

fn allServed(link: *Link) bool {
    for (&link.jobs) |*job| {
        if (std.mem.eql(u8, job.name, "unused")) continue;
        if (!job.served) return false;
    }
    return true;
}

fn allComplete(link: *Link) bool {
    for (&link.jobs) |*job| {
        if (std.mem.eql(u8, job.name, "unused")) continue;
        if (!link.finished(&link.getter_fin, job.stream)) return false;
    }
    return true;
}

/// The two ends proved who they are to each other by the handshake, not by the
/// configuration.
fn checkIdentity(link: *Link) !void {
    const getter_conn = link.dialled;
    const provider_conn = link.provider.bridge.connectionAt(0) orelse
        return error.NoConnection;
    if (!getter_conn.established() or !provider_conn.established()) {
        link.report("the blobs handshake did not finish");
        return error.Stalled;
    }
    try t.expectEqual(
        link.provider.id.toBytes(),
        getter_conn.entry.conn.tls13_hs.?.peerNodeId().?,
    );
    try t.expectEqual(
        link.getter.id.toBytes(),
        provider_conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(blobs.alpn, getter_conn.entry.conn.negotiatedAlpn());
}

// ---------------------------------------------------------------------------
// What a getter does with what arrived
// ---------------------------------------------------------------------------

/// The answer on one stream, as `BaoResponse` reads it: everything that is
/// left, which is the whole of what a `get`'s answer is.
fn answerOf(link: *Link, job: *Job) blobs.BaoResponse {
    var reader = postcard.Reader.init(received(&link.getter_bytes, job.stream));
    return blobs.BaoResponse.read(&reader);
}

/// Whether an answer is the whole of what was asked for.
///
/// A content comparison and not a length: a transfer that silently truncates
/// hands back a short buffer, and comparing what arrived against what was read
/// rather than against what was asked for would make that pass. This is the
/// predicate a caller would write, and the truncating test asserts it is false.
fn covers(store: Store, plan: Plan, answer: blobs.BaoResponse) bool {
    var at: usize = 0;
    for (plan.ranges[0..plan.len]) |range| {
        const want = store.bytes[range.start..range.end];
        if (answer.bytes.len < at + want.len) return false;
        if (!std.mem.eql(u8, want, answer.bytes[at .. at + want.len])) return false;
        at += want.len;
    }
    return at == answer.bytes.len;
}

// ---------------------------------------------------------------------------
// Test 1: a whole blob, by content, across a segmented send
// ---------------------------------------------------------------------------

test "a whole blob crosses a real socket, and the send seam segments it" {
    var link: Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // The ephemeral ports are two distinct numbers on the loopback, which is
    // what says neither end dialled itself.
    try t.expect(link.getter.socket.address.port != link.provider.socket.address.port);
    try t.expect(link.getter.socket.address.port != 0);
    try t.expect(link.provider.socket.address.port != 0);

    const job = &link.jobs[0];
    link.put(0, .{ .name = "whole blob", .kind = .get, .whole = true });
    try job.expect(&.{.{ .start = 0, .end = link.store.bytes.len }});
    try link.ask(job);
    try drive(&link, "the whole-blob request never arrived whole", allServed);
    try drive(&link, "the whole blob never finished arriving", allComplete);

    // ── the request survived the socket ──
    try t.expectEqual(blobs.RequestType.get, job.seen.?.discriminant());
    const get = switch (job.seen.?) {
        .to_eof => |request| switch (request) {
            .get => |value| value,
            else => return error.NotAGet,
        },
        .length_prefixed => return error.NotAnEofRequest,
    };
    try t.expectEqualSlices(u8, &blob_hash, &get.hash);
    // The plan came from the decoded sequence rather than from the test's
    // widths, so this is the range algebra the wire carried: one selected span
    // over every chunk, cut at the blob's real length because the last chunk is
    // short.
    try t.expectEqual(@as(usize, 1), job.plan.len);
    try t.expectEqual(job.expected.ranges[0], job.plan.ranges[0]);
    try t.expectEqual(@as(u64, 0), job.plan.boundaries[0]);
    try t.expectEqual(link.store.chunkCount(), job.plan.boundaries[1]);

    // ── the bytes arrived, and they are the blob ──
    const answer = answerOf(&link, job);
    try t.expect(!answer.isEof());
    try t.expect(covers(link.store, job.expected, answer));
    // The content assertion, spelled out rather than folded into `covers`, so a
    // failure names the transfer and not only the predicate.
    try t.expectEqualSlices(u8, link.store.bytes, answer.bytes);
    // And the stream ended, with no reset behind it: `protocol.zig` has no
    // error frame, and a reset is what one would have cost this layer.
    const stream = link.dialled.entry.conn.streams.getStream(job.stream).?;
    try t.expect(stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), stream.recv.reset_err);

    // ── the send seam segmented the transfer ──
    //
    // The seam's own capability, asserted rather than assumed: a socket that
    // could not segment would make every count below true in a way that says
    // nothing about segmentation.
    try t.expect(link.provider.socket.caps.supportsSegmentation());
    const sent = link.provider.stats;
    // More than one packet, and more than one GSO batch's worth of them.
    try t.expect(sent.datagrams > 1);
    try t.expect(sent.datagrams > batch.max_segments_linux);
    // `UDP_SEGMENT` went on the wire rather than merely being available.
    try t.expect(sent.segmented > 0);
    // And the batching ran off the end of what one `sendmsg` may carry, which
    // is what "crosses the batch boundary" means. The widest batch on this
    // transfer is 80 datagrams of 1200 bytes, above both `max_segments_linux`
    // and what one datagram can carry at that segment size, so `batch.Runs` had
    // to cut it: 10 sends became 12 socket writes, and 54 segments plus 26 is
    // the cut at this size.
    try t.expect(sent.widest > batch.max_segments_linux);
    try t.expect(sent.runs > sent.sends);
}

// ---------------------------------------------------------------------------
// Test 2: partial ranges
// ---------------------------------------------------------------------------

test "disjoint ranges and a whole blob return exactly the bytes asked for" {
    var link: Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // The unaligned request, stated in bytes and derived in chunks: the two are
    // not the same question, and the conversion between them is the point. 5000
    // is inside chunk 4 and 20000 is inside chunk 19, so the outward rounding
    // asks for chunks 4 through 20 and the answer is bytes 4096 through 20480
    // — which is what the assertions below say, and not 5000.
    const unaligned = blobs.ByteRange{ .start = 5000, .end = 20000 };
    try t.expectEqual(blobs.ChunkRange{ .start = 4, .end = 20 }, blobs.bytesToChunks(unaligned));
    const unaligned_widths = [_]u64{ 4, 16 };

    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    const unaligned_expected = [_]blobs.ByteRange{.{ .start = 4096, .end = 20480 }};
    const tail_expected = [_]blobs.ByteRange{
        .{ .start = 254 * 1024, .end = link.store.bytes.len },
    };
    const whole_expected = [_]blobs.ByteRange{.{ .start = 0, .end = link.store.bytes.len }};

    link.put(0, .{ .name = "two disjoint ranges", .widths = &disjoint_widths });
    link.put(1, .{ .name = "an unaligned byte range", .widths = &unaligned_widths });
    link.put(2, .{ .name = "the short last chunk", .widths = &tail_widths });
    link.put(3, .{ .name = "availability", .kind = .observe, .widths = &disjoint_widths });
    link.put(4, .{ .name = "whole blob", .whole = true });
    const jobs = 5;
    try link.jobs[0].expect(&disjoint_expected);
    try link.jobs[1].expect(&unaligned_expected);
    try link.jobs[2].expect(&tail_expected);
    try link.jobs[4].expect(&whole_expected);

    for (0..jobs) |index| try link.ask(&link.jobs[index]);
    try drive(&link, "a range request never arrived whole", allServed);
    try drive(&link, "a range answer never finished arriving", allComplete);

    // ── the provider planned from what it decoded ──
    //
    // Checked before the content, because a plan that is wrong and a store that
    // is wrong can produce the same bytes, and this says which of the two it
    // was. The decoded request is re-encoded into a buffer of its own and
    // compared against the getter's bytes: the two sides are the frame that
    // went out and the frame that came back, not one buffer against itself.
    for (0..jobs) |index| {
        const job = &link.jobs[index];
        try t.expectEqual(job.kind.discriminant(), job.seen.?.discriminant());
        var check: [request_room]u8 = undefined;
        var writer = postcard.Writer.init(&check);
        try job.seen.?.write(&writer, &link.body);
        try t.expectEqualSlices(u8, job.frame[0..job.frame_len], writer.finish());
        // The request's own ranges, read back out of the storage it was decoded
        // into. And that the decoded sequence borrows that storage, which is a
        // claim about an address and so is checked as one: a decode through a
        // `Storage` that was copied out of its own struct reads whatever is in
        // a dead frame now, and a debug build is the only reason that can look
        // like it worked.
        const get: ?blobs.GetRequest = switch (job.seen.?) {
            .to_eof => |request| switch (request) {
                .get => |value| value,
                .observe, .get_many => null,
            },
            .length_prefixed => null,
        };
        if (get) |value| {
            try t.expectEqualSlices(u8, &blob_hash, &value.hash);
            try t.expectEqual(
                @intFromPtr(&job.storage.items[0]),
                @intFromPtr(value.ranges.items.ptr),
            );
        }
        const spec = try requestSpec(job);
        if (job.whole) {
            // The module's own whole-blob sequence: one selected spec and the
            // terminator that stops the walk. Its spec is `RangeSpec.all`,
            // which is not the empty width list a job built from widths would
            // carry — which is why this is not a comparison against `widths`.
            try t.expect(spec.isAll());
        } else {
            try t.expectEqualSlices(u64, job.widths, spec.widths);
        }
    }

    // The disjoint spec is two selected runs with a gap either side, so the
    // answer is two runs and not one.
    try t.expectEqual(@as(usize, 2), link.jobs[0].plan.len);
    try t.expectEqual(disjoint_expected[0], link.jobs[0].plan.ranges[0]);
    try t.expectEqual(disjoint_expected[1], link.jobs[0].plan.ranges[1]);
    // The unaligned request came back on chunk boundaries, wider than the byte
    // range it was asked for at the start and narrower at the end: outward at
    // both ends, which is the conversion's whole asymmetry.
    try t.expectEqual(unaligned_expected[0], link.jobs[1].plan.ranges[0]);
    // The last chunk is short, so the range that ends in it is clipped to the
    // blob's real length rather than to 257 whole chunks: 2748 bytes where the
    // chunk arithmetic alone says 3072.
    try t.expectEqual(tail_expected[0], link.jobs[2].plan.ranges[0]);
    const tail_span = link.jobs[2].plan.ranges[0];
    try t.expectEqual(@as(usize, 2748), tail_span.end - tail_span.start);
    // The whole blob is one span, and it is clipped at the same place.
    try t.expectEqual(whole_expected[0], link.jobs[4].plan.ranges[0]);

    // ── and the bytes are exactly those ranges ──
    for (0..jobs) |index| {
        const job = &link.jobs[index];
        if (job.kind == .observe) continue;
        const answer = answerOf(&link, job);
        try t.expect(!answer.isEof());
        try t.expect(covers(link.store, job.expected, answer));
        // Spelled out, span by span, so a failure says which range is wrong.
        var at: usize = 0;
        for (job.expected.ranges[0..job.expected.len]) |range| {
            const want = link.store.bytes[range.start..range.end];
            try t.expectEqualSlices(u8, want, answer.bytes[at .. at + want.len]);
            at += want.len;
        }
        const stream = link.dialled.entry.conn.streams.getStream(job.stream).?;
        try t.expect(stream.recv.allReceived());
        try t.expectEqual(@as(?u64, null), stream.recv.reset_err);
    }

    // ── `ChunkRangeSet`, over the same socket ──
    //
    // The availability the provider reported is a boundary list, and it is the
    // only description of the answer the getter gets. The byte ranges are
    // derived from it, chunks to bytes, with the clip a short last chunk needs,
    // so a getter that read the boundaries wrong gets ranges that do not match
    // the `get` above.
    {
        const job = &link.jobs[3];
        var reader = postcard.Reader.init(received(&link.getter_bytes, job.stream));
        var run = blobs.ObserveResponse.read(&reader, &link.seen.inner);
        const item = (try run.next()) orelse return error.NoObserveItem;
        try t.expectEqual(link.store.bytes.len, item.size);
        try t.expectEqualSlices(u64, &.{ 2, 5, 9, 14 }, item.ranges.boundaries);
        // And the run ends between items, which is a `null` rather than an
        // error: an observe answer is a run to the end of its stream.
        try t.expect(try run.next() == null);
        try t.expect(link.finished(&link.getter_fin, job.stream));

        // The ranges those boundaries name, read against the size that came
        // with them — the other direction of the conversion, and the getter's.
        const derived = planFromBoundaries(item.ranges.boundaries, item.size);
        try t.expectEqual(@as(usize, 2), derived.len);
        try t.expectEqual(disjoint_expected[0], derived.ranges[0]);
        try t.expectEqual(disjoint_expected[1], derived.ranges[1]);
        // And the answer to the `get` on those same ranges is what the
        // boundaries promised, which is the last of the algebra end to end.
        try t.expect(covers(link.store, derived, answerOf(&link, &link.jobs[0])));
    }
}

// ---------------------------------------------------------------------------
// Test 3: the two framings, on the wire
// ---------------------------------------------------------------------------

test "a push body cannot be read as a get body, on the wire" {
    var link: Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // A `push` carrying a partial range request and a kilobyte of bao data
    // behind it, and a `get` for the same partial ranges, both on their own
    // streams. The two frames are the ones the confusion is about: a
    // `PushRequest` is a newtype over a `GetRequest`, so the bodies are the
    // same shape and only the byte in front and the framing behind it differ.
    link.put(0, .{ .name = "push with a payload", .kind = .push, .widths = &disjoint_widths });
    link.put(1, .{ .name = "partial get", .kind = .get, .widths = &disjoint_widths });
    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    try link.jobs[1].expect(&disjoint_expected);

    try link.ask(&link.jobs[0]);
    try link.ask(&link.jobs[1]);
    try drive(&link, "a framed request never arrived whole", allServed);
    try drive(&link, "a framed stream never finished", allComplete);

    const push = &link.jobs[0];
    const get = &link.jobs[1];

    // ── the push arrived as a `push`, and its payload is behind it ──
    try t.expectEqual(blobs.RequestType.push, push.seen.?.discriminant());
    const framed = switch (push.seen.?) {
        .length_prefixed => |value| value,
        .to_eof => return error.PushReadAsEof,
    };
    const received_push = received(&link.provider_bytes, push.stream);
    // The payload is the kilobyte the getter wrote and not a byte of the
    // request: it starts where the decode said it starts, and the getter's
    // frame was exactly that many bytes.
    try t.expectEqual(push.frame_len, push.payload_offset);
    try t.expectEqual(received_push.len, push.frame_len + link.store.payload.len);
    {
        // Decoded again from the bytes that came off the socket, because the
        // property is about where a decode leaves its reader and not about
        // what a second call on an already-consumed one returns.
        var reader = postcard.Reader.init(received_push);
        const again = try blobs.Request.read(&reader, &push.storage.inner);
        try t.expectEqualSlices(u8, link.store.payload, again.payload(&reader));
        // The reader is left *on* the payload, not past it: the request is
        // over and the bao data has not started being consumed.
        try t.expectEqual(push.payload_offset, reader.offset);
    }
    // And the request's own ranges came through: a push is not restricted to a
    // whole blob, so the sequence is the disjoint one rather than `blob`'s.
    try t.expectEqualSlices(
        u64,
        &disjoint_widths,
        framed.request.get.ranges.items[0].spec.widths,
    );
    // A `to_eof` request has no payload at all, which the type says rather than
    // leaving the caller to know which framing it was handed.
    {
        var reader = postcard.Reader.init(received(&link.provider_bytes, get.stream));
        try t.expectEqualSlices(u8, "", get.seen.?.payload(&reader));
    }
    // The `get` on the same ranges got the bytes, which says the push did not
    // eat the connection and the framing is per stream.
    try t.expect(covers(link.store, get.expected, answerOf(&link, get)));

    // ── the confusion the two types exist to prevent ──
    //
    // A `push` body read as a `get` body. The discriminant says `push` and the
    // framing that carries it is length-prefixed, so the payload is not
    // swallowed into the request. Point the decoder at the other framing and it
    // is told so before it reads a byte of the body.
    {
        var reader = postcard.Reader.init(received_push[1..]);
        try t.expectError(
            error.WrongFraming,
            blobs.EofFraming.read(.push, &reader, &push.storage.inner),
        );
    }
    // The same body as a `get` frame, on its own and with the payload behind
    // it. The first is a request; the second is not one, and the `to_eof` rule
    // is what says so — the request is the whole stream, so a byte after it
    // cannot be part of it. This is the confusion in one comparison, and both
    // halves are the push's own bytes rather than a frame this file invented.
    {
        var clean_frame: [request_room]u8 = undefined;
        var clean_writer = postcard.Writer.init(&clean_frame);
        try clean_writer.writeU8(@intFromEnum(blobs.RequestType.get));
        try framed.request.write(&clean_writer);
        const clean_bytes = clean_writer.finish();
        // `EofFraming.read` takes the *body*: the discriminant is read by
        // `Request.read`, which is the one reader that chooses between the two
        // framings. Handing it the body is the point of the type, and handing
        // it a frame is a different call.
        var clean_storage: DecodeStorage = .{};
        clean_storage.init();
        {
            var clean_reader = postcard.Reader.init(clean_bytes[1..]);
            const clean = try blobs.EofFraming.read(.get, &clean_reader, &clean_storage.inner);
            try t.expectEqual(blobs.RequestType.get, clean.discriminant());
            try t.expectEqualSlices(u8, &blob_hash, &clean.get.hash);
            try t.expectEqualSlices(
                u64,
                &disjoint_widths,
                clean.get.ranges.items[0].spec.widths,
            );
        }
        {
            var wide: [request_room + payload_length]u8 = undefined;
            @memcpy(wide[0..clean_bytes.len], clean_bytes);
            @memcpy(
                wide[clean_bytes.len..][0..link.store.payload.len],
                link.store.payload,
            );
            const all = clean_bytes.len + link.store.payload.len;
            var reader = postcard.Reader.init(wide[1..all]);
            try t.expectError(
                error.TrailingBytes,
                blobs.EofFraming.read(.get, &reader, &clean_storage.inner),
            );
        }
    }
    // And the *received* frame with its discriminant byte changed, which is
    // what a peer that ignored the byte in front would decode. The length byte
    // the `push` framing put there is now the hash's first byte, so the whole
    // body shifts and the sequence's element count is read out of hash bytes:
    // it names more pairs than any caller's storage holds, and the answer is
    // `BufferFull` — a named refusal and never a request that quietly includes
    // the payload. (`protocol.zig` reports `BadLength` from the same step on
    // its own captured hash; which named error it is depends on the bytes, and
    // that it is an error rather than a request does not.)
    {
        var swapped: [request_room + payload_length]u8 = undefined;
        @memcpy(swapped[0..received_push.len], received_push);
        swapped[0] = @intFromEnum(blobs.RequestType.get);
        var reader = postcard.Reader.init(swapped[1..]);
        try t.expectError(
            error.BufferFull,
            blobs.EofFraming.read(.get, &reader, &push.storage.inner),
        );
    }
    // And a `get` frame is not a `push` frame: with the byte in front changed,
    // the hash's first byte is the declared body length. 0x5a is a one-byte
    // varint for ninety, and the frame has thirty-seven bytes left of it.
    {
        const received_get = received(&link.provider_bytes, get.stream);
        var swapped: [request_room]u8 = undefined;
        @memcpy(swapped[0..received_get.len], received_get);
        swapped[0] = @intFromEnum(blobs.RequestType.push);
        var reader = postcard.Reader.init(swapped[0..received_get.len]);
        try t.expectError(
            error.UnexpectedEnd,
            blobs.Request.read(&reader, &push.storage.inner),
        );
        // And the framing that carries a `push` refuses a `get` before it
        // reads a byte, as `EofFraming` refuses a `push` above: neither is a
        // value of the other, and `Request.read` is the only reader that gets
        // to choose.
        var get_reader = postcard.Reader.init(received_get[1..]);
        try t.expectError(
            error.WrongFraming,
            blobs.LengthPrefixedFraming.read(.get, &get_reader, &push.storage.inner),
        );
    }
    // Both streams ended with a FIN and no reset, which is what a request that
    // ran to the end of its stream looks like and what a payload that stayed
    // behind the request looks like from the far end.
    try t.expect(link.finished(&link.getter_fin, push.stream));
    try t.expect(link.finished(&link.getter_fin, get.stream));
}

// ---------------------------------------------------------------------------
// Test 4: a short answer is not a complete one
// ---------------------------------------------------------------------------

test "a truncated answer is not a complete transfer, and no answer is EOF" {
    var link: Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // A provider that stops part way through the blob and closes, and a
    // provider that has nothing at all. Both are answers the getter has to tell
    // apart from a whole one, and one of them alone proves nothing: an empty
    // answer is the success the other artifact covers, and a short one is the
    // failure this one is for.
    const whole_expected = [_]blobs.ByteRange{.{ .start = 0, .end = link.store.bytes.len }};
    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    link.put(0, .{
        .name = "truncated after 1000 bytes",
        .whole = true,
        .truncate_to = truncated_at,
    });
    link.put(1, .{
        .name = "a provider with nothing",
        .widths = &disjoint_widths,
        .empty = true,
    });
    try link.jobs[0].expect(&whole_expected);
    try link.jobs[1].expect(&disjoint_expected);

    try link.ask(&link.jobs[0]);
    try link.ask(&link.jobs[1]);
    try drive(&link, "a truncation request never arrived whole", allServed);
    try drive(&link, "a truncated answer never finished arriving", allComplete);

    // ── the short answer ──
    const cut = &link.jobs[0];
    const wanted = cut.expected.total();
    const answer = answerOf(&link, cut);
    // It is not EOF: bytes arrived, and `protocol.zig` has no value that could
    // say "this is where the transfer stopped".
    try t.expect(!answer.isEof());
    // The stream ended anyway, and ended cleanly: a FIN and no reset, which is
    // the whole of the evidence the getter has.
    const stream = link.dialled.entry.conn.streams.getStream(cut.stream).?;
    try t.expect(stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), stream.recv.reset_err);
    // The bytes that did arrive are the right ones — the transfer is not
    // corrupt, it is short.
    try t.expectEqual(truncated_at, answer.bytes.len);
    try t.expectEqualSlices(u8, link.store.bytes[0..truncated_at], answer.bytes);
    // And it is not a complete transfer. This is the assertion the file is for:
    // a caller that compared what arrived against what it had read rather than
    // against what it asked for would hand this short buffer back as a whole
    // blob, and nothing in `BaoResponse` stops it.
    try t.expect(wanted > answer.bytes.len);
    try t.expect(!covers(link.store, cut.expected, answer));

    // ── the answer that is EOF ──
    const empty = &link.jobs[1];
    const nothing = answerOf(&link, empty);
    try t.expect(nothing.isEof());
    try t.expectEqual(@as(usize, 0), nothing.bytes.len);
    // EOF is a success only where none of the data existed: the getter's
    // completion test is false for it as well, which is the point — the two
    // answers are the same bytes, and the caller has to know which it asked
    // for.
    try t.expect(!covers(link.store, empty.expected, nothing));
    const empty_stream = link.dialled.entry.conn.streams.getStream(empty.stream).?;
    try t.expect(empty_stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), empty_stream.recv.reset_err);
    // The provider still planned the ranges it was asked for before it found it
    // had nothing to send, so the plan is the answer's evidence and it is a
    // real one rather than an empty stand-in.
    try t.expectEqual(@as(usize, 2), empty.plan.len);
    try t.expectEqual(disjoint_expected[0], empty.plan.ranges[0]);
    try t.expectEqual(disjoint_expected[1], empty.plan.ranges[1]);
}

// ---------------------------------------------------------------------------
// Test 5: the count a caller sees
// ---------------------------------------------------------------------------

test "a stream's received count is the count written, below and above its room" {
    var bytes: std.AutoHashMap(u64, StreamBytes) = .init(t.allocator);
    defer {
        freeSides(&bytes);
        bytes.deinit();
    }

    const gop = try bytes.getOrPut(1);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
    const short = [_]u8{ 1, 2, 3 };
    try gop.value_ptr.push(&short);

    // ── below the room ──
    //
    // Three bytes against a room of more than three whatever the allocator's
    // first stop happened to be, so the count and the room cannot coincide and
    // the line below has teeth: an accessor that handed back the room instead
    // of the count fails exactly here and nowhere else in the file.
    try t.expectEqual(@as(usize, short.len), received(&bytes, 1).len);
    try t.expect(gop.value_ptr.room() > gop.value_ptr.slice().len);

    // ── above it ──
    //
    // A quarter of a megabyte behind a room this size, so the queue grew again
    // and again and the count is nothing like the room it started from. Both
    // halves of "well above" are measured: the count clears the room the small
    // answer left, and the room moved because of it.
    const bulk = try t.allocator.alloc(u8, 256 * 1024);
    defer t.allocator.free(bulk);
    for (bulk, 0..) |*byte, index| byte.* = @truncate(index);
    const room_before = gop.value_ptr.room();
    try gop.value_ptr.push(bulk);

    try t.expectEqual(short.len + bulk.len, received(&bytes, 1).len);
    try t.expect(received(&bytes, 1).len > room_before);
    try t.expect(gop.value_ptr.room() > room_before);

    // The count being right while the bytes are not is the other half of this
    // accessor, so the bytes are checked at both ends: the short answer, which
    // is where a count taken from the room would be visibly wrong, and the
    // bulk that followed it.
    const whole = received(&bytes, 1);
    try t.expectEqualSlices(u8, &short, whole[0..short.len]);
    try t.expectEqualSlices(u8, bulk, whole[short.len..]);

    // A stream that never arrived reads as no bytes, and there is no queue to
    // read a room from — which is why `queueOf` answers `?` and `received`
    // answers a slice: the two questions are different and a caller asking for
    // the count of a stream it has never seen should not have to tell them
    // apart.
    try t.expect(queueOf(&bytes, 2) == null);
    try t.expectEqual(@as(usize, 0), received(&bytes, 2).len);
}

// ---------------------------------------------------------------------------
// The boundary at the segment sizes a loopback connection cannot reach
// ---------------------------------------------------------------------------

/// The most bytes one UDP datagram may carry, and the reason the batch
/// boundary is a ratio and not a count.
///
/// `batch.max_segments_linux` is `UDP_MAX_SEGMENTS`, the `1 << 6` of
/// `include/uapi/linux/udp.h`, and it is not the constraint that binds first:
/// a `sendmsg` whose payload is over what a datagram holds is refused with
/// `EMSGSIZE`, and `batch` has no field for a cap that depends on the segment
/// size. Measured on this node with a `UDP_SEGMENT` control message at
/// 1200-byte segments: 54 segments and 64800 bytes go out, 55 and 66000 are
/// refused. At 1024 it is 63 against 64, and at 1500 it is 43 against 44 —
/// three different counts for one constant, which is what "a ratio" means.
///
/// The ceiling itself is 65535 less the 20-byte IPv4 header and the 8-byte UDP
/// one; over IPv6 it is 65527. A `Runs` walk is handed no address and so no
/// family, and of two ceilings the smaller is the one legal on both, so
/// `batch.max_send_payload` is this number. It is written out here rather than
/// read from there on purpose: a test that quoted the model's own constant
/// would follow it up and not notice it move.
const max_datagram_payload: usize = 65507;

/// The datagram sizes the batcher is asked to cut, and the batch sizes around
/// the crossing.
///
/// The transfer above only ever bursts at one of them: the core's, which on
/// loopback is the base PLPMTU and does not move. A fix that holds at 1200 and
/// nowhere else would pass that transfer and regress silently at the rest, so
/// the sizes a connection cannot be made to produce are asserted here instead.
/// 576 is IPv6's minimum MTU, 1200 is what the core sends on loopback and never
/// moves from, 1024 and 1452 bracket it and 9000 is a jumbo frame. 32767 is not
/// an MTU and is here for one reason: `65535 mod 32767` is 1, so a model clamped
/// at 65535 would put two of them in one write — 65534 bytes — and pass every
/// real size in the list, while one clamped at the datagram ceiling cannot. A
/// boundary that no input can cross is not a boundary.
const segment_sizes = [_]usize{ 576, 1024, 1200, 1452, 9000, 32767 };
const batch_sizes = [_]usize{ 1, 2, 7, 54, 55, 63, 64, 65, 200 };

test "a run is within one datagram, at every segment size" {
    for (segment_sizes) |size| {
        for (batch_sizes) |count| {
            const payload = try t.allocator.alloc(u8, size * count);
            defer t.allocator.free(payload);
            @memset(payload, 0x5a);
            // A batch of one datagram carries no segment size, and the seam's
            // own rule is that it must not acquire one here.
            const send = if (count == 1)
                batch.Send.single(payload, null)
            else
                try batch.Send.batch(payload, size, null);
            var runs = try batch.Runs.init(send, batch.Capability.linux_full);
            const promised = runs.count();
            var taken: usize = 0;
            var rejoined: usize = 0;
            while (runs.next()) |run| {
                taken += 1;
                rejoined += run.contents.len;
                // The property the crossing is about: no write may ask for more
                // bytes than one datagram can carry, whatever the segment cap
                // says.
                try t.expect(run.contents.len <= max_datagram_payload);
                // No run is cut inside a datagram, so the runs put the batch
                // back together.
                try t.expectEqual(@as(usize, 0), run.contents.len % size);
                if (run.segment_size) |value| {
                    // A segmented run is the batcher's own, at this batch's own
                    // size, and it is more than one datagram.
                    try t.expectEqual(@as(usize, @intCast(size)), @as(usize, value));
                    try t.expect(run.contents.len > size);
                } else {
                    // And a run of one datagram carries no segment size, which
                    // is the fallback `DECISIONS/0002` promised.
                    try t.expectEqual(@as(usize, 1), run.datagramCount());
                }
            }
            try t.expectEqual(payload.len, rejoined);
            try t.expectEqual(promised, taken);
            // And the batch is still this many datagrams: no run dropped one
            // and none invented one.
            try t.expectEqual(send.datagramCount(), rejoined / size);
        }
    }

    // The crossing is in the table at every one of those sizes, so a model
    // that cut at the segment cap alone fails here rather than passing because
    // no case in it needed a second write.
    const largest = batch_sizes[batch_sizes.len - 1];
    try t.expect(largest > batch.max_segments_linux);
    for (segment_sizes) |size| {
        const payload = try t.allocator.alloc(u8, size * largest);
        defer t.allocator.free(payload);
        @memset(payload, 0x5a);
        var runs = try batch.Runs.init(
            try batch.Send.batch(payload, size, null),
            batch.Capability.linux_full,
        );
        try t.expect(runs.count() > 1);
    }
}
