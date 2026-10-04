//! The stream seam: everything that runs above a datagram.
//!
//! `Conn` reads connection state and `Conn.drain` writes packets, and nothing
//! in between was exposed. A protocol carried *over* a connection — the relay
//! protocol is the one this project has — has to run on a stream, and a caller
//! reaching into `Conn.entry.conn.streams` for one would be a second opinion on
//! the core, which is the thing `quic_bridge.zig` exists to prevent. So the
//! streams are named here, once, and `vendor/quic` is untouched: a stream
//! opens, carries bytes and says when it is done, which is the whole of what a
//! framed protocol over QUIC asks of a transport.
//!
//! # Three kinds, because the core has three
//!
//! RFC 9000 §2.1 splits a stream by who opened it and by whether it has a
//! receive half, and the core keeps the two halves in two maps
//! (`stream.zig:1518-1528`): `streams` for bidirectional, `send_streams` for a
//! locally-opened unidirectional one, `recv_streams` for one the *peer* opened.
//! So there are three wrappers rather than one, and a wrapper that claimed to
//! be "a stream" would be a claim the core cannot honour.
//!
//!   * `Stream` — bidirectional, opened here. Both halves.
//!   * `UniStream` — unidirectional, opened here. Send half only: there is no
//!     `recv` on it to get wrong.
//!   * `RecvUni` — unidirectional, opened by the peer. Receive half only.
//!
//! # Bounded, and what "bounded" means on each side
//!
//! **A `UniStream` write is refused past the credit the peer granted.**
//! `SendStream.writeData` itself is unbounded: it appends to a buffer and lets
//! the packer block, so a caller that writes a megabyte into a stream the peer
//! has not opened a window on has queued a megabyte it cannot send and cannot
//! take back. `UniStream.write` asks `sendCredit` first and answers
//! `error.NoSendCredit`, which is a fact about *now* — the peer's MAX_STREAM_DATA
//! will lift it — and not a fault.
//!
//! **A read is bounded by runs per call, not by bytes.** `drain` takes at most
//! `max_drain_runs` contiguous runs and returns whether it moved any, so a
//! caller can fold "did this pass move anything" into its own answer without a
//! second read, and can drive an empty stream without treating it as a failure.
//!
//! `Stream.write` is *not* bounded, and that is deliberate: it is the relay
//! protocol's write, its peer grants credit for the framed messages it expects,
//! and a bound there would be a change to a working path for no gain. The
//! caller-visible bound on it is `credit`, which is exposed by `UniStream` for
//! exactly that reason.
//!
//! # Who owns which buffer
//!
//! Three owners, and they do not overlap:
//!
//!   * **The write buffer is the core's.** `writeData` copies into it, so
//!     `bytes` may be released the moment `write` returns, and nothing this
//!     file hands back points into it. `buffered` is how much of it is spoken
//!     for and not yet acknowledged.
//!   * **The read sink is the caller's.** `drain` grows it, and `gpa` must be
//!     the allocator the stream was made with — the bridge's, which is the one
//!     the core hands each chunk to be freed with. A refused reserve leaves
//!     everything appended before it in place and every unappended byte still
//!     pending on the stream, in order, so a retry with an allocator that
//!     answers appends exactly the bytes this call stopped at, and none of them
//!     twice.
//!   * **The handle is borrowed.** Every wrapper here points at core-owned
//!     memory, so every guarantee `Conn` states about its own entry holds here
//!     too: good until the connection is swept.
//!
//! # Purity
//!
//! No clock, no entropy, no allocator of this file's own and no socket. Stream
//! limits and flow-control credit are the core's, read at the call.

const std = @import("std");
const quic = @import("quic");

const Error = @import("quic_error.zig").Error;

const core_stream = quic.stream;
const Connection = quic.connection.Connection;

/// How many contiguous runs one `drain` takes.
///
/// Each pass consumes the run it took, so the loop ends when the stream is
/// drained; this is the backstop for a bug that broke that, not a budget.
/// `noq`'s `SEND_DATAGRAM_BATCH_SIZE` is 20 and `SEND_BATCH_SIZE` 64, and 64
/// is the figure `quic_bridge.zig`'s stream tests were written against.
pub const max_drain_runs = 64;

/// Open a bidirectional stream.
///
/// The core's error set here is `anyerror` — `Connection.openStream`
/// (`connection.zig:4799`) carries no named set — so it is mapped onto this
/// project's own answers, for the reason each of those gives. A stream limit
/// is `error.NoStreamRoom` and logs nothing, because it is the core saying
/// "not yet" and a warning a pass later contradicted would be a log about a
/// fact that has since changed. Anything else is `Error.CoreRefused`, with the
/// core's own answer logged before the refusal is named.
pub fn openBidi(conn: *Connection) Error!Stream {
    const opened = conn.openStream() catch |err| switch (err) {
        error.StreamLimitError => return error.NoStreamRoom,
        else => {
            std.log.warn("quic stream: the core refused to open a stream: {t}", .{err});
            return error.CoreRefused;
        },
    };
    return .{ .entry = opened };
}

/// Open a unidirectional stream: send half only.
///
/// Same error mapping as `openBidi`, for the same two reasons, and the same
/// `error.NoStreamRoom`: the limit here is the peer's `initial_max_streams_uni`,
/// which is zero until its transport parameters have been read, so every open
/// on a connection whose peer has not answered yet is refused with it.
pub fn openUni(conn: *Connection) Error!UniStream {
    const opened = conn.openUniStream() catch |err| switch (err) {
        error.StreamLimitError => return error.NoStreamRoom,
        else => {
            std.log.warn("quic stream: the core refused to open a uni stream: {t}", .{err});
            return error.CoreRefused;
        },
    };
    return .{ .entry = opened };
}

/// The peer's next unidirectional stream after `after`, or null when there is
/// none.
///
/// **It is a scan, and the scan is the whole of the contract.** The core keeps
/// a peer's unidirectional streams in one map with no order of its own
/// (`stream.zig:1528`), so "the next one" has to be defined against something
/// the caller holds: the last id it took. `after = 0` asks for the first,
/// because RFC 9000 §2.1 numbers streams from two and no stream id is zero.
///
/// The map is scanned whole and the smallest matching id wins, so a caller
/// that takes one and asks again with its id gets the next one in stream order
/// rather than whatever the hash table happened to yield first. Two scans at
/// most per take, because the second only looks at ids above the one the
/// caller already has.
///
/// A stream that has been reclaimed answers nothing: the core drops its id
/// below a watermark (`stream.zig:1882`), so a caller's `after` is what keeps
/// it from being handed the same id twice.
pub fn acceptUni(conn: *const Connection, after: u64) ?RecvUni {
    var taken: ?*core_stream.ReceiveStream = null;
    var it = conn.streams.recv_streams.iterator();
    while (it.next()) |entry| {
        const id = entry.key_ptr.*;
        if (id <= after) continue;
        // A bidirectional stream is a `Stream`, and one this end opened is a
        // `UniStream`. Neither belongs in a call that is about the peer's.
        if (core_stream.isBidi(id)) continue;
        if (core_stream.isLocal(id, conn.is_server)) continue;
        const candidate = entry.value_ptr.*;
        if (taken == null or candidate.stream_id < taken.?.stream_id) taken = candidate;
    }
    const found = taken orelse return null;
    return .{ .entry = found };
}

/// Take up to `max_drain_runs` ready runs from `entry`, appending them to
/// `sink`.
///
/// The one implementation behind `Stream.drain` and `RecvUni.drain`, because
/// the two are the same operation on the same core type and a second copy
/// would be a second copy of the ownership contract above.
fn drainEntry(
    gpa: std.mem.Allocator,
    entry: *core_stream.ReceiveStream,
    sink: *std.ArrayList(u8),
) std.mem.Allocator.Error!bool {
    var moved = false;
    var runs: usize = 0;
    while (runs < max_drain_runs) : (runs += 1) {
        const len = entry.peekLen() orelse break;
        try sink.ensureUnusedCapacity(gpa, len);
        const chunk = entry.read() orelse break;
        sink.appendSliceAssumeCapacity(chunk);
        gpa.free(chunk);
        moved = true;
    }
    return moved;
}

/// One application stream, bidirectional, as a byte pipe in this project's
/// vocabulary.
///
/// **A stream is read by whichever end opened it.** `drain` reads the stream
/// it is called on and nothing else, so a protocol where both ends speak on one
/// stream has only two shapes: this end opens one and finds the peer's, or the
/// peer opens one and this end takes it. The relay protocol takes the second —
/// the client opens one stream and the relay speaks on that same one — because
/// the client is the end that dials, and the end that dials is the end that has
/// to speak first.
///
/// A borrowed handle, so every guarantee `Conn` states about its own entry
/// holds for this: good until the connection is swept. Copies share the same
/// stream and cursor. Serialize access with the owning bridge. `close` ends
/// sending, but does not release the stream.
pub const Stream = struct {
    /// The core's own stream.
    entry: *core_stream.Stream,

    /// The core's own id for this stream.
    pub fn id(self: Stream) u64 {
        return self.entry.stream_id;
    }

    /// Write bytes, after everything written before them.
    ///
    /// Returns how many bytes this call took, which is all of them or none of
    /// them: the core's `writeData` either copies the whole run into the
    /// stream's buffer or refuses, and a partial copy is not an answer it can
    /// give. **The bytes are copied**, so they may be released the moment this
    /// returns; the stream's buffer belongs to the core.
    pub fn write(self: *Stream, bytes: []const u8) Error!usize {
        self.entry.send.writeData(bytes) catch |err| {
            std.log.warn("quic stream: the core refused stream bytes: {t}", .{err});
            return error.CoreRefused;
        };
        return bytes.len;
    }

    /// Say nothing more on this stream. A peer reads the end as a FIN.
    pub fn close(self: *Stream) void {
        self.entry.send.close();
    }

    /// Take up to `max_drain_runs` ready runs from this stream, appending them
    /// to `sink`.
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
    /// Each call consumes at most `max_drain_runs` ready runs. Drain again
    /// until `false` before treating the receive side as empty. `sink` must use
    /// the same allocator as the stream.
    pub fn drain(
        self: *Stream,
        gpa: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) std.mem.Allocator.Error!bool {
        return drainEntry(gpa, &self.entry.recv, sink);
    }

    /// Whether the peer has said everything it will say on this stream.
    pub fn finished(self: Stream) bool {
        return self.entry.recv.allReceived();
    }
};

/// A unidirectional stream this end opened: the peer reads, this end writes.
///
/// **There is no receive half and no `drain`,** because RFC 9000 §3.1 does not
/// give a unidirectional stream one, and a wrapper that offered `drain` here
/// would be offering a read of bytes the core does not have.
///
/// The write buffer is the core's; `write` copies into it and the caller's
/// bytes may be released on return. What the peer has granted this stream is
/// `credit`, and a write past it is refused rather than queued.
pub const UniStream = struct {
    /// The core's own send half.
    entry: *core_stream.SendStream,

    /// The core's own id for this stream. Its low two bits say `10` or `11`
    /// (RFC 9000 §2.1), which is what tells a peer's from ours.
    pub fn id(self: UniStream) u64 {
        return self.entry.stream_id;
    }

    /// How many bytes this stream may still send before the peer's
    /// MAX_STREAM_DATA says otherwise.
    ///
    /// Zero until the peer's transport parameters have been read, so a caller
    /// that opens a unidirectional stream on a connection whose handshake has
    /// not completed gets a stream it cannot write to yet. That is the same
    /// "not yet" `error.NoStreamRoom` is, reached the other way round.
    pub fn credit(self: UniStream) u64 {
        return self.entry.sendCredit();
    }

    /// Bytes written and not yet acknowledged.
    pub fn buffered(self: UniStream) usize {
        return self.entry.write_offset -| self.entry.send_offset;
    }

    /// Write `bytes`, and refuse them if the peer has not granted the credit.
    ///
    /// **The refusal is the point.** `SendStream.writeData` appends whatever it
    /// is given and leaves the packer to block, so an unbounded write on a
    /// window the peer has not opened queues bytes this node cannot send and
    /// cannot take back — a megabyte of it is a megabyte the core holds for the
    /// life of the connection. Asking `credit` first turns that into a value
    /// the caller can act on: `error.NoSendCredit` says the peer's window is
    /// spent, which MAX_STREAM_DATA will lift, and not that anything is wrong.
    ///
    /// The check is before the core is asked, so a refused write queues
    /// nothing. On success the bytes are copied and `bytes.len` is returned.
    pub fn write(self: *UniStream, bytes: []const u8) Error!usize {
        if (@as(u64, @intCast(bytes.len)) > self.credit()) return error.NoSendCredit;
        self.entry.writeData(bytes) catch |err| {
            std.log.warn("quic stream: the core refused stream bytes: {t}", .{err});
            return error.CoreRefused;
        };
        return bytes.len;
    }

    /// Say nothing more on this stream. A peer reads the end as a FIN, and a
    /// second call is one FIN rather than two.
    pub fn close(self: *UniStream) void {
        self.entry.close();
    }

    /// Abandon this stream with `code`, which the peer reads as a
    /// RESET_STREAM. Bytes never sent stop being owed (`stream.zig:1107`).
    pub fn reset(self: *UniStream, code: u64) void {
        self.entry.reset(code);
    }
};

/// A unidirectional stream the *peer* opened: this end reads, the peer writes.
///
/// The receive half only, for the mirror of `UniStream`'s reason. `drain` and
/// its ownership contract are `Stream.drain`'s, because they are the same
/// operation on the same core type — see `drainEntry`.
pub const RecvUni = struct {
    /// The core's own receive half.
    entry: *core_stream.ReceiveStream,

    /// The core's own id for this stream.
    pub fn id(self: RecvUni) u64 {
        return self.entry.stream_id;
    }

    /// Take up to `max_drain_runs` ready runs from this stream, appending them
    /// to `sink`. The sink is the caller's, grows, and everything about what a
    /// refused reserve leaves behind is `Stream.drain`'s, because it is the
    /// same function.
    pub fn drain(
        self: *RecvUni,
        gpa: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) std.mem.Allocator.Error!bool {
        return drainEntry(gpa, self.entry, sink);
    }

    /// Whether the peer has said everything it will say on this stream.
    pub fn finished(self: RecvUni) bool {
        return self.entry.allReceived();
    }

    /// Stop this stream with `code`: the peer is told its bytes will be
    /// discarded rather than delivered. A stream this end has already drained
    /// to its end is not affected.
    pub fn stopSending(self: *RecvUni, code: u64) void {
        self.entry.stopSending(code);
    }
};
