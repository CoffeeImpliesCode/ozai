//! The scenario one `ozai-interop-peer` run declared, and the proof that the
//! peer actually delivered it.
//!
//! # What this file is responsible for
//!
//! `interop_runtime.zig` moves datagrams; this file decides what those datagrams
//! are *for*. It owns the four channels an interoperability run exercises —
//! bidirectional stream, unidirectional stream, DATAGRAM, and the peer pin the
//! handshake already enforced — and it owns the one thing that makes a run
//! evidence rather than activity: **byte-for-byte equality against a declared
//! expectation**.
//!
//! It is the only file that knows what a scenario *is*, which is why the flag
//! names appear in `interop_options.zig` and nowhere here. What arrives is a
//! `Scenario` of optional payloads, and everything here is decided by which of
//! them are present.
//!
//! # A declared channel is verified; an undeclared one is not mentioned
//!
//! `Scenario.complete` is about *declared* work and nothing else. A run with no
//! `--expect-uni` does not print a unidirectional line at all rather than
//! printing `received_uni 0` — because a zero that reads as a transfer is a
//! transfer this file did not observe, and the whole point of the exercise is
//! that every reported line is something the wire did.
//!
//! That is also why there is no "the peer sent nothing, so it must have been
//! empty" fallback anywhere in this file. A declared expectation either arrives
//! whole and equal, or the run fails naming both values.
//!
//! # The barrier, and why it is the partner's
//!
//! A listener writes its `--response-bi` **only after** every declared
//! expectation has been verified — its own `--expect-bi` request as much as
//! its `--expect-uni` and `--expect-datagram`. That ordering is
//! `test/rust_partner/src/main.rs`'s, and it is the whole of what makes an
//! answer evidence: if the answer is on the wire, every payload the listener
//! declared as received did arrive, so a dialer that received the answer has
//! proof of the request's whole arrival rather than proof of one stream's.
//!
//! The request's own stream is in that list because the answer is written
//! *about* it. Without it a reply goes out on the first pass that merely had
//! a peer stream — a stream whose bytes had not been read, let alone
//! compared — and the peer holds an answer to a question this end never
//! verified. The partner gates its reply the same way, and for the same
//! reason.
//!
//! Mirroring it is not politeness. A listener that answered immediately would
//! let a dialer complete on the strength of one stream while its own unidi-
//! rectional and datagram expectations were still outstanding, and the run
//! would pass having proved less than it was asked to prove.
//!
//! # Flow control is a value, not a wait
//!
//! `UniStream.write` answers `error.NoSendCredit` when the peer's window is
//! closed, and `Stream.write` writes as much as the window allows and returns
//! how much. Neither is a fault and neither is papered over with a sleep: a
//! partial write is carried in `written` and the rest goes out on a later pass
//! once `tick` has run and MAX_STREAM_DATA has moved. **No pass in this file
//! ever waits for the peer.** Everything here is decided by state the core
//! reports, which is what `loopback_link.zig`'s module doc says about virtual
//! time, and what a real clock turns into: an instant that advances because the
//! monotonic clock advanced.

const std = @import("std");
const ozai = @import("ozai");

const runtime = @import("interop_runtime.zig");
const options = @import("interop_options.zig");

const stream_mod = ozai.transport_quic_stream;
const error_mod = ozai.transport_quic_error;
const Conn = runtime.Conn;
const Instant = runtime.Instant;

pub const Stream = stream_mod.Stream;
pub const UniStream = stream_mod.UniStream;

/// What a refusal in this file means, over and above the transport's own.
///
/// Every name here is a *scenario* fault rather than a wire fault, which is the
/// distinction a reader of a failed run needs most: `PayloadMismatch` says the
/// two ends disagreed about bytes, while anything from `error_mod.Error` says the
/// stack refused something. Collapsing the two would make a scenario bug look
/// like a protocol bug.
pub const Error = error_mod.Error || std.mem.Allocator.Error || error{
    /// The peer's payload arrived and is not the declared one. Both values are
    /// printed by the caller, so this name never travels alone.
    PayloadMismatch,
    /// A declared payload is longer than the connection's DATAGRAM allowance,
    /// so the frame could never be built. The caller prints the two lengths.
    DatagramTooLarge,
    /// A declared payload is longer than `max_payload`. Refused by
    /// `interop_options` before it reaches here, so this arm is what a future
    /// caller that built a `Scenario` by hand would meet.
    PayloadTooLarge,
};

/// The most bytes a sink will hold.
///
/// The declared payload length is the real bound; this is the ceiling a
/// scenario may declare at all, and it is `options.max_payload` rather than a
/// number of this file's own.
pub const max_sink = options.max_payload;

/// One channel's expectation: what was declared, and what has been read.
///
/// A value rather than three parallel variables, because the three channels are
/// the same shape and the shape is what this file is about. `received` is the
/// sink and `complete` says the FIN arrived — which is a different fact from
/// "the expected length is in the sink", and is why a partial read is not
/// reported as a match.
pub const Channel = struct {
    /// What the peer must have sent. Null means this channel was not declared
    /// and nothing about it will be said.
    expected: ?[]const u8 = null,
    /// Bytes read so far, growing as the peer sends.
    received: std.ArrayList(u8) = .empty,
    /// Whether this channel's expectation has been verified equal.
    complete: bool = false,
    /// Whether `received_*` has already been printed for it. A declaration is
    /// announced exactly once, so a peer that arrives in two pieces produces
    /// one line and not two.
    announced: bool = false,

    /// Whether this channel was part of the run at all.
    fn declared(self: Channel) bool {
        return self.expected != null;
    }

    /// Refuse a peer that sent more than the declared payload, rather than
    /// growing the sink to whatever it feels like sending.
    ///
    /// A run that let the sink grow would eventually mismatch anyway, but only
    /// after buffering whatever the peer chose to send — which for a peer under
    /// no obligation is unbounded work on this side of a failing run.
    fn bound(self: *Channel) !void {
        const wanted = self.expected orelse return;
        if (self.received.items.len > wanted.len) return error.PayloadMismatch;
    }

    /// The bytes read, for a comparison.
    fn got(self: *const Channel) []const u8 {
        return self.received.items;
    }
};

/// The scenario this run declared, and the state of its four channels.
///
/// No stream handle is kept across passes: `Bridge.sweep` frees a finished
/// connection and its streams with it, so a handle held in a struct field would
/// be a handle into freed memory on the next pass. Every pass re-derives what it
/// needs from the connection it was handed, which is why `step` takes the
/// `Conn` rather than storing one.
pub const Scenario = struct {
    gpa: std.mem.Allocator,
    /// The peer this run insists on, or null when the scenario declared no
    /// pin. Carried so a run can report what it enforced without re-reading the
    /// command line.
    expect_peer: ?ozai.NodeId,

    /// The bidirectional channel. On a dialer it is the stream this run opened
    /// and wrote its request on; on a listener it is the stream the peer opened
    /// and this run answers on the same handle. **One channel either way**,
    /// because a bidirectional stream is one stream with two halves and `Stream`
    /// holds both — an exchange that opened two would be a protocol this
    /// project does not speak.
    bidirectional: Channel = .{},
    uni: Channel = .{},
    datagram: Channel = .{},

    /// Whether this run has a request to write, an answer to write, and both.
    send_bi: ?[]const u8 = null,
    response_bi: ?[]const u8 = null,
    send_uni: ?[]const u8 = null,
    send_datagram: ?[]const u8 = null,

    /// Bytes written to the bidirectional stream, and whether it is closed.
    ///
    /// The count is a state parameter rather than something re-derived, because
    /// a `Stream.write` that writes part of its input is the ordinary case on a
    /// bounded window and re-deriving it would rewrite the prefix.
    bi_written: usize = 0,
    bi_closed: bool = false,
    /// The bidirectional stream, between the pass that opened or took it and
    /// the pass that closed it. Kept for the reason `uni_stream`'s doc gives,
    /// and it is the handle the reply is read from on the requesting side.
    bi_stream: ?Stream = null,
    /// The unidirectional stream this run opened, between the pass that created
    /// it and the pass that closed it. `openUni` *creates* a stream rather than
    /// finding one, so this cannot be re-derived per pass the way a
    /// bidirectional stream can.
    uni_stream: ?UniStream = null,
    uni_written: usize = 0,
    uni_closed: bool = false,
    /// Whether the datagram has been queued.
    datagram_queued: bool = false,
    /// The last unidirectional stream id taken, because `acceptUni`'s argument
    /// is "the next one after this" and RFC 9000 §2.1 numbers from 2, so the
    /// first call passes 0.
    uni_after: u64 = 0,

    /// A scenario built from a parsed command line.
    ///
    /// Pure over its arguments and allocating nothing: the three sinks are
    /// `std.ArrayList`s that grow on first use, so a run that declares one
    /// channel never allocates for the two it did not.
    ///
    /// Every payload is re-checked against `max_sink` here rather than trusted
    /// from `interop_options`, because this constructor is public: a caller that
    /// assembled an `Options` by hand meets the same bound, and the bound is
    /// what stops a peer from growing a sink without limit.
    pub fn init(
        self: *Scenario,
        gpa: std.mem.Allocator,
        expect_peer: ?ozai.NodeId,
        parsed: options.Options,
    ) Error!void {
        for ([_]?[]const u8{
            parsed.send_bi,
            parsed.response_bi,
            parsed.send_uni,
            parsed.expect_bi,
            parsed.expect_uni,
            parsed.send_datagram,
            parsed.expect_datagram,
        }) |payload| {
            const bytes = payload orelse continue;
            if (bytes.len > max_sink) return error.PayloadTooLarge;
        }
        self.* = .{
            .gpa = gpa,
            .expect_peer = expect_peer,
            .send_bi = parsed.send_bi,
            .response_bi = parsed.response_bi,
            .send_uni = parsed.send_uni,
            .send_datagram = parsed.send_datagram,
            .bidirectional = .{ .expected = parsed.expect_bi },
            .uni = .{ .expected = parsed.expect_uni },
            .datagram = .{ .expected = parsed.expect_datagram },
        };
    }

    /// Release the three sinks and leave the scenario unusable.
    ///
    /// The streams in `bi_stream` and `uni_stream` are borrowed out of the
    /// core and are not freed here — `Bridge.sweep` took them with the
    /// connection — so this is a claim about the three sinks and about
    /// nothing being usable afterwards. The poison is the whole of the
    /// second half: a second `deinit` would free three sinks that are already
    /// back in the allocator.
    pub fn deinit(self: *Scenario) void {
        self.bidirectional.received.deinit(self.gpa);
        self.uni.received.deinit(self.gpa);
        self.datagram.received.deinit(self.gpa);
        self.* = undefined;
    }

    /// One pass of the scenario against a live connection.
    ///
    /// `conn` is the established connection, or null while there is none — a
    /// pass before the handshake finished is a fact, not a fault, and the
    /// run's deadline is what ends a peer that never arrives.
    pub fn step(self: *Scenario, conn: ?Conn, at: Instant, text: *std.Io.Writer) !void {
        const established = conn orelse return;
        // The sends first. Both halves of the reason are in the module doc: a
        // listener's answer waits on its own verifications (the partner's
        // barrier), and a request goes out before anything is read so the
        // peer's own sends are not waiting on this end to speak.
        try self.send(established, at, text);
        try self.receive(established, at, text);
    }

    /// Everything this run has to write, in the order it may write it.
    fn send(self: *Scenario, conn: Conn, at: Instant, text: *std.Io.Writer) !void {
        try self.sendBidirectional(conn, text);
        try self.sendUni(conn, text);
        try self.sendDatagram(conn, at, text);
    }

    /// The one bidirectional exchange: a request, an answer, or both halves'
    /// share of it.
    ///
    /// **One stream handle, kept, because `openBidi` creates a stream rather
    /// than finding one** — calling it on every pass would put a stream per pass
    /// on the wire and answer none of them. The requester opens its own; the
    /// listener takes the one the peer opened, once it exists, and answers on
    /// that same handle. A bidirectional stream is one stream with two halves
    /// (RFC 9000 §2.1), so the requester reads its own reply from here rather
    /// than looking for a second stream that will never come.
    fn sendBidirectional(self: *Scenario, conn: Conn, text: *std.Io.Writer) !void {
        const payload = self.send_bi orelse self.response_bi orelse return;
        if (self.bi_closed) return;

        // A listener writes its answer only once every expectation it declared
        // is verified, its own `--expect-bi` request included: the module doc's
        // barrier, and the only thing that makes the answer proof of the whole
        // arrival.
        if (self.response_bi != null and !self.barrierReached()) return;

        if (self.bi_stream == null) {
            self.bi_stream = if (self.send_bi != null)
                (stream_mod.openBidi(conn.entry.conn) catch |err| switch (err) {
                    // The peer's MAX_STREAMS has no room this instant. It lifts
                    // as soon as a stream is finished, so a later pass retries;
                    // refusing here would fail a run whose peer was briefly out
                    // of credit rather than broken.
                    error.NoStreamRoom => return,
                    else => |other| return other,
                })
            else
                // The listener has nothing to answer on until the peer opens
                // one, which is a value and not a failure. No cursor: this end
                // accepted the connection, so the peer's first bidirectional
                // stream is id zero and a cursor of `0` would skip it.
                conn.peerStream(null) orelse return;
        }
        const stream = &self.bi_stream.?;
        while (self.bi_written < payload.len) {
            const written = stream.write(payload[self.bi_written..]) catch |err| switch (err) {
                // A closed window is the peer not being ready yet. It lifts on
                // MAX_STREAM_DATA and the rest goes out on a later pass.
                error.NoSendCredit => return,
                else => |other| return other,
            };
            if (written == 0) return;
            self.bi_written += written;
        }
        stream.close();
        self.bi_closed = true;
        // The FIN ends this end's half only; the reply still arrives on the
        // same stream, so the handle stays until it has been read.
        if (self.send_bi != null) try text.print("sent_bi {d}\n", .{payload.len});
    }

    /// A unidirectional payload, if the run declared one.
    ///
    /// **The stream is opened exactly once**, on the first pass where the peer
    /// has granted room for one, and its handle is kept: `openUni` *creates* a
    /// stream rather than finding one, so calling it again would put a second
    /// stream on the wire instead of continuing the first. The handle is
    /// borrowed from the core's own stream map, so it stays good for as long as
    /// the connection does — which is why the field carrying it is only ever
    /// read on a pass that was handed a live `Conn`.
    ///
    /// A `NoSendCredit` is the peer's window being closed, not a fault and not a
    /// lost payload: MAX_STREAM_DATA lifts it and a later pass writes the rest.
    /// So it returns, and the run's deadline is what catches a window that never
    /// opens. **Nothing here sleeps** — that is the whole reason this file can
    /// be driven by a real clock.
    fn sendUni(self: *Scenario, conn: Conn, text: *std.Io.Writer) !void {
        const payload = self.send_uni orelse return;
        if (self.uni_closed) return;

        if (self.uni_stream == null) {
            self.uni_stream = conn.openUni() catch |err| switch (err) {
                // The peer's MAX_STREAMS has no room this instant. It lifts as
                // soon as a stream is finished, so a later pass retries — and
                // refusing here would fail a run whose peer was briefly out of
                // credit rather than broken.
                error.NoStreamRoom => return,
                else => |other| return other,
            };
        }
        const stream = &self.uni_stream.?;
        while (self.uni_written < payload.len) {
            const written = stream.write(payload[self.uni_written..]) catch |err| switch (err) {
                error.NoSendCredit => return,
                else => |other| return other,
            };
            if (written == 0) return; // Window closed; a later pass carries the rest.
            self.uni_written += written;
        }
        stream.close();
        self.uni_closed = true;
        self.uni_stream = null;
        // Queued, not received: this line says the payload went out on this
        // end's wire, and `received_uni` is what says the peer read it back.
        try text.print("sent_uni {d}\n", .{payload.len});
    }

    /// A DATAGRAM payload, if the run declared one.
    ///
    /// Sized from `datagramMaxPayload` rather than from the format's ceiling,
    /// because that is the number this connection can actually carry and the
    /// core refuses a frame past it with an answer no caller can act on. A
    /// payload that does not fit is a scenario bug and says so by name.
    fn sendDatagram(self: *Scenario, conn: Conn, at: Instant, text: *std.Io.Writer) !void {
        const payload = self.send_datagram orelse return;
        if (self.datagram_queued) return;
        const room = conn.datagramMaxPayload() orelse return error.DatagramTooLarge;
        if (payload.len > room) return error.DatagramTooLarge;
        try conn.sendDatagram(payload, at);
        self.datagram_queued = true;
        // Queued, not received: a DATAGRAM is one frame or it is nothing, so
        // this line says it was handed to the transport and nothing more.
        // `received_datagram` is what says the peer took it.
        try text.print("sent_datagram {d}\n", .{payload.len});
    }

    /// Everything the peer has delivered, and every declared expectation that
    /// has now been met.
    fn receive(self: *Scenario, conn: Conn, at: Instant, text: *std.Io.Writer) !void {
        try self.receiveBidirectional(conn, text);
        try self.receiveUni(conn, text);
        try self.receiveDatagram(conn, at, text);
    }

    /// Read the one bidirectional stream, and compare it once its FIN arrived.
    ///
    /// The same handle the request was written on, whether this run wrote it or
    /// took it from the peer. A prefix is not a message: the comparison waits
    /// for `finished`, so a peer that sent three bytes of a nine-byte payload
    /// and then stopped has satisfied nothing.
    fn receiveBidirectional(self: *Scenario, conn: Conn, text: *std.Io.Writer) !void {
        if (!self.bidirectional.declared()) return;
        if (self.bidirectional.complete) return;

        // A listener reads the request on the stream the peer opened, which is
        // the handle `sendBidirectional` takes; a requester reads its own reply
        // on the handle it opened. Both are this one field, for that reason.
        if (self.bi_stream == null and self.send_bi == null) {
            // Taken once into `bi_stream` and kept for the run, which is what
            // makes this a poll rather than a take: the handle is held rather
            // than asked for again, so there is no cursor to pass and the
            // peer's lowest bidirectional stream is the stream there is. On a
            // listener that stream is id zero, which a cursor of `0` skipped.
            self.bi_stream = conn.peerStream(null) orelse return;
        }
        var stream = self.bi_stream orelse return;

        _ = try stream.drain(self.gpa, &self.bidirectional.received);
        try self.bidirectional.bound();
        if (!stream.finished()) return;
        if (!self.bidirectional.announced) {
            self.bidirectional.announced = true;
            try text.print("received_bi {x}\n", .{self.bidirectional.got()});
        }
        try expect(&self.bidirectional, self.bidirectional.expected.?);
    }

    /// Read a unidirectional stream, and compare it once its FIN arrived.
    ///
    /// `acceptUni(after)` returns the peer's next stream *after* the id given,
    /// and the core's map is unordered, so "next" is defined against the last id
    /// this run took. RFC 9000 §2.1 numbers streams from 2 and no id is 0, so
    /// the first call passes 0 and nothing is ever lost to the ordering.
    fn receiveUni(self: *Scenario, conn: Conn, text: *std.Io.Writer) !void {
        if (!self.uni.declared()) return;
        if (self.uni.complete) return;

        var taken = conn.acceptUni(self.uni_after) orelse return;
        self.uni_after = taken.id();
        _ = try taken.drain(self.gpa, &self.uni.received);
        try self.uni.bound();
        if (!taken.finished()) return; // A prefix is not a message.
        if (!self.uni.announced) {
            self.uni.announced = true;
            try text.print("received_uni {x}\n", .{self.uni.got()});
        }
        try expect(&self.uni, self.uni.expected.?);
    }

    /// Read one DATAGRAM, if the run declared one.
    ///
    /// A DATAGRAM has no FIN and no framing beyond its own length, so the
    /// comparison happens the moment one arrives rather than on a boundary.
    /// `recvDatagram` copies into this run's own buffer, so the bytes are
    /// stable after the core's buffer is reused by the next call.
    fn receiveDatagram(self: *Scenario, conn: Conn, at: Instant, text: *std.Io.Writer) !void {
        if (!self.datagram.declared()) return;
        if (self.datagram.complete) return;

        const room = conn.datagramMaxPayload() orelse return;
        if (room > max_sink) return error.DatagramTooLarge;
        const scratch = try self.gpa.alloc(u8, room);
        defer self.gpa.free(scratch);
        const got = conn.recvDatagram(scratch, at) orelse return;
        // Copied out of the core's borrow, because the next `recvDatagram`
        // overwrites `scratch` and the announcement below reads these bytes.
        try self.datagram.received.appendSlice(self.gpa, got);
        try self.datagram.bound();
        if (!self.datagram.announced) {
            self.datagram.announced = true;
            try text.print("received_datagram {x}\n", .{self.datagram.got()});
        }
        try expect(&self.datagram, self.datagram.expected.?);
    }

    /// Whether every expectation this run declared has been verified.
    ///
    /// The gate on a listener's answer, and named for what it gates rather than
    /// for the channels it looks at.
    ///
    /// The bidirectional channel is consulted only for the end that is
    /// *answering* it. A requester has already written its own half and reads
    /// the reply on that same stream, so gating its send on the reply would be
    /// a deadlock it could never leave; a listener that declared `--expect-bi`
    /// is answering a request it has not yet compared. An undeclared channel
    /// is not consulted either way, which is what keeps a `--response-bi`-only
    /// listener writing its answer as soon as the peer opens a stream.
    fn barrierReached(self: *const Scenario) bool {
        const answering = self.response_bi != null and self.bidirectional.declared();
        if (answering and !self.bidirectional.complete) return false;
        if (self.uni.declared() and !self.uni.complete) return false;
        if (self.datagram.declared() and !self.datagram.complete) return false;
        return true;
    }

    /// Whether the declared scenario has finished, in both directions.
    ///
    /// A *declared* send counts, because the peer cannot answer what was never
    /// sent; an undeclared channel is not part of the run and is not consulted.
    /// An expectation that is not declared is likewise not required — which is
    /// what makes a handshake-only run complete as soon as the handshake is up.
    pub fn complete(self: *const Scenario) bool {
        if (self.bidirectional.declared() and !self.bidirectional.complete) return false;
        if (self.uni.declared() and !self.uni.complete) return false;
        if (self.datagram.declared() and !self.datagram.complete) return false;
        if (self.send_bi != null and self.bi_written < self.send_bi.?.len) return false;
        if (self.response_bi != null and self.bi_written < self.response_bi.?.len) return false;
        if (self.send_uni != null and self.uni_written < self.send_uni.?.len) return false;
        if (self.send_datagram != null and !self.datagram_queued) return false;
        return true;
    }
};

/// Compare one channel's bytes against what was declared, and mark it done if
/// they are equal.
///
/// The only place equality is decided in this file, so a mismatch has one name
/// and one caller. The caller prints both hexes; this returns the name alone,
/// because a `PayloadMismatch` that formatted its own message would put a
/// scenario's payload inside a transport's error set — and a reader of a
/// failed run needs to tell a scenario bug from a protocol bug at a glance.
fn expect(channel: *Channel, wanted: []const u8) Error!void {
    if (!std.mem.eql(u8, channel.got(), wanted)) return error.PayloadMismatch;
    channel.complete = true;
}
