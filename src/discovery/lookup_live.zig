//! The live `lookup_io.Datagram`: a query on `transport/socket.zig`, an answer
//! off it, and a handle that stops both.
//!
//! `lookup_io.zig` names what a lookup needs from a socket and opens none, and
//! its module doc gives the reason: `docs/ARCHITECTURE.md` draws
//! `ozai.transport` *above* `ozai.discovery`, so a file under `discovery/`
//! that reached for a transport socket would invert the tree. That is right
//! for a codec. This file is not a codec — it is the seam itself, and
//! something has to cross it or every transport in the tree stays a test fake.
//! Crossing it here is the whole file, and it is crossed in one place on
//! purpose.
//!
//! # Who runs it, and who does not
//!
//! `Datagram.init` takes a `transport/socket.zig` `Socket`, so what follows is
//! reached by real descriptors rather than by a fake: the mapping, the sliced
//! deadline and the abort all name things a socket has. No node drives any of
//! it yet. `discovery/dial_source.zig` says in its own module doc that it
//! takes every answer as a value it was handed and fetches none, and the only
//! callers of `Datagram` are the tests at the bottom of this file. The seam is
//! crossed by real sockets and by nothing else; what a caller will do with one
//! is a gap in the node, and the sections below are about the seam's own
//! behaviour because that is all that is decided here.
//!
//! # The three arms of the mapping, and the sets behind them
//!
//! `lookup_io.SocketError` has three members, and a real socket names its
//! failures in two sets of its own — `SendError` and `ReceiveError`. A lookup
//! cannot act differently on any two of them, so the mapping is that file's
//! and this file performs it:
//!
//! * `Canceled` is `Canceled`: `Io`'s own cancellation, which the socket
//!   checks on the way into every call it makes, and this file's latch, which
//!   is what `resolve.Cancellation` fires.
//! * `WouldBlock` is `Empty`: a poll that timed out is the deadline arriving
//!   with nothing, and `Answer.timeout` is what that looks like above.
//! * Everything else is `Refused`, including the two a fake cannot produce at
//!   all — see the next section.
//!
//! # What a real socket has that a scripted one does not
//!
//! Four, and each is a way to hand back bytes that are not the answer:
//!
//! 1. **A coalesced read.** `Socket.create` probes the socket and that probe
//!    turns `UDP_GRO` on, so the kernel is free to hand back several datagrams
//!    in one read, and `Received.stride` is how it says so. `Datagram.Reply`
//!    carries one `bytes`, and nothing above this file can say which of the
//!    several was the question's answer, so the read is refused. Splitting it
//!    is not available either: which datagram to skip is a policy, and RFC
//!    1035 §7.2's "try other servers before repeating a query" needs an
//!    instant this file does not carry.
//! 2. **A datagram larger than the buffer.** `MSG_TRUNC` makes the bytes in
//!    the buffer a prefix, and a prefix parsed as a message is a name that
//!    exists with records nobody published. Refused, and the query advertises
//!    `max_udp_payload` so a server that honours it cannot cause this.
//! 3. **A datagram of no bytes.** RFC 1035 has no such message and
//!    `batch.Recv.init` refuses it, which is the right answer for a lookup.
//! 4. **A datagram from elsewhere.** `Retrieval.ask` refuses it as
//!    `ForeignSource`, which is a fact about the seam rather than about this
//!    file: one `ask` is one datagram out and one in, so a stray datagram ends
//!    the ask rather than being skipped. A nameserver that answers late
//!    behind another server's answer will be seen as that.
//!
//! # The deadline is a budget, spent in slices
//!
//! `Request.deadline_ms` reaches the socket as `poll`'s own timeout and this
//! file reads no clock, so the deadline cannot be compared against an instant.
//! What it can be is *spent*: `receiveAnswer` waits `poll_slice_ms` at a time
//! and subtracts each wait from what is left, so the slices add up to the
//! deadline rather than rounding past it, and a null deadline — the caller
//! meaning "as long as you mean" — is the one unbounded wait here. It ends on
//! a datagram, a refusal or an abort handle, and on nothing else.
//!
//! The slicing is not what an abort waits for, and it used to look as though
//! it were: a latch is read between two waits and nowhere else, so a receive
//! already inside `poll` ran its slice out before anything noticed. The next
//! section is what that became.
//!
//! # The abort reaches the socket, and the socket is what it leaves behind
//!
//! `lookup_io.Datagram.stop` is specified as stopping whatever is in flight,
//! and it names the failure a flag would be: a latch nobody reads would
//! satisfy every assertion written about cancellation while the query sat in
//! the socket's queue. So `stop` does two things. It latches, which is what a
//! send and a wait between two slices read. And it names the socket, which is
//! `Socket.stop` — one write to a second descriptor that sits in the same
//! `poll` set as the socket, so a receive already inside `poll` returns at
//! once rather than at the end of its slice. That write is the half a stop may
//! do from a signal handler (`src/node/node.zig:485` says a stop may be raised
//! from one), and the queue is emptied by the waiter rather than by the stop,
//! because `recvmsg` is not on the list of calls such a handler may make.
//!
//! The datagram is the other half of "in flight", and it was quietly the
//! worse one. This file borrows a socket it cannot close, the abandoned
//! lookup is a value that goes out of scope, and the answer to the abandoned
//! query is still in the kernel's queue: the next `Datagram` on that
//! descriptor reads it and `lookup_io.readHeader` refuses it as
//! `error.ForeignTransaction`, which is a hard failure of a lookup that had
//! nothing to do with the one that was dropped — after the good datagram was
//! already on the wire. So `Socket.stop` leaves the socket refusing to serve:
//! the wait a wake ends empties the queue, and the next datagram out of the
//! descriptor takes whatever arrived in between, because a datagram queued
//! before a query went out cannot be that query's answer.
//!
//! What that does not reach is a datagram that arrives *after* the next query
//! is out, and nothing in this layer can tell it from that query's own answer:
//! the transaction id is above it, `Retrieval.begin` draws it and `readHeader`
//! is what matches a reply to a question, and a match is a fact about DNS
//! rather than about a descriptor. A straggler that late is still read, and
//! still refused under the name it deserves. What is gone is the datagram that
//! was in flight when the abort landed, which is the one the abort is about.
//!
//! # Truncation needs a separate stream
//!
//! The UDP seam remains a datagram seam. `dns_live.Retrieval` consumes the pure
//! `host_io.StreamRetry` decision through `retryStream` below: one short-lived
//! TCP connection, the identical question, and a complete length-prefixed reply.
//! The wire decoder remains responsible for validating the returned DNS message.
//!
//! # `net/probe_run.zig`'s transport is not this, and why
//!
//! `probe_run.Transport` is the same shape over different wire and is not
//! built here. Three of its six methods are the QUIC address-discovery probe
//! and three are the captive-portal check, and that second trio is an HTTPS
//! request to a relay (`iroh/src/net_report.rs:826-961`). This tree has no
//! HTTP client and no TLS client outside the vendored QUIC core, and building
//! one is relay work rather than socket work. A transport that answered three
//! of the six would satisfy the type and answer nothing real, which is the
//! fake dressed as a live one this file exists to replace.
//!
//! # Purity, ownership and lifetimes
//!
//! No global, thread, or `std.Io` stored. Datagram operations borrow their
//! buffers; the TCP consumer borrows `io`, reads its monotonic deadline, and
//! allocates exactly the response length advertised by the stream prefix.
//!
//! What the socket carries across an abort is the socket's own state and not
//! this file's: a `stop` writes a descriptor and sets a flag, and neither one
//! is a field here, which is the same reason there is no `Io` to unwind.
//!
//! `Datagram` borrows the socket it is given, so the caller owns the
//! descriptor and closes it; `Datagram.seam` hands out a copy of the three
//! function pointers, so the `Retrieval` that takes it, and the `Datagram`
//! itself, must both outlive the `ask`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const batch = @import("../transport/batch.zig");
const socket = @import("../transport/socket.zig");
const dns = @import("dns.zig");
const lookup_io = @import("lookup_io.zig");
const tcp = @import("../transport/tcp.zig");
const tcp_execution = @import("../transport/tcp_execution.zig");
const host_io = @import("host_io.zig");
const wire = @import("lookup_wire.zig");

const SocketError = lookup_io.SocketError;
const Reply = lookup_io.Datagram.Reply;

/// How long one wait on the socket lasts before its slice is charged.
///
/// 20 ms, a bound rather than a number somebody liked: long enough that
/// upstream's three-second per-query deadline
/// (`iroh/src/address_lookup/dns.rs:19`) costs 150 `poll` calls rather than
/// 150 000. It is not short enough for an abort any more, and does not have to
/// be, because an abort has a descriptor of its own to end the wait with.
pub const poll_slice_ms: i32 = 20;

/// The stop latches borrowed during a bounded TCP fallback.
pub const StreamStops = struct {
    retrieval: *const std.atomic.Value(bool),
    resolver: ?*const std.atomic.Value(bool) = null,

    fn check(self: StreamStops) SocketError!void {
        if (self.retrieval.load(.acquire)) return error.Canceled;
        if (self.resolver) |flag| {
            if (flag.load(.acquire)) return error.Canceled;
        }
    }
};

/// Repeat a TC question through the borrowed TCP provider.
/// The caller frees the returned message. No partial reply escapes on any error.
/// `timeout_ms` is the remaining query budget, capped at the per-query DNS bound.
/// Provider callbacks and context outlive this call and all descriptor cleanup.
pub fn retryStream(
    alloc: std.mem.Allocator,
    io: std.Io,
    retry: host_io.StreamRetry,
    timeout_ms: i32,
    stops: StreamStops,
    execution: tcp_execution.Execution,
) lookup_io.Error![]u8 {
    try stops.check();
    if (timeout_ms <= 0) return error.Empty;
    const budget: StreamBudget = .{
        .start = std.Io.Timestamp.now(io, .awake),
        .timeout_ms = @min(timeout_ms, @as(i32, @intCast(host_io.query_timeout_ms))),
        .stops = stops,
    };
    var stream = tcp.Tcp.create(io, retry.server, execution) catch |err| {
        return if (err == error.Canceled) error.Canceled else error.Refused;
    };
    defer stream.close();
    // Tcp retains pending handshake state, so slices never reissue the connect syscall.
    while (true) {
        const left = try budget.remaining(io);
        stream.connect(io, @min(left, poll_slice_ms)) catch |err| {
            try stops.check();
            switch (err) {
                error.Canceled => return error.Canceled,
                error.WouldBlock => continue,
                else => return error.Refused,
            }
        };
        break;
    }
    try stops.check();
    var prefix: [host_io.length_prefix_bytes]u8 = undefined;
    host_io.writeLengthPrefix(&prefix, retry.query.len) catch return error.Refused;
    try streamWrite(io, &stream, &prefix, budget);
    try streamWrite(io, &stream, retry.query, budget);
    try streamRead(io, &stream, &prefix, budget);
    const length = wire.be16(&prefix, 0);
    if (length < wire.header_length) return error.ShortMessage;
    const message = try alloc.alloc(u8, length);
    errdefer alloc.free(message);
    try streamRead(io, &stream, message, budget);
    try stops.check();
    return message;
}

const StreamBudget = struct {
    start: std.Io.Timestamp,
    timeout_ms: i32,
    stops: StreamStops,

    fn remaining(self: StreamBudget, io: std.Io) SocketError!i32 {
        try self.stops.check();
        const elapsed_ns = std.Io.Timestamp.now(io, .awake).nanoseconds - self.start.nanoseconds;
        const left_ns = @as(i96, self.timeout_ms) * std.time.ns_per_ms - elapsed_ns;
        if (left_ns <= 0) return error.Empty;
        // Round up so a positive final millisecond is not discarded.
        return @intCast(@divFloor(left_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms));
    }
};

fn streamWrite(
    io: std.Io,
    stream: *tcp.Tcp,
    bytes: []const u8,
    budget: StreamBudget,
) lookup_io.Error!void {
    var at: usize = 0;
    while (at < bytes.len) {
        const left = try budget.remaining(io);
        const count = stream.write(io, bytes[at..], @min(left, poll_slice_ms)) catch |err| {
            try budget.stops.check();
            switch (err) {
                error.Canceled => return error.Canceled,
                error.WouldBlock => continue,
                else => return error.Refused,
            }
        };
        try budget.stops.check();
        if (count == 0) return error.Refused;
        at += count;
    }
}

fn streamRead(
    io: std.Io,
    stream: *tcp.Tcp,
    bytes: []u8,
    budget: StreamBudget,
) lookup_io.Error!void {
    var at: usize = 0;
    while (at < bytes.len) {
        const left = try budget.remaining(io);
        const count = stream.read(io, bytes[at..], @min(left, poll_slice_ms)) catch |err| {
            try budget.stops.check();
            switch (err) {
                error.Canceled => return error.Canceled,
                error.WouldBlock => continue,
                else => return error.Refused,
            }
        };
        try budget.stops.check();
        if (count == 0) return error.ShortMessage;
        at += count;
    }
}

/// The socket a lookup goes out on, as the two calls this file makes on it.
///
/// Injected for the reason `lookup_io.Datagram` is: the query and the answer
/// are two calls, and nothing about them can be proved without standing
/// something in for the descriptor. `transport/socket.zig` is the live arm and
/// the unit tests are the other one.
///
/// Nothing here is owned: `ctx` is whatever the wire wraps — a `*socket.Socket`
/// for the live arm — and it has to stay alive for as long as the `Datagram`
/// that wraps it, because every call reaches through it. Each call runs
/// synchronously, on the thread that asked through the seam, and returns before
/// that call does, and nothing is retained between them: `receiveAnswer` reads
/// what `receive` returned inside the same call and hands a copy of it upward,
/// so a wire may not return bytes that die before that call returns. Nothing
/// reenters the `Datagram` from a wire call: `stop` is the one callback that can
/// arrive from elsewhere — `src/node/node.zig` says a stop may be raised from a
/// signal handler — and it is the one that must therefore do nothing but latch
/// and name the socket.
const Wire = struct {
    /// The value the two calls and the stop are made on, borrowed. Reachable
    /// from every call below, so it outlives them.
    ctx: *anyopaque,
    /// Called with the framed query and the server the retrieval named, both by
    /// value, and returns once the datagram is away.
    ///
    /// `error.Canceled` crosses the seam as `SocketError.Canceled` and every
    /// other arm of `socket.SendError` as `SocketError.Refused` — that mapping
    /// is `sendQuery`'s, because cancellation is the one thing a lookup acts on
    /// differently and the two sets name it differently.
    send: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) socket.SendError!void,
    /// Receive into `into`, waiting at most `timeout_ms`. Null waits without
    /// a deadline. Returned bytes must borrow `into`, not callback-local memory.
    /// Buffers may change on error. Cancellation must return `error.Canceled`.
    receive: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        into: []u8,
        timeout_ms: ?i32,
    ) socket.ReceiveError!socket.Received,
    /// Name the socket stopped, for a wire that holds one to name. Null where
    /// there is none, and the difference is the whole of what the scripted arm
    /// can be asked to prove: it holds no descriptor, so there is no wait in
    /// flight to end and no queue to leave behind.
    ///
    /// With a null one, `stop` still latches and the seam still refuses every
    /// later ask; what it cannot do is end a wait that is already inside the
    /// kernel. A wire that holds a descriptor therefore has to supply this,
    /// because a latch nobody polls is the failure the module doc names.
    stop: ?*const fn (ctx: *anyopaque) void,
};

///
/// The live `lookup_io.Datagram`: the query, the answer, and the handle that
/// stops both.
///
/// The latch is what makes a stop final: it is set once and never cleared, and
/// every entry to the seam reads it, so an ask after an abort is refused rather
/// than sent. A copy of this value copies the latch and not the socket, so the
/// `Datagram` a `Retrieval` holds has to be the one the handle stops.
///
/// Serialize query and receive calls on this socket. Only cancellation may run
/// concurrently. Keep this value at its original address after `seam`, and
/// keep the socket open until every retrieval and cancellation call finishes.
pub const Datagram = struct {
    /// The socket to go out on, borrowed. It and the `Datagram` both have to
    /// outlive every `Retrieval` begun from `seam`, because a retrieval holds
    /// the seam and the seam points here.
    wire: Wire,
    /// Set by `stop` and read at every seam entry and after every wait. The
    /// latch, and no longer the whole of `stop`: a wait already inside `poll`
    /// reads nothing, so the handle names the socket as well. See the module
    /// doc.
    stopped: std.atomic.Value(bool) = .init(false),

    /// Bind the seam to `handle`, which the caller owns and closes.
    ///
    /// Borrowed rather than opened because a `Datagram` is held by a
    /// `Retrieval` that is held by a stream, and a descriptor reached through
    /// a pointer into a value that had to be copied to be returned is a
    /// dangling one. Opening the socket is `transport/socket.zig`'s call and
    /// the caller makes it. The socket therefore has to outlive this value and
    /// every `Retrieval` begun from its `seam`; closing it first leaves those
    /// asks writing to a descriptor nobody owns.
    pub fn init(handle: *socket.Socket) Datagram {
        return .{
            .wire = .{
                .ctx = @ptrCast(handle),
                .send = sendOn,
                .receive = receiveOn,
                .stop = stopOn,
            },
        };
    }

    /// This value as the `lookup_io.Datagram` a `Retrieval` is begun with.
    ///
    /// The returned handle borrows this, so a `Retrieval` begun from it is dead
    /// the moment this value is moved or released, and `cancel` from
    /// `Stream.deinit` reads the latch through it — which is why a caller that
    /// wants its own copy of the handle keeps the `Datagram` alive until every
    /// stream is closed.
    pub fn seam(self: *Datagram) lookup_io.Datagram {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = sendQuery,
            .receive = receiveAnswer,
            .stop = stop,
        };
    }

    /// Whether the abort handle has fired, for a caller that would rather not
    /// start a lookup than ask and be refused. It is final: a `true` here is a
    /// `true` on every later read, and no ask this value makes will be sent.
    pub fn aborted(self: *const Datagram) bool {
        return self.stopped.load(.acquire);
    }
};

/// One query, as one datagram, to the server the retrieval named.
fn sendQuery(
    ctx: *anyopaque,
    // `ctx` is the vtable slot itself, not an ordinary parameter:
    // `lookup_io.Datagram.send` names it first and a reordered one is a
    // different function type. Z023 reads `*anyopaque` as a runtime value.
    // ziglint-ignore: Z023
    io: std.Io,
    to: addr.SocketAddr,
    bytes: []const u8,
) SocketError!void {
    const self: *Datagram = @ptrCast(@alignCast(ctx));
    // The abort can land between `Retrieval.ask`'s own check and this send,
    // and a query nobody is waiting for is the failure `resolve.Cancellation`
    // exists to stop.
    if (self.aborted()) return error.Canceled;
    self.wire.send(self.wire.ctx, io, to, bytes) catch |err| switch (err) {
        // `Io`'s own cancellation, which the socket asks about before it
        // writes. Everything else is one arm of the seam's three, `Refused`:
        // a full send queue is `EAGAIN`, which is backpressure rather than a
        // refusal, and absorbing it is a retry loop with a deadline this file
        // does not carry.
        error.Canceled => return error.Canceled,
        else => return error.Refused,
    };
}

/// One answer, in waits of at most `poll_slice_ms` until one arrives, the
/// deadline runs out, or the abort handle fires.
fn receiveAnswer(
    ctx: *anyopaque,
    // `ctx` is the vtable slot itself, not an ordinary parameter:
    // `lookup_io.Datagram.receive` names it first and a reordered one is a
    // different function type. Z023 reads `*anyopaque` as a runtime value.
    // ziglint-ignore: Z023
    io: std.Io,
    into: []u8,
    deadline_ms: ?i32,
) SocketError!Reply {
    const self: *Datagram = @ptrCast(@alignCast(ctx));
    if (self.aborted()) return error.Canceled;
    // A deadline at or below zero has already passed, and a negative one is
    // `poll`'s own spelling of "wait for ever" — which `Request` already has a
    // spelling for, in null. Refusing the read here is what stops a negative
    // deadline from becoming the one deadline this file cannot honour.
    if (deadline_ms != null and deadline_ms.? <= 0) return error.Empty;
    var left = deadline_ms;
    while (true) {
        const slice = @min(left orelse poll_slice_ms, poll_slice_ms);
        const got = self.wire.receive(self.wire.ctx, io, into, slice) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            // The wait ran out with nothing in it, which is the deadline
            // arriving rather than a failure: charge it to the budget, and a
            // stop that landed while the wait was in flight ends the wait now
            // and not at the end of it. Slicing the wait is the whole reason
            // there is anywhere to look.
            error.WouldBlock => {
                if (self.aborted()) return error.Canceled;
                if (left) |budget| {
                    if (budget <= poll_slice_ms) return error.Empty;
                    left = budget - poll_slice_ms;
                }
                continue;
            },
            else => return error.Refused,
        };
        if (self.aborted()) return error.Canceled;
        // One datagram is what this seam carries, and a read holding several
        // is not one; see the module doc's first section.
        const read = got.toRecv() catch return error.Refused;
        if (read.datagramCount() != 1) return error.Refused;
        return .{ .bytes = got.bytes, .from = got.from };
    }
}

/// `resolve.Cancellation` arriving: the latch, and the socket.
///
/// The latch is what the next call to this seam reads without touching the
/// descriptor, and it is one store, which is the whole of what a signal handler
/// may do — the reason this is a latch and not a queue. The socket is the other
/// half: a wait already inside `poll` reads nothing, so the handle writes a
/// descriptor the wait is watching. Both are needed and neither is enough; the
/// module doc has what each one is for.
fn stop(ctx: *anyopaque) void {
    const self: *Datagram = @ptrCast(@alignCast(ctx));
    self.stopped.store(true, .release);
    if (self.wire.stop) |name_it| name_it(self.wire.ctx);
}

// The section rule is 80 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────── the live socket arm

/// One query, on the descriptor the caller opened.
fn sendOn(
    ctx: *anyopaque,
    // `ctx` is the vtable slot itself, not an ordinary parameter: `Wire`'s
    // type names it first and a reordered one is a different function type.
    // Z023 reads `*anyopaque` as a plain runtime value.
    // ziglint-ignore: Z023
    io: std.Io,
    to: addr.SocketAddr,
    bytes: []const u8,
) socket.SendError!void {
    const handle: *socket.Socket = @ptrCast(@alignCast(ctx));
    const report = try handle.send(io, to, batch.Send.single(bytes, null));
    // Nothing was asked of the report and nothing could have been lost: a
    // single datagram has no segment size, which is what `batch.report` needs
    // for `degraded`, and a send that wanted no codepoint cannot have lost
    // one. Asserted rather than dropped, because a dropped report is how a
    // lost codepoint becomes invisible and `batch.Report` exists to stop that.
    std.debug.assert(!report.degraded);
}

/// One datagram, waiting at most `timeout_ms` for it.
fn receiveOn(
    ctx: *anyopaque,
    // `ctx` is the vtable slot itself, not an ordinary parameter: `Wire`'s
    // type names it first and a reordered one is a different function type.
    // Z023 reads `*anyopaque` as a plain runtime value.
    // ziglint-ignore: Z023
    io: std.Io,
    into: []u8,
    timeout_ms: ?i32,
) socket.ReceiveError!socket.Received {
    const handle: *socket.Socket = @ptrCast(@alignCast(ctx));
    // The control buffer is this call's rather than a field: `Received` holds
    // the stride and the codepoint as values, and nothing in it borrows the
    // blob the kernel wrote them into.
    var control: socket.ControlBuffer = undefined;
    return handle.receive(io, into, &control, timeout_ms);
}

/// The live arm's half of `stop`: the descriptor, and nothing else.
///
/// No `io` and no buffer, because both of the calls a stop could make here are
/// ones a signal handler is not allowed to make — the queue is emptied by the
/// wait the write wakes. See `Socket.stop`.
fn stopOn(ctx: *anyopaque) void {
    const handle: *socket.Socket = @ptrCast(@alignCast(ctx));
    handle.stop();
}

// The section rule is 79 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────────────────────── tests

const t = std.testing;
const Prng = std.Random.DefaultPrng;

/// The seed every test's node comes from, so the name asked and the answer
/// given are the same bytes on every run.
const seed = @as([key.SecretKey.seed_length]u8, @splat(7));

/// The name a lookup of the test's node is asked under, and the bytes its
/// framed query takes.
const asked_len = dns.queryNameLength(dns.prod_origin);
const asked_bytes = lookup_io.queryLength(&@as([asked_len:0]u8, @splat('x')));
/// Frame an answer to the question `query` carried: its own wire name, one TXT
/// record under it, and the flags the caller wants the header to carry.
///
/// The name is copied out of the framed query rather than encoded again, so
/// this cannot disagree with the encoder the query went out through.
/// `discovery/pkarr.zig`'s own captured packet answers this way too: no
/// question section, the name written once, in the record.
fn frameAnswer(
    out: []u8,
    query: []const u8,
    presentation: []const u8,
    id: u16,
    flags: u16,
    payload: []const u8,
) lookup_io.WireError![]const u8 {
    // §3.3.14's `<character-string>` is a length octet and that many octets,
    // so a string over 255 is not one this framing can carry.
    const payload_length: u8 = std.math.cast(u8, payload.len) orelse return error.BufferTooSmall;
    const wire_name = presentation.len + 1;
    // The name, then §4.1.3's TYPE, CLASS, TTL and RDLENGTH, then the length
    // octet and the string itself.
    const needed = lookup_io.header_length + wire_name + 10 + 1 + payload.len;
    if (out.len < needed) return error.BufferTooSmall;
    const owner = lookup_io.header_length;
    @memcpy(out[owner..][0..wire_name], query[owner..][0..wire_name]);
    var at = owner + wire_name;
    std.mem.writeInt(u16, out[at..][0..2], lookup_io.type_txt, .big);
    std.mem.writeInt(u16, out[at + 2 ..][0..2], lookup_io.class_in, .big);
    // The TTL, in seconds. Nothing reads it; 30 is what the reference
    // implementation's own packet carried.
    std.mem.writeInt(u32, out[at + 4 ..][0..4], 30, .big);
    std.mem.writeInt(u16, out[at + 8 ..][0..2], @as(u16, payload_length) + 1, .big);
    at += 10;
    out[at] = payload_length;
    @memcpy(out[at + 1 ..][0..payload.len], payload);
    at += 1 + payload.len;
    // §4.1.1's header: the transaction this answer belongs to, the flags under
    // test, no question section, and the one record.
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], flags, .big);
    std.mem.writeInt(u16, out[4..6], 0, .big);
    std.mem.writeInt(u16, out[6..8], 1, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);
    return out[0..at];
}

/// What the tests' lookups find, in `resolve_record.RecordSet`'s own shape.
const record = "relay=https://127.0.0.1/\x00";
/// That record without its separator, which is what one TXT character-string
/// carries on the wire.
const one_record = "relay=https://127.0.0.1/";

/// The server a scripted socket answers for, and a different one it answers
/// from, because a TXT answer carries no signature.
const nameserver: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 53 };

/// Loopback on an ephemeral port, which is what the tests that open a real
/// descriptor bind.
const loopback: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// A datagram socket that answers from a script and holds no descriptor.
///
/// Injected the way `net/probe_run.zig`'s fakes are: what the seam did to the
/// socket is recorded here and read by the test, rather than being asserted
/// about. No nameserver, no network, and no thread.
///
/// It holds no descriptor, and that is the one thing it cannot stand in for.
/// A stop on a wire with a descriptor behind it ends a wait and empties a
/// queue; a counter on this struct would be read by the test that wrote it and
/// by nothing else, which is the failure the module doc's abort section is
/// about. `wire` therefore carries no stop, and every claim about an abort
/// reaching a socket is made on a real one: the queue in the last test of this
/// file, and the wait in `transport/socket.zig`'s own.
const Scripted = struct {
    /// Enough for the longest deadline a test spends, and refused rather than
    /// overflowed: a script that ran out of room would look like a lookup that
    /// answered.
    const max_slices = 512;

    /// What the last send carried.
    sent: [asked_bytes]u8 = undefined,
    sent_len: usize = 0,
    sent_to: addr.SocketAddr = undefined,
    sends: u32 = 0,
    /// What a send fails with, for the sweep over `SendError`'s arms.
    send_fails: ?socket.SendError = null,
    /// The answer the next receive hands back, or null for a socket that
    /// answers nothing.
    reply: ?[]const u8 = null,
    /// Waits to let go by with nothing before the answer comes back, which is
    /// what shows a wait is repeated rather than run once to the end.
    reply_after: u32 = 0,
    /// What a receive fails with when there is no answer to hand back.
    fail: ?socket.ReceiveError = null,
    /// The `UDP_GRO` stride the kernel would have reported, for the read that
    /// carried more than one datagram.
    stride: ?usize = null,
    /// Who a scripted answer comes from. Off the server by default, because a
    /// TXT answer is unsigned.
    from: addr.SocketAddr,
    /// Every wait the seam asked the socket for, which is how a deadline is
    /// read without a clock.
    slices: [max_slices]i32 = undefined,
    slices_len: usize = 0,
    receives: u32 = 0,

    fn send(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Wire.send` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) socket.SendError!void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (self.send_fails) |failure| return failure;
        if (bytes.len > self.sent.len) return error.MessageTooLarge;
        @memcpy(self.sent[0..bytes.len], bytes);
        self.sent_len = bytes.len;
        self.sent_to = to;
        self.sends += 1;
    }

    fn receive(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Wire.receive` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        into: []u8,
        timeout_ms: ?i32,
    ) socket.ReceiveError!socket.Received {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.slices_len < self.slices.len);
        self.receives += 1;
        self.slices[self.slices_len] = timeout_ms orelse -1;
        self.slices_len += 1;
        if (self.fail) |failure| return failure;
        if (self.receives <= self.reply_after) return error.WouldBlock;
        const answer = self.reply orelse return error.WouldBlock;
        if (answer.len > into.len) return error.MessageTooLarge;
        @memcpy(into[0..answer.len], answer);
        return .{
            .bytes = into[0..answer.len],
            .from = self.from,
            .stride = self.stride,
            .ecn = null,
        };
    }

    fn wire(self: *Scripted) Wire {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = send,
            .receive = receive,
            .stop = null,
        };
    }
};

/// The buffers one `ask` writes into, both the caller's because neither
/// outlives the call.
const Buffers = struct {
    /// `lookup_io.queryLength` bytes for the framed query.
    wire: [asked_bytes]u8 = undefined,
    /// `lookup_io.reply_length` bytes for the answer: what a peer that honours
    /// the advertised size can send.
    reply: [lookup_io.reply_length]u8 = undefined,

    fn request(self: *Buffers, name: []const u8, deadline_ms: ?i32) lookup_io.Request {
        return .{
            .name = name,
            .wire = &self.wire,
            .reply = &self.reply,
            .deadline_ms = deadline_ms,
        };
    }
};

/// The question `retrieval` will send, framed here so an answer can be built
/// against the same bytes.
///
/// It is framed through the retrieval's own advertised size rather than a bare
/// query, because that OPT record is eleven bytes of the datagram that goes
/// out: a question framed without it is not the question the socket carries,
/// and the test that compares the two would be comparing a prefix.
fn questionFor(
    retrieval: lookup_io.Retrieval,
    name: []const u8,
    out: []u8,
) lookup_io.WireError![]const u8 {
    return lookup_io.writeQuery(name, .{
        .id = retrieval.id,
        .udp_payload = retrieval.udp_payload,
    }, out);
}

// There is no threaded abort test here, and the reason is worth writing down.
// `receiveAnswer` reads the latch after every slice, so a stop is noticed
// within `poll_slice_ms` however it arrives: a test that fired the handle from
// a second thread and asserted `error.Canceled` would pass with the latch
// alone. It cannot tell the wake from the slice boundary, and an assertion
// that cannot tell is not evidence. What the wake claims is a claim about a
// `poll` and a descriptor, so it is made where the `poll` is —
// `transport/socket.zig`'s own test, whose wait is five seconds long and must
// not take five seconds.

test "a query goes out on the socket and its answer comes back off it" {
    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var engine: Prng = .init(7);
    var retrieval = lookup_io.Retrieval.begin(datagram.seam(), nameserver, engine.random());
    var buffers: Buffers = .{};

    // Nothing answered, so this ask observes the framing, the send and the
    // deadline. The deadline is observed as 150 waits of 20 ms: a budget spent,
    // which is the only way a wait can be bounded without reading a clock.
    const silent = try retrieval.ask(t.allocator, t.io, buffers.request(name, 3000));
    try t.expectEqual(lookup_io.Answer.timeout, silent);
    try t.expectEqual(@as(u32, 1), script.sends);
    try t.expectEqual(nameserver, script.sent_to);
    try t.expectEqual(lookup_io.queryLength(name), script.sent_len);
    try t.expectEqual(retrieval.id, std.mem.readInt(u16, script.sent[0..2], .big));
    try t.expectEqual(@as(usize, 150), script.slices_len);
    const every_slice: [150]i32 = @splat(poll_slice_ms);
    try t.expectEqualSlices(i32, &every_slice, script.slices[0..script.slices_len]);

    // The answer is framed against the query that went out, so the two
    // encoders cannot disagree about the name.
    var answer: [lookup_io.reply_length]u8 = undefined;
    script.reply = try frameAnswer(
        &answer,
        script.sent[0..script.sent_len],
        name,
        retrieval.id,
        lookup_io.flag_response,
        one_record,
    );
    script.slices_len = 0;
    const read = try retrieval.ask(t.allocator, t.io, buffers.request(name, 3000));
    defer read.deinit(t.allocator);
    try t.expect(read.hasRecords());
    // One wait, because the answer was already in the queue: a deadline ends a
    // wait, it is not what every wait spends.
    try t.expectEqual(@as(usize, 1), script.slices_len);
    try t.expectEqual(poll_slice_ms, script.slices[0]);

    // The records are this call's and not the read buffer's — the fourth of the
    // seam's four things, proven rather than asserted.
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    @memset(&buffers.reply, 0xaa);
    try t.expectEqualStrings(record, records.bytes);
}

test "a deadline that runs out is a timeout, spent in slices that add up to it" {
    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var engine: Prng = .init(19);
    var retrieval = lookup_io.Retrieval.begin(datagram.seam(), nameserver, engine.random());
    var buffers: Buffers = .{};

    // 50 ms as 20 + 20 + 10: the slices add up to the deadline rather than
    // rounding past it, and the last wait is the remainder rather than a
    // twenty-first of a second over it.
    const late = try retrieval.ask(t.allocator, t.io, buffers.request(name, 50));
    try t.expectEqual(lookup_io.Answer.timeout, late);
    try t.expectEqualSlices(i32, &.{ 20, 20, 10 }, script.slices[0..script.slices_len]);

    // It is the third answer, not "this node published nothing": a caller that
    // read a timeout as an empty set would tell the world this node published
    // nothing, having learned nothing at all.
    try t.expect(!late.hasRecords());
}

test "a deadline that has already passed waits for nothing" {
    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var engine: Prng = .init(23);
    var retrieval = lookup_io.Retrieval.begin(datagram.seam(), nameserver, engine.random());
    var buffers: Buffers = .{};

    // Zero is a deadline in the past, and a negative one is `poll`'s own
    // spelling of "wait for ever" — which is the one wait this file cannot
    // bound, and which `Request` already spells as null.
    try t.expectEqual(
        lookup_io.Answer.timeout,
        try retrieval.ask(t.allocator, t.io, buffers.request(name, 0)),
    );
    try t.expectEqual(
        lookup_io.Answer.timeout,
        try retrieval.ask(t.allocator, t.io, buffers.request(name, -1)),
    );
    // Not one wait for either, and the query went out both times: the deadline
    // is what the wait costs, not what the ask does.
    try t.expectEqual(@as(u32, 0), script.receives);
    try t.expectEqual(@as(u32, 2), script.sends);
}

test "a wait with no deadline is still sliced, and a second wait is made" {
    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var engine: Prng = .init(29);
    var retrieval = lookup_io.Retrieval.begin(datagram.seam(), nameserver, engine.random());
    var buffers: Buffers = .{};
    var answer: [lookup_io.reply_length]u8 = undefined;
    const question = try questionFor(retrieval, name, &buffers.wire);
    script.reply = try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response,
        one_record,
    );
    script.reply_after = 1;

    // Null is "as long as you mean", and it is not one unbounded wait: two
    // waits of one slice each, which is what leaves anywhere for the abort
    // handle to be read.
    const read = try retrieval.ask(t.allocator, t.io, buffers.request(name, null));
    defer read.deinit(t.allocator);
    try t.expectEqualSlices(i32, &.{ poll_slice_ms, poll_slice_ms }, script.slices[0..2]);
    try t.expectEqual(@as(usize, 2), script.slices_len);
    try t.expect(read.hasRecords());
}

test "an abandoned resolve asks the socket for nothing at all" {
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var buffers: Buffers = .{};

    // The handle fired before anything was in flight, which is every path out
    // of a resolve that never got to asking. The socket is not touched on
    // either side of it: a flag nothing reads would satisfy every assertion
    // written about cancellation while the query sat in the queue.
    const seam = datagram.seam();
    seam.stop(seam.ctx);
    try t.expectError(error.Canceled, seam.send(seam.ctx, t.io, nameserver, "query"));
    try t.expectError(
        error.Canceled,
        seam.receive(seam.ctx, t.io, &buffers.reply, 3000),
    );
    try t.expectEqual(@as(u32, 0), script.sends);
    try t.expectEqual(@as(u32, 0), script.receives);
}

test "a truncated answer is refused, not read as a name that published nothing" {
    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var engine: Prng = .init(37);
    var retrieval = lookup_io.Retrieval.begin(datagram.seam(), nameserver, engine.random());
    var buffers: Buffers = .{};
    const question = try questionFor(retrieval, name, &buffers.wire);
    var answer: [lookup_io.reply_length]u8 = undefined;

    // §4.1.1's `TC`: the answer did not fit one datagram, and the rest of it is
    // somewhere a datagram socket cannot reach. RFC 1035 §4.2.2 retries it
    // over TCP, which `transport/socket.zig` has no socket for.
    script.reply = try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response | lookup_io.flag_truncated,
        one_record,
    );
    try t.expectError(
        error.Truncated,
        retrieval.ask(t.allocator, t.io, buffers.request(name, 3000)),
    );

    // The same framing with the bit clear is the records it carried, so the
    // refusal is the bit and not the answer — and never an empty set, which
    // reads as a name that exists with nothing published for it.
    script.reply = try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response,
        one_record,
    );
    const read = try retrieval.ask(t.allocator, t.io, buffers.request(name, 3000));
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(record, records.bytes);
}

test "a read that is not one datagram is refused rather than read as a prefix" {
    var script: Scripted = .{ .from = nameserver };
    var datagram: Datagram = .{ .wire = script.wire() };
    var buffers: Buffers = .{};
    const seam = datagram.seam();
    var answer: [lookup_io.reply_length * 2]u8 = @splat(0);

    // Three ways a real socket hands back bytes that are not the answer, and
    // one arm of the seam's three for each.
    //
    // A coalesced read: `Socket.create`'s probe turns `UDP_GRO` on, so the
    // kernel may return a list, and this seam carries one `bytes` field.
    script.reply = answer[0..16];
    script.stride = 8;
    try t.expectError(
        error.Refused,
        seam.receive(seam.ctx, t.io, &buffers.reply, 3000),
    );

    // A datagram of no bytes, which RFC 1035 has no message for.
    script.stride = null;
    script.reply = answer[0..0];
    try t.expectError(
        error.Refused,
        seam.receive(seam.ctx, t.io, &buffers.reply, 3000),
    );

    // A datagram larger than the buffer, so what is in the buffer is a prefix
    // of it. Parsed as a message, a prefix is a name with records nobody
    // published.
    script.reply = &answer;
    try t.expectError(
        error.Refused,
        seam.receive(seam.ctx, t.io, &buffers.reply, 3000),
    );
    try t.expectEqual(@as(u32, 3), script.receives);
}

test "every failure a socket can report is one of the three the seam has" {
    var buffers: Buffers = .{};
    // The whole set on each side, and the two arms that are not `Refused`:
    // `Io`'s own cancellation, and the wait that ran out with nothing in it.
    // A deadline of one millisecond so the seam's own `Empty` is reachable.
    inline for (@typeInfo(socket.ReceiveError).error_set.error_names.?) |member| {
        const failure: socket.ReceiveError = @field(socket.ReceiveError, member);
        var script: Scripted = .{ .from = nameserver, .fail = failure };
        var datagram: Datagram = .{ .wire = script.wire() };
        const seam = datagram.seam();
        const want: SocketError = switch (failure) {
            error.Canceled => error.Canceled,
            error.WouldBlock => error.Empty,
            else => error.Refused,
        };
        try t.expectError(want, seam.receive(seam.ctx, t.io, &buffers.reply, 1));
    }
    inline for (@typeInfo(socket.SendError).error_set.error_names.?) |member| {
        const failure: socket.SendError = @field(socket.SendError, member);
        var script: Scripted = .{ .from = nameserver, .send_fails = failure };
        var datagram: Datagram = .{ .wire = script.wire() };
        const seam = datagram.seam();
        const want: SocketError = if (failure == error.Canceled)
            error.Canceled
        else
            error.Refused;
        try t.expectError(want, seam.send(seam.ctx, t.io, nameserver, "query"));
    }
}

// The section rule is 80 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────────── real descriptors
//
// The four tests below open descriptors. They bind `127.0.0.1` on ephemeral
// ports and talk to each other, so they need no nameserver and no network and
// cannot be skipped for want of either: what they reach is
// `transport/socket.zig`'s syscalls underneath the seam, which an injected
// wire cannot.
//
// The last of them is about the abort, and it is here for the reason the
// scripted arm's `wire` carries no stop: an abort is a fact about a
// descriptor, and a script has none. It fires the handle the way
// `resolve.Stream.deinit` does and then reads the descriptor to see what the
// stop left on it. The other half — that a stop ends a wait already inside
// `poll` — is a claim about a `poll`, and is made in `transport/socket.zig`.

test "integration: a question and its answer cross a real socket" {
    var server = try socket.Socket.create(loopback, .{});
    defer server.close();
    var client = try socket.Socket.create(loopback, .{});
    defer client.close();
    var speaker = Datagram.init(&server);
    var seeker = Datagram.init(&client);
    var engine: Prng = .init(41);
    var retrieval = lookup_io.Retrieval.begin(seeker.seam(), server.address, engine.random());

    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var buffers: Buffers = .{};
    const question = try questionFor(retrieval, name, &buffers.wire);
    var answer: [lookup_io.reply_length]u8 = undefined;
    const framed = try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response,
        one_record,
    );

    // The answer goes on the wire first, so the seeker's own question lands in
    // the server's queue and is read afterwards: a datagram nobody has read
    // yet is queued by the kernel, not lost by a test.
    const out = speaker.seam();
    try out.send(out.ctx, t.io, client.address, framed);

    const read = try retrieval.ask(t.allocator, t.io, buffers.request(name, 3000));
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(record, records.bytes);

    // The question the seeker really sent, read on the server: byte for byte
    // the query the encoder framed, and from the address the seeker bound.
    var readback: [asked_bytes]u8 = undefined;
    var control: socket.ControlBuffer = undefined;
    const sent = try server.receive(t.io, &readback, &control, 3000);
    try t.expectEqualSlices(u8, question, sent.bytes);
    try t.expectEqual(client.address, sent.from);
}

test "integration: a deadline on a real socket is a timeout" {
    // A bound server that is never sent anything, rather than a port nobody
    // is on: an unbound one draws an ICMP refusal the socket reports on the
    // next read, which is `Refused` and not the third answer.
    var server = try socket.Socket.create(loopback, .{});
    defer server.close();
    var client = try socket.Socket.create(loopback, .{});
    defer client.close();
    var seeker = Datagram.init(&client);
    var engine: Prng = .init(43);
    var retrieval = lookup_io.Retrieval.begin(seeker.seam(), server.address, engine.random());

    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var buffers: Buffers = .{};

    // Thirty milliseconds of `poll` on a descriptor with nothing on it: the
    // wait ends because the deadline ran out, which is `Answer.timeout` and
    // not an answer set with nothing in it.
    try t.expectEqual(
        lookup_io.Answer.timeout,
        try retrieval.ask(t.allocator, t.io, buffers.request(name, 30)),
    );
}

test "integration: a truncated answer over a real socket is refused" {
    var server = try socket.Socket.create(loopback, .{});
    defer server.close();
    var client = try socket.Socket.create(loopback, .{});
    defer client.close();
    var speaker = Datagram.init(&server);
    var seeker = Datagram.init(&client);
    var engine: Prng = .init(47);
    var retrieval = lookup_io.Retrieval.begin(seeker.seam(), server.address, engine.random());

    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var buffers: Buffers = .{};
    const question = try questionFor(retrieval, name, &buffers.wire);
    var answer: [lookup_io.reply_length]u8 = undefined;

    const out = speaker.seam();
    try out.send(out.ctx, t.io, client.address, try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response | lookup_io.flag_truncated,
        one_record,
    ));

    // `TC` set, over a real socket: the answer did not fit one datagram and
    // the rest of it is somewhere this stack cannot reach, so the ask is
    // refused. Never an empty answer set, which reads as a name that exists
    // with nothing published for it.
    try t.expectError(
        error.Truncated,
        retrieval.ask(t.allocator, t.io, buffers.request(name, 3000)),
    );

    // The same answer with the bit clear, over the same socket and through the
    // same ask: the pair is what proves the refusal is `TC` and not the
    // framing.
    try out.send(out.ctx, t.io, client.address, try frameAnswer(
        &answer,
        question,
        name,
        retrieval.id,
        lookup_io.flag_response,
        one_record,
    ));
    const read = try retrieval.ask(t.allocator, t.io, buffers.request(name, 3000));
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(record, records.bytes);
}

test "integration: an abandoned lookup leaves nothing for the next one to read" {
    var server = try socket.Socket.create(loopback, .{});
    defer server.close();
    var client = try socket.Socket.create(loopback, .{});
    defer client.close();
    var speaker = Datagram.init(&server);
    var engine: Prng = .init(53);

    var secret = try key.SecretKey.fromSeed(seed);
    defer secret.deinit();
    var storage: [asked_len]u8 = undefined;
    const name = dns.queryName(&storage, secret.nodeId(), dns.prod_origin);
    var answer: [lookup_io.reply_length]u8 = undefined;

    // A lookup abandoned with its answer already in the queue. The two calls
    // are made by hand because `ask` makes them as one, and this needs the
    // lookup dropped between them — which is what `Stream.deinit` does on every
    // path out of a resolve, including the one that had not got to waiting.
    var dropped = Datagram.init(&client);
    var abandoned = lookup_io.Retrieval.begin(dropped.seam(), server.address, engine.random());
    var sent: Buffers = .{};
    const question = try questionFor(abandoned, name, &sent.wire);
    const spoke = dropped.seam();
    try spoke.send(spoke.ctx, t.io, server.address, question);
    const out = speaker.seam();
    try out.send(out.ctx, t.io, client.address, try frameAnswer(
        &answer,
        question,
        name,
        abandoned.id,
        lookup_io.flag_response,
        one_record,
    ));
    abandoned.cancellation().fire();
    try t.expectError(
        error.Canceled,
        spoke.receive(spoke.ctx, t.io, &sent.reply, 3000),
    );

    // The next lookup on the same descriptor, which is what a node does with one
    // socket: the abandoned resolve took its `Datagram` out of scope and the
    // socket stayed. Two ids, because an abandoned answer that parsed as this
    // one's would pass this test for the wrong reason.
    var live = Datagram.init(&client);
    var other: Prng = .init(59);
    var kept = lookup_io.Retrieval.begin(live.seam(), server.address, other.random());
    try t.expect(kept.id != abandoned.id);
    var buffers: Buffers = .{};
    const asked = try questionFor(kept, name, &buffers.wire);
    const asking = live.seam();

    // The query goes out, and the send takes the queue with it: a datagram that
    // was queued before this one went out cannot be this one's answer, so the
    // one the abandoned lookup left behind is gone before anybody can read it.
    // The answer comes afterwards, because a test with no thread to answer a
    // wait in progress has to put it in the queue before the wait starts — and
    // that is why the ask below sends the same query a second time. Two copies
    // of one query is a thing a nameserver is built to see.
    try asking.send(asking.ctx, t.io, server.address, asked);
    try out.send(out.ctx, t.io, client.address, try frameAnswer(
        &answer,
        asked,
        name,
        kept.id,
        lookup_io.flag_response,
        one_record,
    ));
    const read = try kept.ask(t.allocator, t.io, buffers.request(name, 3000));
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(record, records.bytes);
}
