//! The live DNS side: a `_iroh.<z32>.<origin>` TXT question put on a socket of
//! its own, and the answer handed to the resolver that already exists.
//!
//! `discovery/dns.zig` is the resolver and it opens nothing: it is handed a
//! `RecordSet` and streams an `Item` out of it. `discovery/lookup_io.zig` is the
//! seam — two calls and a stop, injected — and `discovery/lookup_live.zig` is one
//! implementation of it over `transport/socket.zig`. **This file is the second
//! implementation, and the reason there are two is the whole of its subject.**
//!
//! # Why DNS gets a descriptor of its own
//!
//! `lookup_live.Datagram` *borrows* a socket: `init` takes a `*socket.Socket`
//! the caller opened, and the seam outlives neither. That is right for a caller
//! that already has one and wrong for a discovery path on a node whose gossip
//! socket is already carrying traffic. Two facts make sharing wrong, and both
//! are about the queue rather than the wire:
//!
//! 1. **A lookup would consume a datagram meant for gossip.** The socket is a
//!    queue. `lookup_io.Retrieval.ask` sends one question and reads one
//!    datagram, matching it by transaction id — but the datagram it consumed is
//!    gone from the queue, and the gossip receiver that was going to read it
//!    never will. A node's gossip socket carries hyparview and plumtree
//!    traffic; losing one of those to a DNS question is a liveness failure with
//!    no error anywhere.
//! 2. **A cancellation reaching a shared descriptor would empty another
//!    subsystem's queue.** `transport/socket.zig`'s `Socket.stop` is not a
//!    latch: it "leaves the queue as though nothing had ever been asked of it",
//!    because a stopped datagram socket is still usable and the queue's
//!    contents are datagrams nobody read and nobody is going to. That is right
//!    for a socket one owner stops and wrong for a socket two owners share:
//!    `resolve.Stream.deinit` fires `resolve.Cancellation` on every path out of
//!    a resolve, so an abandoned DNS lookup would drain the gossip queue with
//!    it.
//!
//! The two are the same fact seen from both ends — one queue, one owner — and
//! `Socket.stop`'s own doc is where the second half is argued. A descriptor per
//! subsystem is the fix for both, and it is cheap: a UDP socket is one file
//! descriptor and one `eventfd`.
//!
//! # Timeout and empty are different outcomes, and this file keeps them apart
//!
//! The question asks for two things at once and the caller has to tell them
//! apart, because `item.Resolution` and `docs/ARCHITECTURE.md` invariant 13
//! make them different facts:
//!
//! * **An answer that arrived and carried nothing** is a fact about the world:
//!   the name exists and this node published nothing under it.
//!   `lookup_answer.Answer.nothing` is the arm, and a caller that builds
//!   `Resolver.service` over it gets a service that ran and came back with no
//!   items — `Resolution.resolved` with an empty slice.
//! * **An answer that timed out** is a fact about the clock, not about the
//!   world. Nobody said the node published nothing; a nameserver was slow or
//!   unreachable. `lookup_answer.Answer.timeout` is the arm, and it is *not*
//!   mapped onto `nothing` and *not* onto `Resolution.cannot_resolve` either —
//!   `cannot_resolve` stops the walk, and upstream says the opposite in as many
//!   words: "a single failing service must not hide results from the others
//!   still in flight" (`iroh/src/address_lookup.rs:584`). A slow nameserver
//!   that ended the walk would hide every other source.
//!
//! So the arms given them are `Answer.timeout` and `Answer.nothing`, unchanged
//! and unnamed, and what this file adds is the seam that reaches them:
//! `Resolver.ask` returns `Answer`, not a bool and not an item. Collapsing them
//! here would make the collapse invisible above this file, and the whole reason
//! `lookup_io.zig` documents the distinction is that a collapse stays invisible
//! until a walk ends early for a reason nobody can name.
//!
//! # Entropy is the caller's, and `io` is a parameter
//!
//! The transaction id is a parameter of `Resolver.begin`, so the caller draws it
//! from its own generator and this file holds none. `io: std.Io` is a parameter
//! of every call and is stored nowhere, for the reason
//! `docs/DECISIONS/0002-async-substrate.md` gives: a struct holding an `Io`
//! cannot be driven twice with different runtimes. `Resolver` owns a socket, a
//! server address and a stop latch, and those are the only three things it has.
//!
//! # What is not here
//!
//! No `TC`-to-TCP retry. `lookup_answer.readHeader` refuses a truncated answer
//! as `error.Truncated` before this file is asked anything, and
//! `discovery/host_io.zig` already says what the retry is — RFC 1035 §4.2.2's
//! two-octet length prefix over `transport/tcp.zig` — as a value a caller
//! holding both owns. This file owns no stream, so it makes no retry; adding one
//! would mean opening a second transport in a file whose subject is that one
//! descriptor is enough.
//!
//! Also not here: the origin's nameserver. `Resolver` takes the server address
//! it asks, because a resolver that picked one itself would be a resolver policy
//! — `discovery/host_io.zig`'s staggering table is that policy, as a value — and
//! because `/etc/resolv.conf` is an environment read this tree does not do.

const std = @import("std");

const resolve = @import("resolve.zig");

const addr = @import("../base/addr.zig");
const dns = @import("dns.zig");
const key = @import("../base/key.zig");
const socket = @import("../transport/socket.zig");

const batch = @import("../transport/batch.zig");

const item = @import("item.zig");
const answer = @import("lookup_answer.zig");
const lookup_io = @import("lookup_io.zig");
const query = @import("lookup_query.zig");
const lookup_live = @import("lookup_live.zig");
const wire = @import("lookup_wire.zig");

/// Everything one live lookup can fail with.
///
/// `lookup_io.Error` plus the socket's own open failures. The other two calls
/// this file makes — send and receive — cannot produce a new arm: they are
/// mapped onto `lookup_io.SocketError`'s three by `sendQuery`, `receiveAnswer`
/// and `stopResolver`, which is `lookup_live`'s mapping and is why the arms are
/// the same three.
pub const Error = socket.OpenError || lookup_io.Error;

/// What one lookup came to. `lookup_io.Answer`, named here so a caller of this
/// file never reaches for the facade to name it.
pub const Answer = lookup_io.Answer;

/// What one `ask` writes and how long it waits. See `lookup_io.Request`.
pub const Request = lookup_io.Request;

/// How long one wait lasts before its slice is charged.
///
/// `lookup_live.poll_slice_ms`, reached through the module that owns the first
/// live arm rather than restated: two live arms with two slice lengths would be
/// two conventions for one fact, and the reasoning for the value is
/// `lookup_live`'s.
pub const poll_slice_ms: i32 = lookup_live.poll_slice_ms;

/// The datagram size a reply is read into, which is what a peer honouring the
/// advertised size can send.
pub const reply_length = lookup_io.reply_length;

/// What a query advertises it can receive. RFC 6891 §6.2.3's `CLASS`, 1232.
pub const max_udp_payload = lookup_io.max_udp_payload;

/// A resolver bound to one nameserver, over a datagram socket of its own.
///
/// `open` opens the socket and `close` closes it, and this value is the only
/// thing that knows its address. **Copies are handles, not a second owner**: a
/// copy shares one descriptor, and two owners sharing one descriptor is the
/// failure this module doc is about.
pub const Resolver = struct {
    /// The descriptor and its wake, borrowed by every call below. Both are this
    /// value's, and `close` closes them exactly once.
    handle: socket.Socket,
    /// The server every question goes to, by value. RFC 1035 §7.2's "the client
    /// should try other servers before repeating a query" is a policy and needs
    /// an instant this value deliberately does not carry, so one resolver asks
    /// one server.
    server: addr.SocketAddr,
    /// Set by `stopResolver` and read at every seam entry. Terminal, and the
    /// reason a stopped resolver cannot be asked: `resolve.Stream.deinit` fires
    /// on every path out of a resolve, so an abandoned resolve must not leave a
    /// query going out under a socket somebody has released.
    stopped: std.atomic.Value(bool) = .init(false),

    /// Open a socket bound to `local` and ask `server`.
    ///
    /// `local` is a bind address, so a caller that wants the kernel's choice
    /// passes port zero. Nothing is sent: a query is an `ask`, and an `ask` is
    /// one datagram out and one in.
    pub fn open(
        local: addr.SocketAddr,
        server: addr.SocketAddr,
        options: socket.Options,
    ) socket.OpenError!Resolver {
        return .{
            .handle = try socket.Socket.create(local, options),
            .server = server,
        };
    }

    /// Close both descriptors. Nothing is buffered on this side: a write that
    /// returned has left the socket and a read that returned has been taken. Do
    /// not close a copy, and do not call this twice.
    pub fn close(self: *Resolver) void {
        self.handle.close();
    }

    /// Where this socket is bound, with the ephemeral port the kernel chose.
    ///
    /// A copy, and not `handle.address`, because reading another module's field
    /// to learn a port is a coupling a caller should not need: a caller that
    /// wants to run its own nameserver on the same host names it here.
    pub fn bound(self: *const Resolver) addr.SocketAddr {
        return self.handle.address;
    }

    /// Whether this resolver has been stopped, for a caller that would rather
    /// not ask than ask and be refused. Final: a `true` here is a `true` on
    /// every later read.
    pub fn stoppedAlready(self: *const Resolver) bool {
        return self.stopped.load(.acquire);
    }

    /// `resolve.Cancellation` over the whole resolver: `fire` stops this
    /// subsystem's socket for good.
    ///
    /// The service-wide handle, and a separate thing from
    /// `Retrieval.cancellation`, which stops one resolve. A resolver's stop is
    /// terminal — the socket has drained its queue and nothing arriving on it is
    /// wanted until a send, and a discovery path that was shut down is not
    /// restarted by the next resolve. A caller that wants to stop one lookup and
    /// keep asking takes the retrieval's handle.
    ///
    /// Borrowed, for the reason `lookup_live.Datagram.seam` gives: the handle
    /// points at this value, so it has to outlive every resolve started through
    /// it.
    pub fn cancellation(self: *Resolver) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stopResolver };
    }

    /// The seam a `lookup_io.Retrieval` is begun from.
    ///
    /// Three function pointers and a context, so it is cheap and it borrows
    /// this value: the retrieval it begins and this resolver must both outlive
    /// every `ask` made through it.
    pub fn seam(self: *Resolver) lookup_io.Datagram {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = sendQuery,
            .receive = receiveAnswer,
            .stop = stopResolver,
        };
    }

    /// Start one lookup under `id` as its transaction.
    ///
    /// The id is a parameter rather than a draw because RFC 1035 §4.1.1's `ID`
    /// "is copied into the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries": it is the one thing on the
    /// wire a resolver must not predict, and a caller holding a seeded generator
    /// can drive it at a fixed one. A caller that wants two questions to be
    /// distinguishable asks twice with two ids.
    pub fn begin(self: *Resolver, id: u16) Retrieval {
        return .{ .datagram = self.seam(), .server = self.server, .id = id };
    }

    /// The whole path in one call: begin under `id` and ask once.
    ///
    /// A convenience over `begin` and `Retrieval.ask` and not a second of
    /// them, because the two halves share nothing a caller could get wrong
    /// between them — the retrieval borrows this resolver either way, and its
    /// `server` and `id` are the two fields `begin` fills.
    pub fn lookup(
        self: *Resolver,
        alloc: std.mem.Allocator,
        io: std.Io,
        id: u16,
        request: Request,
    ) Error!Answer {
        return self.begin(id).ask(alloc, io, request);
    }

    /// The service `discovery/dns.zig` resolves, over `records`.
    ///
    /// A free function and not a method, because it needs nothing from a
    /// resolver: it is the one step between an answer and the pipeline that
    /// already exists, and it is deliberately a step a caller takes rather than
    /// one this file takes on their behalf.
    ///
    /// **Which arm may be handed here is the module doc's whole subject.** Both
    /// `Answer.nothing` and `Answer.timeout` carry no records, and building a
    /// service over either would make them one: `DnsAddressLookup` holds a
    /// `RecordSet` and streams an `Item` out of it, so a stream over an empty
    /// record set reads as "resolved to nothing" — right for `nothing` and a lie
    /// for `timeout`. A caller matches the arm itself.
    pub fn service(
        records: resolve.RecordSet,
        stop: ?resolve.Cancellation,
    ) dns.DnsAddressLookup {
        return dns.DnsAddressLookup.init(records, stop);
    }
};

/// One lookup in flight: the seam, the server, and the transaction.
///
/// A struct rather than a bare `lookup_io.Retrieval` so this file's `begin` can
/// hand back a value with its fields already filled, and so `ask` reads as this
/// file's operation. It borrows the resolver it came from and is worth copying:
/// a copy has its own stop latch and the same seam.
pub const Retrieval = struct {
    /// The two calls and a stop, borrowed from the resolver that opened them.
    datagram: lookup_io.Datagram,
    /// Who the question goes to, kept so a datagram from anywhere else is
    /// refused. A TXT answer carries no signature, so the source address is the
    /// only thing standing between a lookup and a forged one.
    server: addr.SocketAddr,
    /// RFC 1035 §4.1.1's `ID`, chosen by the caller.
    id: u16,
    /// What the query advertises it can receive. See `max_udp_payload`.
    udp_payload: u16 = max_udp_payload,
    /// One decoded owner name, so matching an answer's records against the name
    /// asked about allocates nothing. Fixed-size because RFC 1035 §2.3.4 caps a
    /// name, which makes this a bound rather than a guess.
    owner: [wire.max_name_length]u8 = undefined,

    /// Set by `stopRetrieval`, read at every seam entry and after every wait.
    stopped: std.atomic.Value(bool) = .init(false),

    /// `resolve.Cancellation` over this one lookup. `fire` reaches the socket
    /// through the seam, which is what makes an abandoned resolve stop its
    /// query rather than only its own bookkeeping.
    ///
    /// Separate from `Resolver.cancellation` on purpose: this one ends one
    /// ask and the socket stays usable for the next, and a resolver whose every
    /// resolve stopped its socket would resolve exactly once.
    pub fn cancellation(self: *Retrieval) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stopRetrieval };
    }

    /// Whether this retrieval's abort has fired, for a caller that would rather
    /// not start than ask and be refused.
    pub fn aborted(self: *const Retrieval) bool {
        return self.stopped.load(.acquire);
    }

    /// Ask once and read the answer once. See `Resolver.ask`, whose doc is this
    /// one's; the two differ only in that this one carries the server and the id
    /// and so needs neither argument.
    pub fn ask(
        self: *Retrieval,
        alloc: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!Answer {
        if (self.stopped.load(.acquire)) return error.Canceled;
        const framed = try query.writeQuery(request.name, .{
            .id = self.id,
            .udp_payload = self.udp_payload,
        }, request.wire);
        try self.datagram.send(self.datagram.ctx, io, self.server, framed);
        const reply = self.datagram.receive(
            self.datagram.ctx,
            io,
            request.reply,
            request.deadline_ms,
        ) catch |err| {
            if (self.stopped.load(.acquire)) return error.Canceled;
            return switch (err) {
                error.Empty => .{ .timeout = {} },
                else => |rest| rest,
            };
        };
        // A reply that arrived after a stop is not an answer to deliver.
        if (self.stopped.load(.acquire)) return error.Canceled;
        if (reply.from.order(self.server) != .eq) return error.ForeignSource;
        return answer.readAnswer(alloc, reply.bytes, request.name, self.id, &self.owner);
    }
};

/// One query, as one datagram, to the server the retrieval named.
///
/// The abort can land between the caller's own check and this send, and a query
/// nobody is waiting for is the failure `resolve.Cancellation` exists to stop.
fn sendQuery(
    ctx: *anyopaque,
    // `ctx` is the vtable slot itself, not an ordinary parameter:
    // `lookup_io.Datagram.send` names it first and a reordered one is a
    // different function type. Z023 reads `*anyopaque` as a runtime value.
    // ziglint-ignore: Z023
    io: std.Io,
    to: addr.SocketAddr,
    bytes: []const u8,
) lookup_io.SocketError!void {
    const self: *Resolver = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    const report = self.handle.send(
        io,
        to,
        batch.Send.single(bytes, null),
    ) catch |err| switch (err) {
        // `Io`'s own cancellation, which the socket asks about before it
        // writes. Everything else is the seam's third arm, `Refused`: a full
        // send queue is `EAGAIN`, which is backpressure rather than a refusal,
        // and absorbing it is a retry loop with a deadline this file does not
        // carry.
        error.Canceled => return error.Canceled,
        else => return error.Refused,
    };
    // Nothing was asked of the report and nothing could have been lost: a single
    // datagram has no segment size, which is what `batch.Report` needs for
    // `degraded`, and a send that wanted no codepoint cannot have lost one.
    // Asserted rather than dropped, because a dropped report is how a lost
    // codepoint becomes invisible and `batch.Report` exists to stop that.
    std.debug.assert(!report.degraded);
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
) lookup_io.SocketError!lookup_io.Datagram.Reply {
    const self: *Resolver = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    // A deadline at or below zero has already passed, and a negative one is
    // `poll`'s own spelling of "wait for ever" — which `Request` already has a
    // spelling for, in null. Refusing the read here is what stops a negative
    // deadline from becoming the one deadline this file cannot honour.
    if (deadline_ms != null and deadline_ms.? <= 0) return error.Empty;
    var left = deadline_ms;
    while (true) {
        const slice = @min(left orelse poll_slice_ms, poll_slice_ms);
        // The control buffer is this call's rather than a field: the reply
        // carries the stride and the codepoint as values, and nothing in it
        // borrows the blob the kernel wrote them into.
        var control: socket.ControlBuffer = undefined;
        const got = self.handle.receive(io, into, &control, slice) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            // The wait ran out with nothing in it, which is the deadline
            // arriving rather than a failure: charge it to the budget, and a
            // stop that landed while the wait was in flight ends the wait now
            // and not at the end of its slice. Slicing the wait is the whole
            // reason there is anywhere to look.
            error.WouldBlock => {
                if (self.stopped.load(.acquire)) return error.Canceled;
                if (left) |budget| {
                    if (budget <= poll_slice_ms) return error.Empty;
                    left = budget - poll_slice_ms;
                }
                continue;
            },
            else => return error.Refused,
        };
        if (self.stopped.load(.acquire)) return error.Canceled;
        // One datagram is what this seam carries, and a read holding several is
        // not one: `Socket.create` probes the socket and that probe turns
        // `UDP_GRO` on, so the kernel is free to coalesce, and nothing above
        // this file can say which of the several was the question's answer.
        const read = got.toRecv() catch return error.Refused;
        if (read.datagramCount() != 1) return error.Refused;
        return .{ .bytes = got.bytes, .from = got.from };
    }
}

/// A resolver's stop: the latch, and the descriptor.
///
/// Both halves are `transport/socket.zig`'s `Socket.stop` and `lookup_live`'s
/// `Datagram.stop`, and both are here for their reasons. The latch is what a
/// send and a wait between two slices read; the descriptor is the only thing
/// that can end a wait already inside `poll`. Neither is enough alone, which is
/// what `lookup_live`'s module doc argues in full.
///
/// It is also the seam's `stop`, and that is one function rather than two: a
/// resolver's descriptor and a resolver's seam are the same descriptor, and a
/// stop that reached one and not the other would be a stop that half worked.
fn stopResolver(ctx: *anyopaque) void {
    const self: *Resolver = @ptrCast(@alignCast(ctx));
    self.stopped.store(true, .release);
    self.handle.stop();
}

/// One retrieval's stop: mark it, then stop the socket the seam names.
///
/// The order is what makes a second `fire` cheap rather than wrong:
/// `resolve.Stream.deinit` fires on every path out of a resolve, so the flag is
/// set first and the socket is told once.
fn stopRetrieval(ctx: *anyopaque) void {
    const self: *Retrieval = @ptrCast(@alignCast(ctx));
    if (self.stopped.swap(true, .acq_rel)) return;
    self.datagram.stop(self.datagram.ctx);
}

const t = std.testing;
const support = @import("lookup_test_support.zig");

/// The node the captured answer is about: the key that signed it, from the seed
/// `discovery/lookup_test_support.zig` says produced the packet.
fn capturedNode() !addr.NodeId {
    var secret = try key.SecretKey.fromSeed(support.captured_seed);
    defer secret.deinit();
    return secret.nodeId();
}

/// The name those records are published under: `_iroh.<z32>.`, with no origin.
///
/// The captured answer's own name, and deliberately not a
/// `_iroh.<z32>.dns.iroh.link.` one: the vector is the bytes under test, and
/// renaming them would test a name instead.
fn capturedNameOf(id: addr.NodeId, out: []u8) ![]const u8 {
    return support.capturedName(id, out);
}

test "an answer with records becomes the DNS service, and its item is the answer's" {
    const id = try capturedNode();
    var name: [wire.max_name_length]u8 = undefined;
    const asked = try capturedNameOf(id, &name);

    // The captured answer, read under the transaction it is asked about. §4.1.1
    // has the answer echo the question's `ID`, so the vector has to be told what
    // to echo: it was captured answering transaction zero.
    var framed: [reply_length]u8 = undefined;
    const message = try support.hexBytes(&framed, support.captured_answer_hex);
    wire.put16(message, 0, 7);
    var owner: [wire.max_name_length]u8 = undefined;
    const read = try answer.readAnswer(t.allocator, message, asked, 7, &owner);
    defer read.deinit(t.allocator);

    // `.records` is the only arm that carries a service, and this is it.
    try t.expect(std.meta.activeTag(read) == .records);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(support.captured_record, records.bytes);

    var service = Resolver.service(records, null);
    const handle = service.lookup();
    var stream = (try handle.resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const event = stream.next() orelse return error.TestUnexpectedResult;
    const found = switch (event) {
        .item => |value| value,
        else => return error.ExpectedRecords,
    };
    // The provenance is `discovery/dns.zig`'s and the address is the record's,
    // which is the whole of the answer-to-record conversion.
    try t.expectEqual(item.Provenance.dns, found.provenance);
    try t.expectEqual(@as(usize, 1), found.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://example.com/"),
        found.endpoint.addrs[0].relay,
    );
    // And the resolution is one item rather than an empty one, because records
    // arrived. `finish` is readable only once a pull has answered null, and
    // that pull is half the claim: one item, and nothing after it.
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(usize, 1), stream.finish().itemCount().?);
}

test "a timeout and an empty answer are two arms, and neither carries a service" {
    const id = try capturedNode();
    var name: [wire.max_name_length]u8 = undefined;
    const asked = try capturedNameOf(id, &name);

    // Nothing answered inside the deadline: the arm a walk carries on past,
    // because `Resolution.cannot_resolve` would end it.
    const timed_out: Answer = .timeout;
    try t.expectEqual(Answer.timeout, timed_out);
    try t.expect(!timed_out.hasRecords());

    // An answer arrived and carried no record under the name asked about. This
    // is RFC 1035's NOERROR with an empty answer section: `QR` set, the
    // transaction echoed, the question the reply answers, and no answers. The
    // question section is the one `lookup_query.writeQuery` puts on the wire,
    // made into a response by setting `QR` — a header claiming a question it
    // does not carry is a malformed message, not an empty answer.
    var buffer: [reply_length]u8 = undefined;
    const message = try query.writeQuery(asked, .{ .id = 11 }, &buffer);
    wire.put16(buffer[0..message.len], 2, wire.flag_response);
    var owner: [wire.max_name_length]u8 = undefined;
    const nothing = try answer.readAnswer(t.allocator, message, asked, 11, &owner);
    defer nothing.deinit(t.allocator);
    try t.expectEqual(Answer.nothing, nothing);
    try t.expect(!nothing.hasRecords());

    // The two are distinguishable, which is the whole of the claim: a caller
    // switching on this union cannot act the same way on both, and neither arm
    // has records for `Resolver.service` to build from.
    try t.expect(std.meta.activeTag(timed_out) != std.meta.activeTag(nothing));
    // The `records` arm is the third one and it is the only one that carries
    // records, which is what `Resolver.service` needs.
    const with_records: Answer = .{ .records = .init("relay=https://one.example./\x00") };
    try t.expect(with_records.hasRecords());
}

test "a name that does not exist is refused, which is a third fact again" {
    const id = try capturedNode();
    var name: [wire.max_name_length]u8 = undefined;
    const asked = try capturedNameOf(id, &name);

    // `NXDOMAIN`, RFC 1035 §3.2.1: the name is not there at all. Upstream's
    // `lookup_txt` treats that as an error rather than as an answer with nothing
    // in it (`iroh-dns/src/dns.rs`), and so does the decoder — which is why it
    // is neither of the two arms above.
    var message: [wire.header_length]u8 = undefined;
    wire.put16(&message, 0, 3);
    wire.put16(&message, 2, wire.flag_response | 3);
    wire.put16(&message, 4, 1);
    var owner: [wire.max_name_length]u8 = undefined;
    try t.expectError(
        error.NameError,
        answer.readAnswer(t.allocator, &message, asked, 3, &owner),
    );
}

test "the descriptor is this resolver's own, and a stop reaches it" {
    var resolver = try Resolver.open(
        .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
        support.nameserver,
        .{},
    );
    defer resolver.close();

    // A real descriptor, bound to a real ephemeral port, and nothing sent: a
    // query is an `ask`.
    const local = resolver.bound();
    try t.expectEqual(std.math.Order.eq, local.ip.order(.{ .v4 = .{ 127, 0, 0, 1 } }));
    try t.expect(local.port != 0);
    try t.expect(!resolver.stoppedAlready());

    // A stop is terminal and final, and it reaches the descriptor rather than a
    // flag this test already owns.
    resolver.cancellation().fire();
    try t.expect(resolver.stoppedAlready());
    try t.expect(resolver.handle.stopped.load(.acquire));

    // A second fire is free, because `Stream.deinit` fires on every path out of
    // a resolve including the ones with nothing in flight.
    resolver.cancellation().fire();
    try t.expect(resolver.handle.stopped.load(.acquire));

    // And the seam agrees: a stopped resolver sends nothing, because both
    // halves of the seam read the latch before touching the descriptor.
    const seam = resolver.seam();
    try t.expectError(
        error.Canceled,
        seam.send(seam.ctx, t.io, support.nameserver, &.{}),
    );
}
