//! One lookup in flight, and the handle that stops it.
//!
//! This is where the seam's four things meet: `begin` draws the transaction id
//! from the caller's generator, `ask` frames a question through
//! `lookup_query.zig` and reads the reply back through `lookup_answer.zig`, the
//! deadline rides on `Request`, and `cancellation` reaches
//! `lookup_datagram.Datagram.stop`. It is also the only module above both halves
//! of the wire, so it is the only place the seam's error set is closed.

const std = @import("std");

const dns = @import("dns.zig");
const key = @import("../base/key.zig");
const addr = @import("../base/addr.zig");
const resolve = @import("resolve.zig");

const answer = @import("lookup_answer.zig");
const seam = @import("lookup_datagram.zig");
const query = @import("lookup_query.zig");
const wire = @import("lookup_wire.zig");

/// Everything one lookup can fail with: the wire's failures, the socket's, and
/// the allocator's.
///
/// `OutOfMemory` is here because the answer is copied into `alloc` and that copy
/// is the fourth of the seam's four things. Nothing else here allocates.
///
/// The union closes here and not in either half: `lookup_answer.zig` names only
/// what a decoder can return and `lookup_datagram.zig` only what an injected
/// socket can, and this module is above both. One direction, seam to codec.
pub const Error = wire.WireError || seam.SocketError || error{OutOfMemory};

/// One lookup in flight, and the handle that stops it.
///
/// A value the caller owns, holding a descriptor it was handed and nothing
/// else: no allocator, no runtime, no clock. The four seam-supplied things sit
/// on it — the query and the answer through `ask`, the deadline through
/// `Request`, the transaction id through `begin`, and the abort through
/// `cancellation`.
///
/// Two of its fields are state rather than configuration. `stopped` is
/// terminal: `cancellation().fire()` sets it, and every later `ask` answers
/// `error.Canceled` — a retrieval that was stopped is one that will not ask
/// again, which is a state rather than a failure to retry. `owner` is scratch,
/// reused by every ask, and nothing handed out points into it: the records that
/// leave an ask are copies.
///
/// Serialize `ask` calls. After `cancellation`, keep this value at the same
/// address until all asks and fires return. Cancellation may run concurrently;
/// its callback must synchronize with send and receive. It does not join them.
/// Copies have separate latches but share the borrowed datagram context.
pub const Retrieval = struct {
    /// The socket to ask, borrowed. It, and everything its `ctx` reaches, has to
    /// outlive this retrieval and every ask made through it, because an ask
    /// reads all three of its functions.
    datagram: seam.Datagram,
    /// Who the question goes to, kept so a datagram from anywhere else can be
    /// refused. A TXT answer carries no signature, so the source address is the
    /// only thing standing between a lookup and a forged one.
    server: addr.SocketAddr,
    /// RFC 1035 §4.1.1's `ID`. Drawn here and not read from a global, because
    /// it is the one thing on the wire a resolver must not predict and this
    /// file is not allowed a global.
    id: u16,
    /// What the query advertises it can receive. See `max_udp_payload`.
    udp_payload: u16 = wire.max_udp_payload,
    /// Set by `cancellation`, and the reason `ask` refuses rather than waits.
    stopped: std.atomic.Value(bool) = .init(false),
    /// One decoded owner name, so matching an answer's records against the name
    /// asked about allocates nothing. Fixed-size because RFC 1035 §2.3.4 caps a
    /// name, which makes this a bound rather than a guess.
    owner: [wire.max_name_length]u8 = undefined,

    /// Start a lookup: one transaction id, drawn from `random`.
    ///
    /// Nothing is sent. A send is an `ask`, and an `ask` is one datagram out and
    /// one in — RFC 1035 §7.2's "the client should try other servers before
    /// repeating a query" is a policy, and a policy needs an instant this value
    /// deliberately does not carry.
    pub fn begin(
        datagram: seam.Datagram,
        server: addr.SocketAddr,
        random: std.Random,
    ) Retrieval {
        return .{
            .datagram = datagram,
            .server = server,
            .id = random.int(u16),
        };
    }

    /// `resolve.Cancellation` over this retrieval: `fire` reaches the socket.
    ///
    /// The one handle invariant 13 is about, and it points at the producer
    /// rather than at this struct's state — `resolve.Cancellation` says so, and
    /// a stream that cancelled only itself would be exactly the failure the
    /// invariant names.
    pub fn cancellation(self: *Retrieval) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stopRetrieval };
    }

    /// Ask, and read the answer, once.
    ///
    /// `request.name` is `_iroh.<z32>.<origin>` in presentation form, built by
    /// `discovery/dns.zig`'s `queryName` into storage the caller owns. What
    /// comes back is this call's to free with `Answer.deinit`.
    ///
    /// Waits for a datagram, deadline or stop through the supplied seam.
    /// Stop is checked before I/O and after receive. An observed stop returns
    /// `error.Canceled`, including when receive reports a concurrent timeout.
    /// A result can win if cancellation comes after the final check.
    ///
    /// Both buffers are caller-owned scratch and may retain old bytes.
    /// `wire` changes during query encoding; `reply` changes only as the seam
    /// receives into it. An early cancellation can leave both untouched.
    /// Errors release any answer allocation, but do not restore scratch,
    /// undo a sent query, or return a consumed datagram to the socket.
    ///
    /// This is not a retry. The transaction id was drawn once by `begin`, so a
    /// second ask asks the same question and will read the first one's late
    /// answer if one is still coming. Repeating a query is RFC 1035 §7.2's
    /// policy and needs an instant this value does not carry, so a caller that
    /// wants one begins another retrieval with another id.
    pub fn ask(
        self: *Retrieval,
        alloc: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!answer.Answer {
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
        // A reply that arrived after stop is not an answer to deliver.
        if (self.stopped.load(.acquire)) return error.Canceled;
        if (reply.from.order(self.server) != .eq) return error.ForeignSource;
        return answer.readAnswer(alloc, reply.bytes, request.name, self.id, self.owner[0..]);
    }
};

/// One retrieval's stop: mark it, then stop the socket.
///
/// The order is what makes a second `fire` cheap rather than wrong:
/// `resolve.Stream.deinit` fires on every path out of a resolve, including the
/// ones where nothing was in flight, so the flag is set first and the socket is
/// told once.
fn stopRetrieval(ctx: *anyopaque) void {
    const self: *Retrieval = @ptrCast(@alignCast(ctx));
    if (self.stopped.swap(true, .acq_rel)) return;
    self.datagram.stop(self.datagram.ctx);
}

/// What one `ask` writes, and how long it waits.
///
/// An options struct because two of these are the same type and a positional
/// list that long is a list nothing distinguishes. The buffers are the
/// caller's because a read buffer does not outlive the call and a query may be
/// longer than anything this file could own.
///
/// Encoding and receive may overwrite prefixes only. Buffer contents are not
/// an outcome channel: inspect the returned `Answer`, not unwritten bytes.
pub const Request = struct {
    /// The name asked about, in presentation form with its trailing dot.
    name: []const u8,
    /// Query scratch of at least `queryLength(name)` bytes. Encoding can
    /// overwrite it; a retrieval stopped before encoding leaves it unchanged.
    wire: []u8,
    /// Receive scratch. `reply_length` bytes fits an answer within the advertised
    /// limit. A short receive leaves the tail unchanged; timeout and error may
    /// leave the whole buffer unchanged.
    reply: []u8,
    /// How long one receive waits, in milliseconds, and null for as long as the
    /// caller means. Upstream gives each of its six staggered queries three
    /// seconds (`iroh/src/address_lookup/dns.rs:19`); the staggering is a policy
    /// and needs an instant, so only the per-query deadline is here.
    deadline_ms: ?i32,
};

const t = std.testing;
const support = @import("lookup_test_support.zig");

test "a query is framed, sent, and its answer parsed, with no network" {
    var engine: support.Prng = support.Prng.init(7);
    var name: [support.asked_len]u8 = undefined;
    const text = dns.queryName(&name, try support.nodeOf(support.upstream_id), dns.prod_origin);

    var script: support.Scripted = .{ .from = support.nameserver };
    var retrieval = Retrieval.begin(script.datagram(), support.nameserver, engine.random());
    var scratch: [support.asked_bytes]u8 = undefined;
    var reply: [wire.reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // Nothing answers yet, so this run observes the framing and the send.
    try t.expectEqual(answer.Answer.timeout, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);
    try t.expectEqual(support.nameserver, script.sent_to);
    try t.expectEqual(query.queryLength(text), script.sent_len);
    try t.expectEqual(@as(?i32, 3000), script.deadline_ms);
    try t.expectEqual(retrieval.id, wire.be16(script.sent[0..], 0));
    try t.expectEqual(@as(u16, 1), wire.be16(script.sent[0..], 10));
    try t.expectEqual(
        wire.type_txt,
        wire.be16(script.sent[0..], wire.header_length + support.asked_len + 1),
    );

    // The answer arrives. It is read under the name *it* was published for, and
    // the transaction id this retrieval drew, so the whole path — the ID from
    // the generator, the send, the receive, the header, the record walk, the
    // TXT read — runs against bytes the reference implementation produced.
    var sender = try key.SecretKey.fromSeed(support.captured_seed);
    defer sender.deinit();
    var published: [wire.max_name_length]u8 = undefined;
    var scripted: [wire.reply_length]u8 = undefined;
    script.reply = try support.hexBytes(&scripted, support.captured_answer_hex);
    // The captured answer answers transaction zero, and this retrieval drew its
    // own id: §4.1.1's `ID` is copied into the reply, so a real nameserver
    // echoes it and the vector has to be told what to echo.
    wire.put16(script.reply.?, 0, retrieval.id);
    const read = try retrieval.ask(t.allocator, t.io, .{
        .name = support.capturedName(sender.nodeId(), &published),
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 3000,
    });
    defer read.deinit(t.allocator);
    try t.expect(read.hasRecords());

    // The records are this call's and not the read buffer's: overwriting every
    // byte the socket wrote leaves them reading the same. That is the fourth
    // of the seam's four things — an `Io` read buffer does not outlive the
    // call — proven rather than asserted.
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    @memset(&reply, 0xaa);
    try t.expectEqualStrings(support.captured_record, records.bytes);
}

test "an abandoned resolve stops the query that was in flight" {
    var engine: support.Prng = support.Prng.init(9);
    var name: [support.asked_len]u8 = undefined;
    const text = dns.queryName(&name, try support.nodeOf(support.upstream_id), dns.prod_origin);
    var script: support.Scripted = .{ .from = support.nameserver };
    var retrieval = Retrieval.begin(script.datagram(), support.nameserver, engine.random());
    var scratch: [support.asked_bytes]u8 = undefined;
    var reply: [wire.reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // A resolve whose query is now in flight and is about to be dropped.
    try t.expectEqual(answer.Answer.timeout, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);

    // `Stream.deinit` fires it, and the abort reaches the socket rather than a
    // flag this test already owns: `stops` is the socket's own count.
    var cancellation = retrieval.cancellation();
    cancellation.fire();
    try t.expectEqual(@as(u32, 1), script.stops);
    try t.expect(retrieval.stopped.load(.acquire));

    // A second fire is free, because `deinit` fires on every path out of a
    // resolve including the ones with nothing in flight.
    cancellation.fire();
    try t.expectEqual(@as(u32, 1), script.stops);

    // And nothing more goes out: an abandoned resolve cannot leave a query
    // pending, which is the whole of what `resolve.Cancellation` is for.
    try t.expectError(error.Canceled, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);
}

test "a stop during receive takes precedence over its timeout" {
    var engine: support.Prng = support.Prng.init(17);
    var script: support.Scripted = .{ .from = support.nameserver };
    var retrieval = Retrieval.begin(script.datagram(), support.nameserver, engine.random());
    script.cancel_during_receive = retrieval.cancellation();
    var scratch: [support.asked_bytes]u8 = undefined;
    var reply: [wire.reply_length]u8 = undefined;
    try t.expectError(error.Canceled, retrieval.ask(t.allocator, t.io, .{
        .name = "_iroh.example.",
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 1,
    }));
    try t.expectEqual(@as(u32, 1), script.stops);
}

test "a lookup that got no answer in time is not a node that published nothing" {
    var engine: support.Prng = support.Prng.init(11);
    var name: [support.asked_len]u8 = undefined;
    const text = dns.queryName(&name, try support.nodeOf(support.upstream_id), dns.prod_origin);
    var script: support.Scripted = .{ .from = support.nameserver };
    var retrieval = Retrieval.begin(script.datagram(), support.nameserver, engine.random());
    var scratch: [support.asked_bytes]u8 = undefined;
    var reply: [wire.reply_length]u8 = undefined;

    // Nothing answered inside the deadline.
    const late = try retrieval.ask(t.allocator, t.io, .{
        .name = text,
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 1,
    });
    try t.expectEqual(answer.Answer.timeout, late);
    try t.expect(!late.hasRecords());
    try t.expectEqual(@as(?i32, 1), script.deadline_ms);

    // The name exists and carries nothing, which is a fact about the world and
    // a different one: a header with no records at all.
    var empty: [wire.header_length]u8 = @splat(0);
    wire.put16(&empty, 0, retrieval.id);
    wire.put16(&empty, 2, wire.flag_response);
    var owner: [wire.max_name_length]u8 = undefined;
    const nothing = try answer.readAnswer(t.allocator, &empty, text, retrieval.id, &owner);
    try t.expectEqual(answer.Answer.nothing, nothing);

    // A third answer, and it is an error: `NXDOMAIN` says the name was never
    // published, which upstream reports rather than answering empty.
    wire.put16(&empty, 2, wire.flag_response | 3);
    try t.expectError(
        error.NameError,
        answer.readAnswer(t.allocator, &empty, text, retrieval.id, &owner),
    );

    // The three are three. A caller that read a timeout as `nothing` would tell
    // the world this node published nothing, having learned nothing at all.
    try t.expectEqual(.timeout, std.meta.activeTag(late));
    try t.expectEqual(.nothing, std.meta.activeTag(nothing));
    try t.expect(!late.hasRecords());
}

test "an answer from somewhere else is not this query's answer" {
    var engine: support.Prng = support.Prng.init(13);
    var script: support.Scripted = .{ .from = support.elsewhere };
    var retrieval = Retrieval.begin(script.datagram(), support.nameserver, engine.random());
    var scratch: [support.asked_bytes]u8 = undefined;
    var reply: [wire.reply_length]u8 = undefined;
    var scripted: [wire.reply_length]u8 = undefined;
    var secret = try key.SecretKey.fromSeed(support.captured_seed);
    defer secret.deinit();
    var published: [wire.max_name_length]u8 = undefined;
    script.reply = try support.hexBytes(&scripted, support.captured_answer_hex);

    // A TXT answer carries no signature, so the source address is the only
    // thing telling this datagram from a forged one. A datagram off the queried
    // server is refused even though it echoes the right transaction id.
    try t.expectError(error.ForeignSource, retrieval.ask(t.allocator, t.io, .{
        .name = support.capturedName(secret.nodeId(), &published),
        .wire = &scratch,
        .reply = &reply,
        .deadline_ms = 3000,
    }));
    try t.expectEqual(@as(u32, 1), script.sends);
}