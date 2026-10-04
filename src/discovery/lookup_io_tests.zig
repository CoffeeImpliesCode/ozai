//! The tests `discovery/lookup_io.zig` is held to: one lookup against a
//! scripted datagram, the abort handle, the three answers side by side, and one
//! witness for every arm of the closed set `SocketError`.
//!
//! No nameserver and no network: the socket is `lookup_test_support.zig`'s, so
//! a whole `Retrieval` — send, receive, decode, cancel, stop — runs in the
//! socket-free test root rather than needing the live adapter.

const dns = @import("dns.zig");
const key = @import("../base/key.zig");
const wire = @import("lookup_wire.zig");
const answer = @import("lookup_answer.zig");
const seam = @import("lookup_io.zig");
const support = @import("lookup_test_support.zig");

// The subjects these tests name the way the module under test names them,
// bound once here rather than qualified at every call: a test that says
// `Retrieval.ask` is a claim about the seam, and the answers it inspects come
// from the decoder the seam hands them to.
const t = support.t;
const upstream_id = support.upstream_id;
const asked_len = support.asked_len;
const asked_bytes = support.asked_bytes;
const Scripted = support.Scripted;
const nameserver = support.nameserver;
const elsewhere = support.elsewhere;
const Prng = support.Prng;
const captured_answer_hex = support.captured_answer_hex;
const captured_record = support.captured_record;
const captured_seed = support.captured_seed;
const capturedName = support.capturedName;
const hexBytes = support.hexBytes;
const nodeOf = support.nodeOf;
const sweep_name = support.sweep_name;
const sweptAnswer = support.sweptAnswer;

const queryLength = wire.queryLength;
const header_length = wire.header_length;
const type_txt = wire.type_txt;
const flag_response = wire.flag_response;
const flag_truncated = wire.flag_truncated;
const max_section_records = wire.max_section_records;
const max_name_length = wire.max_name_length;
const reply_length = wire.reply_length;
const be16 = wire.be16;
const put16 = wire.put16;

const Answer = answer.Answer;
const readAnswer = answer.readAnswer;

const SocketError = seam.SocketError;
const Retrieval = seam.Retrieval;
const Request = seam.Request;

test "a query is framed, sent, and its answer parsed, with no network" {
    var engine: Prng = Prng.init(7);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);

    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // Nothing answers yet, so this run observes the framing and the send.
    try t.expectEqual(Answer.timeout, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);
    try t.expectEqual(nameserver, script.sent_to);
    try t.expectEqual(queryLength(text), script.sent_len);
    try t.expectEqual(@as(?i32, 3000), script.deadline_ms);
    try t.expectEqual(retrieval.id, be16(script.sent[0..], 0));
    try t.expectEqual(@as(u16, 1), be16(script.sent[0..], 10));
    try t.expectEqual(type_txt, be16(script.sent[0..], header_length + asked_len + 1));

    // The answer arrives. It is read under the name *it* was published for, and
    // the transaction id this retrieval drew, so the whole path — the ID from
    // the generator, the send, the receive, the header, the record walk, the
    // TXT read — runs against bytes the reference implementation produced.
    var sender = try key.SecretKey.fromSeed(captured_seed);
    defer sender.deinit();
    var published: [max_name_length]u8 = undefined;
    var scripted: [reply_length]u8 = undefined;
    script.reply = try hexBytes(&scripted, captured_answer_hex);
    // The captured answer answers transaction zero, and this retrieval drew its
    // own id: §4.1.1's `ID` is copied into the reply, so a real nameserver
    // echoes it and the vector has to be told what to echo.
    put16(script.reply.?, 0, retrieval.id);
    const read = try retrieval.ask(t.allocator, t.io, .{
        .name = capturedName(sender.nodeId(), &published),
        .wire = &wire,
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
    try t.expectEqualStrings(captured_record, records.bytes);
}

test "an abandoned resolve stops the query that was in flight" {
    var engine: Prng = Prng.init(9);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // A resolve whose query is now in flight and is about to be dropped.
    try t.expectEqual(Answer.timeout, retrieval.ask(t.allocator, t.io, request));
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
    var engine: Prng = Prng.init(17);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    script.cancel_during_receive = retrieval.cancellation();
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    try t.expectError(error.Canceled, retrieval.ask(t.allocator, t.io, .{
        .name = "_iroh.example.",
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1,
    }));
    try t.expectEqual(@as(u32, 1), script.stops);
}

test "a lookup that got no answer in time is not a node that published nothing" {
    var engine: Prng = Prng.init(11);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;

    // Nothing answered inside the deadline.
    const late = try retrieval.ask(t.allocator, t.io, .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1,
    });
    try t.expectEqual(Answer.timeout, late);
    try t.expect(!late.hasRecords());
    try t.expectEqual(@as(?i32, 1), script.deadline_ms);

    // The name exists and carries nothing, which is a fact about the world and
    // a different one: a header with no records at all.
    var empty: [header_length]u8 = @splat(0);
    put16(&empty, 0, retrieval.id);
    put16(&empty, 2, flag_response);
    var owner: [max_name_length]u8 = undefined;
    const nothing = try readAnswer(t.allocator, &empty, text, retrieval.id, &owner);
    try t.expectEqual(Answer.nothing, nothing);

    // A third answer, and it is an error: `NXDOMAIN` says the name was never
    // published, which upstream reports rather than answering empty.
    put16(&empty, 2, flag_response | 3);
    try t.expectError(error.NameError, readAnswer(t.allocator, &empty, text, retrieval.id, &owner));

    // The three are three. A caller that read a timeout as `nothing` would tell
    // the world this node published nothing, having learned nothing at all.
    try t.expectEqual(.timeout, std.meta.activeTag(late));
    try t.expectEqual(.nothing, std.meta.activeTag(nothing));
    try t.expect(!late.hasRecords());
}

test "an answer from somewhere else is not this query's answer" {
    var engine: Prng = Prng.init(13);
    var script: Scripted = .{ .from = elsewhere };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    var scripted: [reply_length]u8 = undefined;
    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var published: [max_name_length]u8 = undefined;
    script.reply = try hexBytes(&scripted, captured_answer_hex);

    // A TXT answer carries no signature, so the source address is the only
    // thing telling this datagram from a forged one. A datagram off the queried
    // server is refused even though it echoes the right transaction id.
    try t.expectError(error.ForeignSource, retrieval.ask(t.allocator, t.io, .{
        .name = capturedName(secret.nodeId(), &published),
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    }));
    try t.expectEqual(@as(u32, 1), script.sends);
}

/// The three arms of the socket seam's closed error set, and the call that
/// produces each. Two arms have two producers each and both are listed: a
/// refusal is what a send and a failed read look like, and a stop is what a
/// caller gave up before I/O and what one gave up during a wait look like.
const socket_arms = [_]struct { tag: SocketError, fault: SocketFault }{
    .{ .tag = error.Refused, .fault = .send_refused },
    .{ .tag = error.Refused, .fault = .receive_refused },
    .{ .tag = error.Empty, .fault = .deadline },
    .{ .tag = error.Canceled, .fault = .stopped_before_io },
    .{ .tag = error.Canceled, .fault = .stopped_during_receive },
};

/// What one arm of the socket seam's closed error set is provoked by.
const SocketFault = enum {
    send_refused,
    receive_refused,
    deadline,
    stopped_before_io,
    stopped_during_receive,
};

comptime {
    var covered = [_]bool{false} ** @typeInfo(SocketError).error_set.?.len;
    for (socket_arms) |row| {
        for (@typeInfo(SocketError).error_set.?, 0..) |member, index| {
            if (row.tag == @field(SocketError, member.name)) covered[index] = true;
        }
    }
    for (covered) |seen| {
        if (!seen) @compileError("a SocketError arm has no call that produces it");
    }
}

test "every arm of the socket seam's closed error set has a call that produces it" {
    inline for (socket_arms) |row| {
        var engine: Prng = Prng.init(37);
        var script: Scripted = .{ .from = nameserver };
        var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
        var wire: [asked_bytes]u8 = undefined;
        var reply: [reply_length]u8 = undefined;
        const request: Request = .{
            .name = sweep_name,
            .wire = &wire,
            .reply = &reply,
            .deadline_ms = 1000,
        };
        switch (row.fault) {
            .send_refused => {
                script.refuse_send = true;
                try t.expectError(row.tag, retrieval.ask(t.allocator, t.io, request));
                // Nothing went out, which is what a refused send means.
                try t.expectEqual(@as(u32, 0), script.sends);
            },
            .receive_refused => {
                script.refuse_receive = true;
                try t.expectError(row.tag, retrieval.ask(t.allocator, t.io, request));
                try t.expectEqual(@as(u32, 1), script.sends);
            },
            .deadline => {
                // The seam's `Empty` is the deadline, and what it looks like on
                // the way out is the third answer rather than an error: a
                // caller that read it as a refusal would be telling the world
                // this node published nothing, having learned nothing at all.
                try t.expectEqual(Answer.timeout, try retrieval.ask(t.allocator, t.io, request));
                try t.expectEqual(@as(?i32, 1000), script.deadline_ms);
            },
            .stopped_before_io => {
                retrieval.cancellation().fire();
                try t.expectError(row.tag, retrieval.ask(t.allocator, t.io, request));
                // A stopped retrieval does not ask again, so nothing is sent.
                try t.expectEqual(@as(u32, 0), script.sends);
            },
            .stopped_during_receive => {
                script.cancel_during_receive = retrieval.cancellation();
                try t.expectError(row.tag, retrieval.ask(t.allocator, t.io, request));
                try t.expectEqual(@as(u32, 1), script.sends);
                try t.expectEqual(@as(u32, 1), script.stops);
            },
        }
    }
}

test "truncated, empty and a deadline are three answers, and truncation publishes nothing" {
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    var owner: [max_name_length]u8 = undefined;

    // A message that had three records in it and says it did not fit. `TC` is
    // read before any count, so nothing is walked and nothing is published.
    var truncated: [reply_length]u8 = undefined;
    @memcpy(truncated[0..built.bytes.len], built.bytes);
    put16(truncated[0..], 2, flag_response | flag_truncated);
    try t.expectError(
        error.Truncated,
        readAnswer(t.allocator, truncated[0..built.bytes.len], sweep_name, 0, &owner),
    );

    // And it stays its own error beside every other thing a header can say: a
    // message that is truncated *and* names a code *and* claims more records
    // than one datagram could hold is still the answer a TCP retry is for, not
    // a name that does not exist and not a header to refuse.
    var header_only: [header_length]u8 = @splat(0);
    put16(&header_only, 2, flag_response | flag_truncated | 3);
    put16(&header_only, 6, max_section_records + 1);
    try t.expectError(
        error.Truncated,
        readAnswer(t.allocator, &header_only, sweep_name, 0, &owner),
    );

    // The name exists and published nothing, which is a fact about the world.
    var empty: [header_length]u8 = @splat(0);
    put16(&empty, 2, flag_response);
    const nothing = try readAnswer(t.allocator, &empty, sweep_name, 0, &owner);
    try t.expectEqual(Answer.nothing, nothing);

    // A deadline is the question asked and nothing answered inside it.
    var engine: Prng = Prng.init(29);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const late = try retrieval.ask(t.allocator, t.io, .{
        .name = sweep_name,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1,
    });

    // Three, and a caller reading one as another tells the world something it
    // does not know: a node that published nothing, and a node nobody reached.
    try t.expectEqual(.nothing, std.meta.activeTag(nothing));
    try t.expectEqual(.timeout, std.meta.activeTag(late));
    try t.expect(!nothing.hasRecords());
    try t.expect(!late.hasRecords());
}

test "the copied-out answer is what the resolver reads, and stopping it keeps its own error" {
    var engine: Prng = Prng.init(41);
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());

    // The socket's own copy has to be a heap buffer of its own: `Scripted`
    // borrows `script.reply` for the call and the answer outlives it.
    const scripted = try t.allocator.dupe(u8, built.bytes);
    defer t.allocator.free(scripted);
    put16(scripted, 0, retrieval.id);
    script.reply = scripted;

    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const answer = try retrieval.ask(t.allocator, t.io, .{
        .name = sweep_name,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1000,
    });
    defer answer.deinit(t.allocator);
    const records = switch (answer) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };

    // `discovery/dns.zig` borrows what it is handed, and the buffer it borrows
    // is this call's: the datagram the socket wrote is dead now, and only the
    // copy survives to be read as records. The item below comes out of the
    // stream's own arena, so it is not that copy either.
    var service = dns.DnsAddressLookup.init(records, retrieval.cancellation());
    const id = try key.NodeId.parseHex(upstream_id);
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();
    const first = stream.next() orelse return error.TestUnexpectedResult;
    const value = switch (first) {
        .item => |item_value| item_value,
        .failed => |failure| return failure.reason,
    };
    try t.expectEqual(id, value.endpoint.node_id);
    try t.expectEqual(@as(usize, 3), value.endpoint.addrs.len);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());

    // Closing the stream fires the retrieval's own handle, so the query behind
    // it stops rather than the stream stopping alone. And the error that
    // retrieval answers with afterwards is its own: not a deadline, which is
    // what a socket with nothing to say reports, and not a refusal.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), script.stops);
    try t.expectError(error.Canceled, retrieval.ask(t.allocator, t.io, .{
        .name = sweep_name,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1000,
    }));
    try t.expectEqual(@as(u32, 1), script.sends);
}