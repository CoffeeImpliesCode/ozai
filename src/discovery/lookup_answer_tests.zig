//! The tests `discovery/lookup_answer.zig` is held to: one answer the reference
//! implementation actually produced, the shapes no capture of exists for, and
//! a sweep of every allocator operation an answer of those shapes makes.
//!
//! The sweep is the last group rather than a leak check. An answer that
//! publishes records has to release them on every refusal path, and a decoder
//! that asks for one more allocation than it used to has to fail on its own
//! line rather than pass a bound written down in the test.

const dns = @import("dns.zig");
const key = @import("../base/key.zig");
const wire = @import("lookup_wire.zig");
const answer = @import("lookup_answer.zig");
const support = @import("lookup_test_support.zig");

// The subjects these tests name the way the module under test names them,
// bound once here rather than qualified at every call: a test that says
// `readAnswer` is a claim about the decoder, and the sweep below is about the
// bytes it copies rather than about who asks for them.
const t = support.t;
const captured_answer_hex = support.captured_answer_hex;
const captured_record = support.captured_record;
const captured_seed = support.captured_seed;
const capturedName = support.capturedName;
const hexBytes = support.hexBytes;
const sweep_name = support.sweep_name;
const swept_records = support.swept_records;
const sweptAnswer = support.sweptAnswer;

const header_length = wire.header_length;
const question_length = wire.question_length;
const type_txt = wire.type_txt;
const class_in = wire.class_in;
const flag_response = wire.flag_response;
const flag_truncated = wire.flag_truncated;
const max_section_records = wire.max_section_records;
const name_pointer = wire.name_pointer;
const max_name_length = wire.max_name_length;
const reply_length = wire.reply_length;
const put16 = wire.put16;
const put32 = wire.put32;

const DecodeError = answer.DecodeError;
const Answer = answer.Answer;
const readAnswer = answer.readAnswer;
const readName = answer.readName;

test "golden: a captured answer decodes into the records it carried" {
    var buffer: [reply_length]u8 = undefined;
    const answer = try hexBytes(&buffer, captured_answer_hex);

    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var name: [max_name_length]u8 = undefined;
    const asked = capturedName(secret.nodeId(), &name);

    var owner: [max_name_length]u8 = undefined;
    const read = try readAnswer(t.allocator, answer, asked, 0, &owner);
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    // The reference implementation's own record, with the character strings
    // inside one TXT record read as one value.
    try t.expectEqualStrings(captured_record, records.bytes);

    // The node the packet is about is the key that signed it, and the name the
    // answer was read under is that key's z32 — read back by the same parser
    // `discovery/dns.zig` uses on a record name.
    try t.expectEqual(secret.nodeId(), try dns.endpointIdFromName(asked));
}

test "a datagram that is not this question's answer is refused" {
    var buffer: [reply_length]u8 = undefined;
    const answer = try hexBytes(&buffer, captured_answer_hex);
    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var name: [max_name_length]u8 = undefined;
    const asked = capturedName(secret.nodeId(), &name);
    var owner: [max_name_length]u8 = undefined;

    // Another query's transaction, which RFC 1035 §4.1.1's `ID` exists to
    // catch: the answer is real and it is not ours.
    try t.expectError(
        error.ForeignTransaction,
        readAnswer(t.allocator, answer, asked, 1, &owner),
    );

    // This one's own transaction, read against a name it is not about: the
    // records are not silently attributed to a node that never published them.
    var other: [max_name_length]u8 = @splat('x');
    other[0] = '_';
    const wrong = try readAnswer(
        t.allocator,
        answer,
        other[0..asked.len],
        0,
        &owner,
    );
    defer wrong.deinit(t.allocator);
    try t.expectEqual(Answer.nothing, wrong);

    // A question arriving where an answer was wanted.
    var query: [header_length]u8 = @splat(0);
    put16(&query, 4, 1);
    try t.expectError(error.NotAResponse, readAnswer(t.allocator, &query, asked, 0, &owner));

    // An answer that did not fit its datagram, which is the one a TCP retry
    // would be for.
    var cut: [reply_length]u8 = undefined;
    const truncated = try hexBytes(&cut, captured_answer_hex);
    put16(truncated[0..], 2, flag_response | flag_truncated);
    try t.expectError(error.Truncated, readAnswer(t.allocator, truncated[0..], asked, 0, &owner));
}

test "every response code is named, and a name that loops is refused" {
    const name = "_iroh.example.";
    var owner: [max_name_length]u8 = undefined;
    var message: [header_length]u8 = @splat(0);

    // RFC 1035 §4.1.1's six codes, each with the answer this file gives rather
    // than one generic "no", which is the point of naming them.
    const cases = [_]struct { code: u16, expect: ?anyerror }{
        .{ .code = 0, .expect = null },
        .{ .code = 1, .expect = error.MalformedResponse },
        .{ .code = 2, .expect = error.ServiceFailure },
        .{ .code = 3, .expect = error.NameError },
        .{ .code = 4, .expect = error.Unimplemented },
        .{ .code = 5, .expect = error.ServiceRefused },
    };
    inline for (cases) |case| {
        put16(&message, 2, flag_response | case.code);
        const read = readAnswer(t.allocator, &message, name, 0, &owner);
        if (case.expect) |wanted| {
            try t.expectError(wanted, read);
        } else {
            try t.expectEqual(Answer.nothing, try read);
        }
    }
    // And the reserved range above them, which is not "no error".
    for (6..16) |code| {
        put16(&message, 2, flag_response | @as(u16, @intCast(code)));
        try t.expectError(
            error.UnknownResponseCode,
            readAnswer(t.allocator, &message, name, 0, &owner),
        );
    }

    // A name whose pointer points forward can never end, so §4.1.4's "prior
    // occurrence" is checked rather than followed. Every other encoding of the
    // two high bits is reserved and has no length to read.
    var looping: [header_length + 2]u8 = @splat(0);
    put16(&looping, 0, 0);
    put16(&looping, 2, flag_response);
    put16(&looping, 6, 1);
    const at = header_length;
    const alias = looping[0 .. header_length + 2];
    looping[at] = name_pointer;
    looping[at + 1] = @intCast(at);
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x40;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x80;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));

    // A message cut short inside a record is refused rather than read past.
    var cut: [header_length + 4]u8 = @splat(0);
    put16(&cut, 0, 0);
    put16(&cut, 2, flag_response);
    put16(&cut, 6, 1);
    cut[header_length] = 0;
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
    try t.expectError(error.ShortMessage, readAnswer(t.allocator, cut[0..4], name, 0, &owner));

    // A count a 64-octet message cannot hold is a header to refuse, not a loop.
    put16(&cut, 2, flag_response);
    put16(&cut, 6, max_section_records + 1);
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
}

test "a compression pointer is followed and a bad one is refused" {
    // RFC 1035 §4.1.4's own example: the name `F.ISI.ARPA` written out, and
    // `FOO.F.ISI.ARPA` written as one label and a pointer back to it. A reader
    // has to expand the alias to the name the writer meant, and the pointer is
    // the whole difficulty. Here the pointed-at name is the question, which is
    // where a real answer keeps it.
    var message: [64]u8 = @splat(0);
    put16(&message, 0, 0);
    put16(&message, 2, flag_response);
    put16(&message, 4, 1);
    put16(&message, 6, 1);
    var at: usize = question_at;
    var labels = std.mem.splitScalar(u8, spelled, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        message[at] = @intCast(label.len);
        @memcpy(message[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
    }
    message[at] = 0;
    at += 1;
    put16(&message, at, type_txt);
    put16(&message, at + 2, class_in);
    at += question_length;
    try t.expectEqual(alias_at, at);

    // One label and the pointer, which is the whole of §4.1.4's alias.
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "foo");
    at += 4;
    message[at] = name_pointer;
    message[at + 1] = @intCast(question_at);
    at += 2;
    put16(&message, at, type_txt);
    put16(&message, at + 2, class_in);
    put32(&message, at + 4, 30);
    put16(&message, at + 8, 4);
    at += 10;
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "bar");
    at += 4;

    var owner: [max_name_length]u8 = undefined;
    const decoded = try readName(message[0 .. alias_at + 6], alias_at, &owner);
    try t.expectEqualStrings("foo.f.isi.arpa.", owner[0..decoded.written]);
    // The name ends after the two pointer octets, which is where the record's
    // `TYPE` starts — and getting that wrong is how a parser reads a type out
    // of a pointer.
    try t.expectEqual(alias_at + 6, decoded.end);

    // And the whole message reads: past the pointer, through the names it
    // expands to, and into the record the pointer stands in for.
    const read = try readAnswer(t.allocator, message[0..at], "foo.f.isi.arpa.", 0, &owner);
    defer read.deinit(t.allocator);
    try t.expectEqualStrings("bar\x00", switch (read) {
        .records => |set| set.bytes,
        else => return error.ExpectedRecords,
    });

    // A pointer past the message, and one that points at itself.
    var bad: [header_length + 2]u8 = undefined;
    bad[header_length] = name_pointer;
    bad[header_length + 1] = 200;
    try t.expectError(error.BadName, readName(&bad, header_length, &owner));
    bad[header_length + 1] = 0;
    try t.expectError(error.BadName, readName(&bad, header_length, &owner));
    // A label whose length runs past the message.
    var cut: [header_length + 2]u8 = @splat(0);
    cut[header_length] = 40;
    try t.expectError(
        error.ShortMessage,
        readName(cut[0 .. header_length + 2], header_length, &owner),
    );
    // A pointer with no second octet at all.
    var lone: [header_length + 1]u8 = @splat(0);
    lone[header_length] = name_pointer;
    try t.expectError(error.ShortMessage, readName(&lone, header_length, &owner));
}

/// The name RFC 1035 §4.1.4's example writes out, and where this message keeps
/// it: as the question, which is where a real answer points back at.
const spelled = "f.isi.arpa.";
const question_at = header_length;
const alias_at = question_at + spelled.len + 1 + question_length;

test "three TXT records become exactly the records they carried" {
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    var owner: [max_name_length]u8 = undefined;

    const answer = try readAnswer(t.allocator, built.bytes, sweep_name, 0, &owner);
    defer answer.deinit(t.allocator);
    const records = switch (answer) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    try t.expectEqualStrings(swept_records, records.bytes);

    // Owned, not borrowed: the bytes a socket wrote are dead the moment the
    // next receive overwrites them, which is the fourth of this seam's four
    // things. Overwriting the message leaves the records reading the same.
    try t.expect(@intFromPtr(records.bytes.ptr) != @intFromPtr(built.bytes.ptr));
    @memset(&buffer, 0xaa);
    try t.expectEqualStrings(swept_records, records.bytes);

    // And each of them reads back through `RecordSet` as one value, which is
    // the shape `discovery/resolve.zig`'s `parseTxt` is handed.
    var set = records;
    try t.expectEqualStrings("relay=https://use1-1.relay.iroh.network./", set.next().?);
    try t.expectEqualStrings("addr=192.168.96.145:60165", set.next().?);
    try t.expectEqualStrings("addr=213.208.157.87:60165", set.next().?);
    try t.expect(set.next() == null);
}

test "the trailing sections are walked, and none of them is this question's answer" {
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    var owner: [max_name_length]u8 = undefined;

    // The authority section holds a TXT record under the name this question
    // asked about, and it is still not one of its records: a record answers
    // because of the section it is in, and only the answer section answers.
    const answer = try readAnswer(t.allocator, built.bytes, sweep_name, 0, &owner);
    defer answer.deinit(t.allocator);
    try t.expectEqualStrings(swept_records, switch (answer) {
        .records => |set| set.bytes,
        else => return error.ExpectedRecords,
    });

    // Cut inside the additional record, at both ends of its fixed part. Walking
    // that section is the only way to know the message was not cut short
    // inside one, so both are refused rather than read up to the cut.
    try t.expectError(
        error.ShortMessage,
        readAnswer(
            t.allocator,
            built.bytes[0 .. built.additional_at + 1],
            sweep_name,
            0,
            &owner,
        ),
    );
    try t.expectError(
        error.ShortMessage,
        readAnswer(
            t.allocator,
            built.bytes[0 .. built.additional_at + 9],
            sweep_name,
            0,
            &owner,
        ),
    );
    // And the whole of it: the fixed part read in full with empty `RDATA` is a
    // complete record, so the same three records come out as before.
    const whole = try readAnswer(
        t.allocator,
        built.bytes[0 .. built.additional_at + 11],
        sweep_name,
        0,
        &owner,
    );
    defer whole.deinit(t.allocator);
    try t.expectEqualStrings(swept_records, switch (whole) {
        .records => |set| set.bytes,
        else => return error.ExpectedRecords,
    });
}

/// How many allocator operations one answer of these shapes needs.
///
/// Discovered by walking the number of operations that are allowed up until
/// one number leaves the decoder with no memory at all, rather than written
/// down as a count: a sweep bounded by a number in the test stops covering the
/// decoder the first time it asks for one thing more than it used to, and that
/// is exactly the change a sweep is for.
fn answerAllocations(message: []const u8, expected: []const u8) !usize {
    var allowed: usize = 0;
    while (allowed < allocation_ceiling) : (allowed += 1) {
        const refusal = try answerAtIndex(message, allowed, expected);
        if (refusal == null) return allowed;
    }
    return error.MoreAllocationsThanTheCeilingAllows;
}

/// The ceiling on an answer sweep, so that one cannot run forever: an answer is
/// at most `reply_length` octets and holds at most `max_section_records`
/// records, and an `ArrayList` that grows to that is a handful of
/// reallocations. Sixty-four is well past it.
const allocation_ceiling = 64;

/// An allocator that refuses every operation past the `allowed`th.
///
/// `std.testing.FailingAllocator` counts allocations and resizes in two
/// sequences, and one index into both steps over operations rather than
/// refusing them. An answer runs both: it grows an `ArrayList`, and
/// `toOwnedSlice` then asks to `remap` that buffer down to the bytes it used
/// and falls back to a fresh allocation when the remap is refused. With one
/// index for both sequences the fallback arrives as an operation the sweep
/// never asked about, and the count of operations it reports depends on
/// whether the target's allocator could remap in place — two targets, two
/// counts, one of them too small to sweep the last step. Counting every call
/// in one sequence is what "fail the Nth allocation" has to mean here, and it
/// makes the sweep the same argument on every target.
const FailAfterOp = struct {
    inner: std.mem.Allocator,
    allowed: usize,
    operations: usize = 0,
    allocated_bytes: usize = 0,
    freed_bytes: usize = 0,

    fn allocator(self: *FailAfterOp) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = opAlloc,
            .resize = opResize,
            .remap = opRemap,
            .free = opFree,
        } };
    }

    /// Whether this operation is past the allowance, counting it when it is not.
    fn pastAllowance(self: *FailAfterOp) bool {
        if (self.operations < self.allowed) {
            self.operations += 1;
            return false;
        }
        return true;
    }

    /// The tail of a buffer that grew or shrank is memory this account does not
    /// hold, so the difference either way is what the caller now owes or has
    /// been given back.
    fn recordLengthChange(self: *FailAfterOp, before: usize, after: usize) void {
        if (after < before) self.freed_bytes += before - after else self.allocated_bytes += after - before;
    }

    fn opAlloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *FailAfterOp = @ptrCast(@alignCast(ctx));
        if (self.pastAllowance()) return null;
        const memory = self.inner.rawAlloc(len, alignment, return_address) orelse return null;
        self.allocated_bytes += len;
        return memory;
    }

    fn opResize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        len: usize,
        return_address: usize,
    ) bool {
        const self: *FailAfterOp = @ptrCast(@alignCast(ctx));
        if (self.pastAllowance()) return false;
        if (!self.inner.rawResize(memory, alignment, len, return_address)) return false;
        self.recordLengthChange(memory.len, len);
        return true;
    }

    fn opRemap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *FailAfterOp = @ptrCast(@alignCast(ctx));
        if (self.pastAllowance()) return null;
        const moved = self.inner.rawRemap(memory, alignment, len, return_address) orelse
            return null;
        self.recordLengthChange(memory.len, len);
        return moved;
    }

    fn opFree(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *FailAfterOp = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(memory, alignment, return_address);
        self.freed_bytes += memory.len;
    }
};

/// One `readAnswer` with every allocator operation past the `allowed`th
/// refused, and the exact bytes it published if it published any.
///
/// `expected` is the record block an accepted message must produce, and null
/// for a message this decoder refuses: a refusal that reached `expected` would
/// have published a partial answer, which is the one thing no error path may
/// do. The balance is checked at every allowance, so a refusal that skipped its
/// `defer` shows up on its own line rather than as a leak the suite's
/// allocator reports somewhere later.
fn answerAtIndex(
    message: []const u8,
    allowed: usize,
    expected: ?[]const u8,
) !?DecodeError {
    var failing: FailAfterOp = .{ .inner = t.allocator, .allowed = allowed };
    var owner: [max_name_length]u8 = undefined;
    var refusal: ?DecodeError = null;
    if (readAnswer(failing.allocator(), message, sweep_name, 0, &owner)) |answer| {
        defer answer.deinit(failing.allocator());
        const wanted = expected orelse return error.RefusedMessagePublished;
        const records = switch (answer) {
            .records => |set| set.bytes,
            else => return error.ExpectedRecords,
        };
        try t.expectEqualStrings(wanted, records);
    } else |err| {
        refusal = err;
    }
    try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    return refusal;
}

test "every allocation index of a multi-record answer hands back exactly these bytes" {
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    const allocations = try answerAllocations(built.bytes, swept_records);
    // More than one, or there was nothing to sweep, and the count belongs to
    // the decoder rather than to this test.
    try t.expect(allocations > 1);

    for (0..allocations) |index| {
        const refusal = (try answerAtIndex(built.bytes, index, swept_records)) orelse
            return error.AnswerSucceededBelowItsOwnAllocationCount;
        try t.expectEqual(error.OutOfMemory, refusal);
    }
}

test "a message cut after three records were copied out publishes nothing at any index" {
    var buffer: [reply_length]u8 = undefined;
    const built = sweptAnswer(&buffer);
    const allocations = try answerAllocations(built.bytes, swept_records);

    // Cut inside the alias record, which is the fourth answer record: three
    // records have been copied into the list by then, and a refusal that did
    // not release them would leak exactly what an answer had published.
    const cut = built.bytes[0 .. built.alias_at + 6];
    try t.expect(cut.len < built.bytes.len);

    for (0..allocations) |index| {
        if ((try answerAtIndex(cut, index, null)) == null)
            return error.RefusedMessagePublishedPartialRecords;
    }
    // And with nothing failing, the refusal names what it could not read.
    var owner: [max_name_length]u8 = undefined;
    try t.expectError(error.ShortMessage, readAnswer(t.allocator, cut, sweep_name, 0, &owner));
}
