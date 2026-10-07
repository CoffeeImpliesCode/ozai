//! The host resolver's surface: what an `IN A` or `IN AAAA` answer is, and the
//! two policies that sit above one — the `TC`-to-TCP retry and the staggered
//! re-ask.
//!
//! This is `lookup_io.zig`'s counterpart for the question a relay hostname
//! raises rather than a node id's. It is the facade over `host_wire.zig` (the
//! address-record vocabulary) and `host_answer.zig` (the walk), and it adds
//! nothing a caller could get from a copy of upstream's schedule.
//!
//! # The TC-to-TCP retry is a value, and it is here as a value
//!
//! RFC 1035 §4.2.2: a message with `TC` set "should be sent over a virtual
//! circuit", which for a client means TCP with a two-octet length prefix in
//! front of each message. `lookup_io.zig`'s module doc refuses that as
//! `error.Truncated` because it has no stream to open; `transport/tcp.zig` is
//! that stream, and `docs/ARCHITECTURE.md` draws `ozai.transport` **above**
//! `ozai.discovery`. So the layering decides the shape: this file can say, in
//! bytes, what the retry is — which server, which question, which prefix, and
//! how the answer behind the prefix is handed to the same decoder — and a
//! caller that owns both owns the connection.
//!
//! `StreamRetry` is therefore a value and not an action, which is also
//! `AGENTS.md` §2's rule for network logic: the decision is pure over bytes,
//! and the socket lives in the module that is allowed to have one.
//!
//! # The staggering table: offsets from the walk's start, not intervals
//!
//! `staggering_ms` is a schedule of **instants measured from the moment one
//! walk began**, and the first query is due at zero. That is upstream's own
//! reading and not an interpretation: `iroh/src/address_lookup/dns.rs:18`
//! calls the constant "Delays after which additional DNS lookup calls are
//! issued", and `iroh-dns`'s `lookup_ipv4_staggered` and friends document
//! "From the moment this function is called, each lookup is scheduled after
//! the delays in `delays_ms` with the first call being done immediately —
//! `[200ms, 300ms]` results in calls at 0ms, 200ms and 300ms." The six values
//! are upstream's, character for character.
//!
//! So `attemptsDue` answers "how many queries should have gone out by now", and
//! a caller that arrives late owes every attempt it missed rather than only the
//! most recent one — the queries are independent, and collapsing them into one
//! would be a different policy with the same table.
//!
//! Upstream jitters each entry by ±20% (`iroh-dns`'s `MAX_JITTER_PERCENT`)
//! from a random draw. A random number is a value, and a value is the caller's
//! to supply from the seeded generator `lookup_io.Retrieval.begin` already
//! takes; nothing in this file draws one. The table is therefore the unjittered
//! schedule, and a caller that wants upstream's spreading applies its own.
//!
//! # `query_timeout_ms` and the walk's budget
//!
//! Upstream gives each of its staggered queries three seconds
//! (`iroh-dns`'s `DNS_TIMEOUT`) and notes that the last one therefore
//! "will finally abort after 6 seconds" — the last offset in the table plus
//! one query's wait. `walkDeadlineMs` is that sum, so the table and the budget
//! are checkable against each other rather than being two literals.

const std = @import("std");

const base_addr = @import("../base/addr.zig");

const names = @import("lookup_name.zig");
const wire = @import("lookup_wire.zig");

const host_answer = @import("host_answer.zig");
const host_wire = @import("host_wire.zig");

/// Everything one host lookup can fail with: the answer's failures and this
/// file's own `MessageTooLong`, which is the refusal a two-octet length prefix
/// has to make.
///
/// The union closes here rather than in `host_answer.zig` because this file is
/// the one above both the walk and the framing, which is the same direction
/// `lookup_retrieval.zig` closes its own in.
pub const Error = host_answer.Error || error{MessageTooLong};

/// Which address family a question was asked for. See `host_wire.Family`.
pub const Family = host_wire.Family;

/// `TYPE` for an IPv4 host address. RFC 1035 §3.2.2, `A 1`.
pub const type_a = host_wire.type_a;
/// `TYPE` for a canonical name. RFC 1035 §3.2.3, `CNAME 5`.
pub const type_cname = host_wire.type_cname;
/// `TYPE` for an IPv6 host address. RFC 1035 §3.2.5, `AAAA 28`.
pub const type_aaaa = host_wire.type_aaaa;

/// One address an answer carried. See `host_answer.Record`.
pub const Record = host_answer.Record;

/// What one answer to a host question came to. See `host_answer.Answer`.
pub const Answer = host_answer.Answer;

/// The scratch one decode needs. See `host_answer.Scratch`.
pub const Scratch = host_answer.Scratch;

/// How many `CNAME` records one answer may make a walk follow. See
/// `host_answer.max_cname_hops`.
pub const max_cname_hops = host_answer.max_cname_hops;

/// Read one answer to a host question and copy its addresses into `alloc`.
pub const readAnswer = host_answer.readAnswer;

/// RFC 1035 §4.2.2: "In the case of TCP, each DNS message is prefixed with a
/// two byte length field specifying the message length, excluding the two byte
/// length field." The prefix is the only thing a DNS message on a stream
/// carries that the same message in a datagram does not, and it is why a
/// truncated answer cannot be resumed by sending a second datagram.
pub const length_prefix_bytes = 2;

/// The widest message a two-octet prefix can name, and so the widest DNS
/// message this seam can carry over a stream.
pub const max_message_length: usize = std.math.maxInt(u16);

/// What one truncated answer asks the caller to do next.
///
/// **A value and not an action.** `docs/ARCHITECTURE.md` draws `ozai.transport`
/// above `ozai.discovery`, so the connection this retry needs is opened by
/// `transport/tcp.zig` by a caller that owns both. What this file can do is say
/// exactly what has to go out and exactly what has to come back before the
/// same decoder may be handed the result.
pub const StreamRetry = struct {
    /// The server that sent the truncated answer, and the one the retry goes
    /// to. RFC 1035 §4.2.2 asks for the question to be repeated and does not
    /// let the client pick a different server for the second attempt, and a
    /// retry somewhere else would be a retry of somebody else's zone.
    server: base_addr.SocketAddr,
    /// The question again, byte for byte, including the `OPT` record. RFC 1035
    /// §4.2.2 asks for the same question to be repeated and not re-asked: the
    /// retry differs in the channel it travels on and in nothing else, so
    /// this is the framed bytes the datagram already carried rather than a
    /// second framing of the same question.
    query: []const u8,
    /// The transaction the retry is still under, which the answer behind the
    /// prefix must echo. Borrowed from the `id` the datagram answer was
    /// refused under, for §4.1.1's matching rule.
    id: u16,
};

/// Whether `message` is this question's answer at all, and whether it set the
/// `TC` bit that sends the question to a stream.
///
/// Null when the message did not set `TC`, which is the ordinary case and is
/// not an error. A `WireError` when the message is not this question's answer,
/// which is a different fact from one that came back short and the one a caller
/// must not retry: a foreign transaction is another lookup's answer, and
/// opening a connection because of it would be answering somebody else's
/// question.
///
/// The checks are `lookup_answer.readHeader`'s, in the order it makes them and
/// up to the `TC` bit, because that is where the ordering is argued: the
/// length, then the `ID`, then `QR`, then `TC`. The `RCODE` and the sections
/// are the answer's business and are read by `readAnswer` once the retry has
/// produced a whole one.
pub fn streamRetry(
    message: []const u8,
    id: u16,
    server: base_addr.SocketAddr,
    query: []const u8,
) Error!?StreamRetry {
    if (message.len < wire.header_length) return error.ShortMessage;
    if (wire.be16(message, 0) != id) return error.ForeignTransaction;
    const flags = wire.be16(message, 2);
    if (flags & wire.flag_response == 0) return error.NotAResponse;
    if (flags & wire.flag_truncated == 0) return null;
    return .{ .server = server, .query = query, .id = id };
}

/// §4.2.2's prefix, for a message of `message_length` bytes.
///
/// `error.MessageTooLong` is a real refusal and not a bound: a two-octet
/// prefix cannot name a longer message, so a caller holding one has to be
/// told rather than handed a length that wrapped.
pub fn writeLengthPrefix(
    prefix: *[length_prefix_bytes]u8,
    message_length: usize,
) Error!void {
    if (message_length > max_message_length) return error.MessageTooLong;
    wire.put16(prefix, 0, @intCast(message_length));
}

/// The message §4.2.2's prefix names, out of the bytes it was read from.
///
/// A slice and not a count, because the stream carries the prefix and the
/// message together: a caller that has read the prefix has to be handed the
/// message that follows it, and a bare count makes it do that indexing at a
/// place that can get it wrong. The result borrows `stream`; a message that
/// has not fully arrived is `error.ShortMessage` and not a partial one.
pub fn readLengthPrefix(stream: []const u8) Error![]const u8 {
    if (stream.len < length_prefix_bytes) return error.ShortMessage;
    const length = wire.be16(stream, 0);
    // Widened before the sum, not after it: a prefix may name `maxInt(u16)`
    // bytes and `length_prefix_bytes + length` in `u16` would wrap rather than
    // report a message that has not arrived.
    if (stream.len < length_prefix_bytes + @as(usize, length)) return error.ShortMessage;
    return stream[length_prefix_bytes..][0..length];
}

/// The instants, in milliseconds from the moment a walk began, at which another
/// query is due.
///
/// **Offsets from the start of the walk, not intervals between attempts**; see
/// the module doc, which quotes upstream for it. Six entries, so seven queries
/// in all with the one at zero.
pub const staggering_ms: [6]u64 = .{ 200, 300, 600, 1000, 2000, 3000 };

/// How many queries one walk issues: the one at the start plus one per entry
/// in `staggering_ms`.
pub const attempts: usize = staggering_ms.len + 1;

/// How long any one of those queries waits, in milliseconds.
///
/// `iroh-dns`'s `DNS_TIMEOUT`, which `iroh/src/address_lookup/dns.rs:20`
/// restates as "Each query has its own timeout of 3s".
pub const query_timeout_ms: u64 = 3000;

/// When a walk is finished, in milliseconds from its start: the last offset in
/// the table plus the wait on the query that offset starts.
///
/// `iroh/src/address_lookup/dns.rs:21` derives six seconds the same way, and
/// this is that derivation as code so the table and the budget cannot drift
/// apart unnoticed.
pub fn walkDeadlineMs() u64 {
    return staggering_ms[staggering_ms.len - 1] + query_timeout_ms;
}

/// How many of the `attempts` queries are due at `elapsed_ms` after a walk
/// began.
///
/// A count and not an index, because a caller that arrives late owes every ask
/// it missed: the queries are independent and RFC 1035 §7.2 wants each of them
/// asked, so a count is what says how far behind the walk is. The answer is
/// never zero, because the first query is due at zero and a walk that had not
/// issued anything would have issued nothing.
pub fn attemptsDue(elapsed_ms: u64) usize {
    var due: usize = 1;
    for (staggering_ms) |offset| {
        if (elapsed_ms < offset) break;
        due += 1;
    }
    return due;
}

const t = std.testing;

/// The server a retry would be made to, and a question it would repeat.
const nameserver: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 53 };
const asked = "www.example.com.";

/// A response header with the flags a test names and no sections at all.
fn header(id: u16, flags: u16) [wire.header_length]u8 {
    var message: [wire.header_length]u8 = undefined;
    wire.put16(&message, 0, id);
    wire.put16(&message, 2, flags);
    return message;
}

test "an answer that set TC says so, and only that answer does" {
    // The whole of `lookup_io.zig`'s refusal, turned into something a caller
    // can act on: a truncated answer is a retry to a stream and not an empty
    // answer, because an empty answer reads as "this host published nothing".
    const message = header(0x1234, wire.flag_response | wire.flag_truncated);
    const query = "the framed question, byte for byte";

    const retry = try streamRetry(&message, 0x1234, nameserver, query);
    try t.expectEqual(nameserver, retry.?.server);
    try t.expectEqualStrings(query, retry.?.query);
    try t.expectEqual(@as(u16, 0x1234), retry.?.id);

    // The same message with the bit clear is the ordinary answer and needs no
    // stream at all.
    const whole = header(0x1234, wire.flag_response);
    try t.expectEqual(@as(?StreamRetry, null), try streamRetry(&whole, 0x1234, nameserver, query));

    // A question arriving where an answer was wanted, and another lookup's
    // answer under another transaction: neither is this question's, and
    // opening a connection for either would be retrying a message that was
    // never ours.
    const question = header(0x1234, wire.flag_truncated);
    try t.expectError(error.NotAResponse, streamRetry(&question, 0x1234, nameserver, query));
    try t.expectError(
        error.ForeignTransaction,
        streamRetry(&message, 0x1235, nameserver, query),
    );
    try t.expectError(error.ShortMessage, streamRetry(message[0..4], 0x1234, nameserver, query));

    // And the two agree about the same bytes: a truncated answer is refused by
    // the decoder *and* is offered for a retry, so a caller cannot get one
    // without the other.
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    try t.expectError(error.Truncated, host_answer.readAnswer(
        t.allocator,
        &message,
        asked,
        .v4,
        0x1234,
        .{ .owner = &owner, .target = &held },
    ));
    try t.expect((try streamRetry(&message, 0x1234, nameserver, query)) != null);
}

test "a stream carries the two-octet prefix RFC 1035 §4.2.2 asks for" {
    // The prefix is the only difference between a DNS message on a stream and
    // the same message in a datagram, so it has to round-trip exactly and it
    // has to refuse a length it cannot spell.
    const question = [_]u8{ 0x00, 0x2a, 0x01, 0x02, 0x03, 0x04 };
    var prefix: [length_prefix_bytes]u8 = undefined;
    try writeLengthPrefix(&prefix, question.len);
    try t.expectEqual(@as(u16, 6), wire.be16(&prefix, 0));

    var stream: [length_prefix_bytes + 16]u8 = undefined;
    @memcpy(stream[0..length_prefix_bytes], &prefix);
    @memcpy(stream[length_prefix_bytes..][0..question.len], &question);
    const whole = stream[0 .. length_prefix_bytes + question.len];
    try t.expectEqualSlices(u8, &question, try readLengthPrefix(whole));

    // A zero-length message is a message: the prefix names it and the reader
    // hands back an empty slice rather than refusing, because `RDLENGTH`-free
    // emptiness is what a server sends when it has nothing to say.
    try writeLengthPrefix(&prefix, 0);
    try t.expectEqual(@as(u16, 0), wire.be16(&prefix, 0));
    try t.expectEqual(@as(usize, 0), (try readLengthPrefix(&prefix)).len);

    // The widest message the prefix can name, and the one it cannot.
    try writeLengthPrefix(&prefix, max_message_length);
    try t.expectEqual(@as(u16, std.math.maxInt(u16)), wire.be16(&prefix, 0));
    try t.expectError(error.MessageTooLong, writeLengthPrefix(&prefix, max_message_length + 1));

    // A prefix naming more than has arrived is a short message and not a
    // truncated answer: on a stream the rest is coming, and refusing here is
    // the caller's cue to read the rest rather than to ask again.
    try t.expectError(error.ShortMessage, readLengthPrefix(stream[0 .. length_prefix_bytes + 3]));
    try t.expectError(error.ShortMessage, readLengthPrefix(&prefix));
    try t.expectError(error.ShortMessage, readLengthPrefix(stream[0..1]));
}

test "the staggering table is upstream's six delays and they are offsets from the start" {
    // `iroh/src/address_lookup/dns.rs:22`, character for character. A table
    // that had drifted — a value reordered, one added, one dropped — would
    // still answer `attemptsDue` correctly for whatever it contained, so the
    // values themselves are the assertion and not a comment.
    try t.expectEqualSlices(u64, &.{ 200, 300, 600, 1000, 2000, 3000 }, &staggering_ms);
    // Seven queries: the one at zero and one per entry.
    try t.expectEqual(@as(usize, 7), attempts);
    // `query_timeout_ms` is `iroh-dns`'s `DNS_TIMEOUT`, three seconds, and the
    // last offset plus it is the six seconds that same doc derives.
    try t.expectEqual(@as(u64, 3000), query_timeout_ms);
    try t.expectEqual(@as(u64, 6000), walkDeadlineMs());
}

test "attempts are due by the instants in the table, counted from the walk's start" {
    // The distinction the module doc makes: offsets and not intervals. Under
    // offsets, 300 ms is the third query and 599 ms is still the third; under
    // intervals the fourth would already be due at 300 ms.
    try t.expectEqual(@as(usize, 1), attemptsDue(0));
    try t.expectEqual(@as(usize, 1), attemptsDue(199));
    try t.expectEqual(@as(usize, 2), attemptsDue(200));
    try t.expectEqual(@as(usize, 2), attemptsDue(299));
    try t.expectEqual(@as(usize, 3), attemptsDue(300));
    try t.expectEqual(@as(usize, 3), attemptsDue(599));
    try t.expectEqual(@as(usize, 4), attemptsDue(600));
    try t.expectEqual(@as(usize, 5), attemptsDue(1000));
    try t.expectEqual(@as(usize, 6), attemptsDue(2000));
    try t.expectEqual(@as(usize, 7), attemptsDue(3000));
    // The count saturates at the last entry rather than growing with elapsed
    // time, so a caller that is very late still owes seven queries and not
    // `elapsed_ms / 200` of them.
    try t.expectEqual(@as(usize, 7), attemptsDue(3001));
    try t.expectEqual(@as(usize, 7), attemptsDue(walkDeadlineMs()));
    try t.expectEqual(@as(usize, 7), attemptsDue(1_000_000));
    // And never zero: a walk that had issued nothing would have issued nothing.
    for (staggering_ms, 0..) |offset, index| {
        try t.expectEqual(index + 1, attemptsDue(offset - 1));
        try t.expectEqual(index + 2, attemptsDue(offset));
    }
}

test "a refused stream retry and an answer with no address are two different facts" {
    // The two answers a caller must not confuse, end to end and over the same
    // builder the walk is driven with: a name that exists and carries nothing
    // is `Answer` with no records, and a truncated answer is `error.Truncated`
    // plus a `StreamRetry`. Collapsing either into the other is how a host
    // that exists stops being dialled.
    var records: [64]u8 = undefined;
    // A whole answer with no records of the family asked about.
    wire.put16(&records, 0, 41);
    wire.put16(&records, 2, wire.flag_response);
    wire.put16(&records, 4, 1);
    wire.put16(&records, 6, 0);
    wire.put16(&records, 8, 0);
    wire.put16(&records, 10, 0);
    // The question starts after the header block, so the name goes there and
    // not over the transaction id the first line wrote.
    var at: usize = wire.header_length;
    at += try names.writeName(asked, records[wire.header_length..]);
    wire.put16(&records, at, wire.type_txt);
    wire.put16(&records, at + 2, wire.class_in);

    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const empty = try host_answer.readAnswer(
        t.allocator,
        records[0 .. at + wire.question_length],
        asked,
        .v4,
        41,
        .{ .owner = &owner, .target = &held },
    );
    defer empty.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), empty.records.len);
    try t.expectEqual(@as(?StreamRetry, null), try streamRetry(
        records[0 .. at + wire.question_length],
        41,
        nameserver,
        asked,
    ));

    // The same message with `TC` set is not an empty answer at all.
    const cut = header(41, wire.flag_response | wire.flag_truncated);
    try t.expectError(error.Truncated, host_answer.readAnswer(
        t.allocator,
        &cut,
        asked,
        .v4,
        41,
        .{ .owner = &owner, .target = &held },
    ));
}
