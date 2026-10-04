//! Fuzz target for the `endpoint` ticket decoder.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus to
//! Zig's coverage-guided fuzzer and lets it mutate for N iterations. A ticket
//! is the first thing in ozai that takes a string a stranger typed and turns
//! it into a node id and a set of addresses, and every one of those addresses
//! reaches a socket, so the string is exactly as untrusted as the bytes behind
//! it.

const std = @import("std");
const ozai = @import("ozai");
const endpoint_ticket = ozai.endpoint_ticket;
const ticket_codec = ozai.ticket_codec;
const t = std.testing;

const EndpointTicket = endpoint_ticket.EndpointTicket;

/// The seeds are the text forms a person or a peer would hand the decoder.
/// `real_ticket` is a real one: the string `tmc/go-iroh`
/// `endpointticket/example_test.go` at commit
/// a22a7c30ef8d5892ba144e2f72461edb3c541bdb hands to its own decoder, and its
/// bytes are the hexdump in `test "test_ticket_base32"` in `iroh-tickets`
/// `src/endpoint.rs` at commit
/// cec7f1e119003980f238819e0f320ccb0ceaa691. `custom_transport` is the same
/// captured field layout with a custom address in the list, which is the one
/// address kind a `BlobTicket` throws away and the reason that kind needs its
/// own target. The rest are the shapes the text form has a rule for.
/// `test/corpus/endpoint_ticket/` is the record, and a file there is live only
/// once it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/endpoint_ticket/empty"), // 0 bytes: not even a prefix
    @embedFile("corpus/endpoint_ticket/prefix_only"), // the kind and no body
    @embedFile("corpus/endpoint_ticket/bad_length"), // one symbol: not whole bytes
    @embedFile("corpus/endpoint_ticket/bad_symbol"), // '0' is in neither case nor alphabet
    @embedFile("corpus/endpoint_ticket/real_ticket"), // upstream: two addresses
    @embedFile("corpus/endpoint_ticket/uppercase_body"), // the same, shouted
    @embedFile("corpus/endpoint_ticket/truncated"), // a prefix of a real ticket
    @embedFile("corpus/endpoint_ticket/trailing_byte"), // a real ticket and one byte after
    @embedFile("corpus/endpoint_ticket/foreign_kind"), // a blob ticket
    @embedFile("corpus/endpoint_ticket/custom_transport"), // upstream layout, a custom address
};

/// Long enough for the longest seed and for a mutated input to still reach a
/// length check it was not grown for.
const input_buffer_len = 128;

/// The widest re-encoding the fuzzer's re-encode buffer has to hold.
///
/// The re-encode cannot grow without bound: postcard is not canonical, so a
/// count written `80 00` comes back as `00` and a length prefix can widen by a
/// few bytes, but every other field is either a fixed width or a re-rendering
/// of bytes that were already in the input — a relay URL is the widest, and
/// `RelayUrl.parse` then `format` makes at most one character longer, the
/// trailing slash. Twice the window is therefore slack rather than a proof. A
/// seed that ever did overrun it would come back as `error.BufferFull` from
/// `encode`, which is a declared error and so reads as a finding rather than a
/// bug; the size is checked against `maxEncodedLength` in the oracle below,
/// which is the bound a caller actually sizes from.
const reencode_len = input_buffer_len * 2;

/// `textLength` of the widest body `reencode_len` can hold.
const text_len = EndpointTicket.kind.len + ticket_codec.base32Length(reencode_len);

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length check would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "endpoint ticket decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const text = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try check(text);
}

fn check(text: []const u8) !void {
    const alloc = t.allocator;
    const decoded = EndpointTicket.decodeString(alloc, text) catch |err| {
        // Oracle: the error set is closed, and every member of it names a rule
        // the text broke. The one that says nothing about the input is
        // `OutOfMemory`, so a decode that failed for any other reason is a
        // value and this is where it is caught; an error outside the set would
        // be a bug in the decoder rather than a finding about the input.
        try t.expect(err != error.OutOfMemory);
        return;
    };
    defer decoded.deinit(alloc);

    // Oracle: invariant 2. A decoded address list is sorted and unique, so a
    // ticket's bytes are a function of the address and not of the order the
    // peer happened to write it in.
    var index: usize = 1;
    while (index < decoded.ticket.addr.addrs.len) : (index += 1) {
        try t.expectEqual(
            std.math.Order.lt,
            decoded.ticket.addr.addrs[index - 1].order(decoded.ticket.addr.addrs[index]),
        );
    }

    var body: [reencode_len]u8 = undefined;
    const bytes = try decoded.ticket.encode(&body);
    // Oracle: the size `encode` documents is a size. A caller sizes its buffer
    // from `maxEncodedLength`, and a body that overran it would be a value
    // rather than a report.
    try t.expect(bytes.len <= decoded.ticket.maxEncodedLength());

    var text_buffer: [text_len]u8 = undefined;
    const again = try decoded.ticket.encodeString(bytes, &text_buffer);
    // The re-encode is postcard's *canonical* spelling, not the one that was
    // sent — `[0x80, 0x00]` is a legal zero — so `again` need not be the input
    // at all, and asserting that it is would be asserting a property postcard
    // does not have. What it always is, is our own output: the kind in front,
    // and nothing upper case after it, which is the order the text form is
    // built in. A ticket whose body came out upper case is one that could not
    // be pasted anywhere.
    try t.expect(again.len <= text_len);
    try t.expect(std.mem.startsWith(u8, again, EndpointTicket.kind));
    for (again[EndpointTicket.kind.len..]) |c| try t.expect(!std.ascii.isUpper(c));

    // Oracle: fixed point. `again` came out of our own encoder, so reading it
    // back and writing it again is the same string. This is what makes a ticket
    // an identifier rather than a fresh value on every send, and a second
    // spelling of one ticket is what breaks it.
    const second = try EndpointTicket.decodeString(alloc, again);
    defer second.deinit(alloc);

    var second_body: [reencode_len]u8 = undefined;
    var second_text: [text_len]u8 = undefined;
    const second_again = try second.ticket.encodeString(
        try second.ticket.encode(&second_body),
        &second_text,
    );
    try t.expectEqualStrings(again, second_again);
}
