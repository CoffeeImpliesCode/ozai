//! Fuzz target for the `blob` ticket decoder.
//!
//! The endpoint ticket decoder is the one that has to be right about a node
//! id. This one has to be right about a projection: variant 0 carries one
//! relay and a set of direct addresses and nothing else, and a decoder that
//! hands back a ticket the wire could not have written would be a decoder that
//! reports a value variant 0 cannot express. The `loss` oracle below is what
//! keeps that honest, so the target is not a copy of the endpoint one.

const std = @import("std");
const ozai = @import("ozai");
const blob_ticket = ozai.blob_ticket;
const endpoint_ticket = ozai.endpoint_ticket;
const t = std.testing;

const BlobTicket = blob_ticket.BlobTicket;

/// The seeds are the text forms a person or a peer would hand the decoder.
/// `real_ticket` is the string the captured bytes of `test "test_ticket_base32"`
/// in iroh-blobs `src/ticket.rs` at commit
/// e82cbdcbdac9a78033174aad55e3199b2cf4c0dc produce under the `encode_string`
/// that commit captures; no iroh implementation publishes a blob ticket as
/// text, so this one string is derived from real bytes rather than copied from
/// a real string, and the bytes themselves are asserted in the module's own
/// test. The rest are the shapes the text form has a rule for.
/// `test/corpus/blob_ticket/` is the record, and a file there is live only
/// once it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/blob_ticket/empty"), // 0 bytes: not even a prefix
    @embedFile("corpus/blob_ticket/prefix_only"), // the kind and no body
    @embedFile("corpus/blob_ticket/bad_length"), // one symbol: not whole bytes
    @embedFile("corpus/blob_ticket/bad_symbol"), // '0' is in neither case nor alphabet
    @embedFile("corpus/blob_ticket/real_ticket"), // upstream: no address at all
    @embedFile("corpus/blob_ticket/uppercase_body"), // the same, shouted
    @embedFile("corpus/blob_ticket/truncated"), // a prefix of a real ticket
    @embedFile("corpus/blob_ticket/trailing_byte"), // a real ticket and one byte after
    @embedFile("corpus/blob_ticket/foreign_kind"), // an endpoint ticket
    @embedFile("corpus/blob_ticket/bad_format"), // a format discriminant with no arm
};

/// Long enough for the longest seed and for a mutated input to still reach a
/// length check it was not grown for.
const input_buffer_len = 128;

/// The widest re-encoding the fuzzer's re-encode buffer has to hold, and why
/// it is not smaller. A relay URL is the widest field and is re-rendered rather
/// than copied; `RelayUrl.parse` then `format` makes at most one character
/// longer, the trailing slash. The rest of the body is either a fixed width or
/// a re-emission of bytes that were already in the input. postcard is not
/// canonical, so a count written `80 00` comes back as `00` and a length
/// prefix can widen by a few bytes. Twice the window is slack rather than a
/// proof; a body that did overrun it would come back as `error.BufferFull`,
/// which is a declared error and reads as a finding rather than a bug.
const reencode_len = input_buffer_len * 2;

/// `textLength` of the widest body `reencode_len` can hold.
const text_len = BlobTicket.kind.len + endpoint_ticket.base32Length(reencode_len);

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length check would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "blob ticket decode" {
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
    const decoded = BlobTicket.decodeString(text, alloc) catch |err| {
        // Oracle: the error set is closed, and every member of it names a rule
        // the text broke. The one that says nothing about the input is
        // `OutOfMemory`, so a decode that failed for any other reason is a
        // value and this is where it is caught; an error outside the set would
        // be a bug in the decoder rather than a finding about the input.
        try t.expect(err != error.OutOfMemory);
        return;
    };
    defer decoded.deinit(alloc);

    // Oracle: the loss. Variant 0 has one relay slot and no arm for a custom
    // transport, so a ticket that came off the wire is one variant 0 could
    // have written. A non-empty answer here means the decoder built an address
    // from bytes the format cannot name, which is exactly the quiet value
    // change `blob_ticket.Loss` exists to make impossible.
    try t.expect(decoded.loss().isEmpty());

    // Oracle: invariant 2. A decoded address list is sorted and unique, so a
    // ticket's bytes are a function of the address and not of the order the
    // peer happened to write it in. postcard reads a `BTreeSet` by inserting,
    // so upstream absorbs a repeat and this must too.
    var index: usize = 1;
    while (index < decoded.addr.addrs.len) : (index += 1) {
        try t.expectEqual(
            std.math.Order.lt,
            decoded.addr.addrs[index - 1].order(decoded.addr.addrs[index]),
        );
    }

    var body: [reencode_len]u8 = undefined;
    const encoded = try decoded.encode(&body);
    // Oracle: the size `encode` documents is a size, and the loss an encode
    // reports is the loss the ticket had, which was nothing.
    try t.expect(encoded.bytes.len <= decoded.maxEncodedLength());
    try t.expect(encoded.loss.isEmpty());

    var text_buffer: [text_len]u8 = undefined;
    const again = try decoded.encodeString(encoded, &text_buffer);
    // The re-encode is postcard's *canonical* spelling, not the one that was
    // sent — `[0x80, 0x00]` is a legal zero — so `again` need not be the input
    // at all, and asserting that it is would be asserting a property postcard
    // does not have. What it always is, is our own output: the kind in front,
    // and nothing upper case after it, which is the order the text form is
    // built in. A ticket whose body came out upper case is one that could not
    // be pasted anywhere.
    try t.expect(again.len <= text_len);
    try t.expect(std.mem.startsWith(u8, again, BlobTicket.kind));
    for (again[BlobTicket.kind.len..]) |c| try t.expect(!std.ascii.isUpper(c));

    // Oracle: fixed point. `again` came out of our own encoder, so reading it
    // back and writing it again is the same string. Without the loss this also
    // holds for a ticket that had a custom transport, because the projection
    // is idempotent once it has happened; the first decode is where the loss
    // would show, and the oracle above is what catches that.
    const second = try BlobTicket.decodeString(again, alloc);
    defer second.deinit(alloc);

    var second_body: [reencode_len]u8 = undefined;
    var second_text: [text_len]u8 = undefined;
    const second_again = try second.encodeString(
        try second.encode(&second_body),
        &second_text,
    );
    try t.expectEqualStrings(again, second_again);
    try t.expectEqual(decoded.hash, second.hash);
    try t.expectEqual(decoded.format, second.format);
}
