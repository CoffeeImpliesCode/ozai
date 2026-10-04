//! Tickets: a value, the postcard a peer reads, and the string a human pastes.
//!
//! This module is a port of `iroh-tickets` 1.0.0, `src/lib.rs` and
//! `src/endpoint.rs`, at commit
//! `cec7f1e119003980f238819e0f320ccb0ceaa691`, fetched 2026-09-30. iroh 1.3.0
//! has no ticket source of its own — `iroh-base/src/` at
//! `187f59e80afdae6bd9866002b33d3365c00b06d8` holds four files and none of
//! them is this — so the crate that owns the type is the upstream. The field
//! order below is that crate's, byte for byte, because a ticket is read by a
//! peer that knows nothing about ozai.
//!
//! # The three forms, and why they are three
//!
//! postcard bytes are what goes on the wire. The text form is what a person
//! pastes into a chat. The two are not interchangeable and neither one is
//! derivable from the other without a buffer, so `encode` and `encodeString`
//! take one each: the text is 1.6 times the bytes, and no single buffer holds
//! both without an in-place expansion, which costs more clarity than it saves
//! bytes on a value that is built once to be pasted.
//!
//! # The order the text form is built in
//!
//! `encodeString` is the kind prefix, then unpadded base32 of the bytes, and
//! the *whole string* is lower cased **after** the two are concatenated.
//! Upstream is `Self::KIND.to_string()`, then `encode_append`, then
//! `out.make_ascii_lowercase()`. The order is load bearing in one direction
//! only, and it is the direction that breaks: base32 emits upper case, so a
//! ticket whose body was left alone is a ticket whose body is upper case. A
//! peer still reads it — `decode_string` upper-cases before decoding — but it
//! is a second spelling of one value, which is the thing
//! `docs/ARCHITECTURE.md` invariant 2 exists to prevent. `encodeText` takes
//! the kind as a `comptime` parameter and refuses a prefix that is not lower
//! case, so the only lower casing that can happen is the one over the whole
//! string, and that is the one the tests pin.
//!
//! # What is shared, and where it lives
//!
//! The prefix, the base32 and the error set upstream keeps in the `Ticket`
//! trait are in `ticket_codec.zig`, together with the postcard encoding of
//! the address fields both kinds share. Zig has no traits, so the trait's own
//! half needs a module rather than one kind's module answering for the other;
//! what is left here is what each kind alone supplies — `KIND`, the field
//! order, and the two decode entry points.
//!
//! # Purity
//!
//! No clock, no environment, no global. A decode takes the allocator it uses
//! and hands back a `Decoded`, because a custom transport's payload has to
//! outlive the frame the bytes were read in — invariant 6 — and a ticket read
//! off the wire therefore owns storage a ticket built by hand does not. That
//! is the whole reason for the wrapper; `Decoded`'s doc says the rest.

const std = @import("std");
const addr = @import("../base/addr.zig");
const codec = @import("ticket_codec.zig");
const key = @import("../base/key.zig");
const node_addr = @import("../base/node_addr.zig");
const postcard = @import("../wire/postcard.zig");
const relay_url = @import("../base/relay_url.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Allocator = std.mem.Allocator;
const CustomAddr = addr.CustomAddr;
const NodeAddr = node_addr.NodeAddr;
const NodeId = key.NodeId;
const RelayUrl = relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;

const WireVariant = enum(u32) { variant1 = 0 };

// -- The endpoint ticket -----------------------------------------------------

/// `endpoint` — a node id and every address that might reach it.
///
/// Variant 1 carries the whole `EndpointAddr`, so unlike a blob ticket this
/// one is lossless: every `TransportAddr` a peer can hold survives the round
/// trip, and `encode` has nothing to report.
///
/// A ticket *built* by `new` borrows: this type has no `deinit`, so the
/// address list stays the caller's and the custom payloads in it stay
/// borrowed too. Only a `Decoded` owns storage, which is why `decodeBytes`
/// and `decodeString` hand one back rather than a bare ticket.
pub const EndpointTicket = struct {
    /// The kind prefix, and the only spelling `decodeString` accepts.
    pub const kind = "endpoint";

    /// The node and its addresses. For a ticket from `new` this borrows the
    /// caller's `NodeAddr` — list and payloads alike; for one inside a
    /// `Decoded` it is owned and released by that wrapper.
    addr: NodeAddr,

    /// A ticket over `address`, which it **borrows**.
    ///
    /// Nothing is copied and nothing is allocated, so `address` must stay
    /// alive, and must not be freed or mutated through another owner, for as
    /// long as the ticket is encoded from. This is the opposite of
    /// `BlobTicket.new`, which takes its address over: an `EndpointTicket`
    /// carries no custom payload copy to release, so it has no teardown to
    /// make the transfer unambiguous, and borrowing is the honest contract.
    pub fn new(address: NodeAddr) EndpointTicket {
        return .{ .addr = address };
    }

    /// postcard variant 1: the ticket discriminant, the node id, then the
    /// address list as a length and that many `TransportAddr`s.
    ///
    /// The list is `NodeAddr.addrs` in slice order, which is
    /// `TransportAddr.order` order and duplicate-free — invariant 2. That is
    /// what makes the bytes a function of the address rather than of the order
    /// it was built in, and it is the same order upstream's `BTreeSet`
    /// iterates, because postcard writes a set in its iteration order.
    ///
    /// The bytes returned are the prefix of `out` the writer filled, not a copy
    /// of it, so `out` must stay alive and unwritten for as long as they are
    /// read, and a later write through `out` invalidates them. A buffer too
    /// short for the ticket is `error.BufferFull`, and `out` then holds the
    /// prefix the writer committed before it ran out of room: a partial
    /// encoding rather than a ticket, which is why nothing is returned for it.
    pub fn encode(self: EndpointTicket, out: []u8) postcard.Error![]const u8 {
        var writer = postcard.Writer.init(out);
        try writer.writeVariant(WireVariant.variant1);
        try codec.writeNodeId(&writer, self.addr.node_id);
        try writer.writeLen(self.addr.addrs.len);
        for (self.addr.addrs) |one| try codec.writeTransportAddr(&writer, one);
        return writer.finish();
    }

    /// The postcard bytes as they would be written, for a caller that wants
    /// the length without producing them.
    pub fn maxEncodedLength(self: EndpointTicket) usize {
        var total: usize = 1 + key.NodeId.byte_length + postcard.varintMax(u64);
        for (self.addr.addrs) |one| total += codec.maxTransportAddrLength(one);
        return total;
    }

    /// The canonical text form of `body`, which must be what `encode`
    /// produced for this ticket. `textLength(kind, …)` sizes `out`.
    ///
    /// The text returned is the prefix of `out` that was filled and not a copy
    /// of it, so `out` must stay alive and unwritten for as long as it is read,
    /// and a later write through `out` invalidates it. `error.BufferFull`
    /// writes nothing. `encodeText` is where the shared contract is stated.
    pub fn encodeString(
        self: EndpointTicket,
        body: []const u8,
        out: []u8,
    ) codec.TextError![]const u8 {
        _ = self;
        return codec.encodeText(kind, body, out);
    }

    /// postcard bytes to a ticket.
    ///
    /// `alloc` takes the address list and every custom transport payload the
    /// result carries, and `Decoded` says so, so a ticket that borrows its
    /// payloads and one that owns them cannot be confused at the call site.
    ///
    /// A custom payload is copied only after the list is canonical, so a
    /// duplicate a peer sent costs no allocation and owns nothing; the
    /// surviving entries each get one copy. Every failure path — a malformed
    /// body, a `TransportAddr` this build refuses, or an allocation that
    /// fails part way through the copies — frees the payloads copied so far
    /// and the list, and returns nothing.
    pub fn decodeBytes(alloc: Allocator, bytes: []const u8) codec.DecodeError!Decoded {
        var reader = postcard.Reader.init(bytes);
        // The ticket discriminant is read as a number rather than through
        // `readVariant`, because a wrong one is not an unknown enum arm: it is
        // a ticket layout this build has no arm for, which is a different
        // thing from a field inside a ticket carrying an arm we lack, and a
        // caller reads the two differently.
        if (try reader.readU32() != @intFromEnum(WireVariant.variant1)) {
            return error.UnknownTicketVariant;
        }

        const id = try codec.readNodeId(&reader);
        // `readLen` has already refused a count the remaining bytes cannot
        // satisfy, and a `TransportAddr` is at least one byte, so the loop
        // below is bounded by the size of the input.
        const count = try reader.readLen();

        // Every address here still borrows `bytes`. That is what makes a
        // duplicate free to drop and what lets one payload be compared against
        // another before either is copied.
        var addrs: std.ArrayList(TransportAddr) = .empty;
        errdefer addrs.deinit(alloc);
        for (0..count) |_| try addrs.append(alloc, try codec.readTransportAddr(&reader));
        try reader.finish();
        // The wire order is upstream's `BTreeSet` order, which a peer is free
        // to ignore, and the set collapses a repeated address on the way in.
        // Both happen here; see `ticket_codec.canonicalizeAddrs`.
        addrs.items = codec.canonicalizeAddrs(addrs.items);

        // The list is final, so the copies are the ones that survive. A
        // payload freed below is one this call allocated and nothing else
        // holds.
        var owned: usize = 0;
        errdefer {
            for (addrs.items[0..owned]) |one| {
                if (one == .custom) alloc.free(one.custom.data);
            }
        }
        while (owned < addrs.items.len) : (owned += 1) {
            const one = &addrs.items[owned];
            switch (one.*) {
                .custom => |*custom| custom.data = try alloc.dupe(u8, custom.data),
                else => {},
            }
        }

        return .{ .ticket = .{
            .addr = .{ .node_id = id, .addrs = try addrs.toOwnedSlice(alloc) },
        } };
    }

    /// A ticket's text form to a ticket. The base32 body is decoded through a
    /// fresh allocation, because its length is whatever the text said it was.
    pub fn decodeString(alloc: Allocator, text: []const u8) codec.DecodeError!Decoded {
        const symbols = try codec.splitBody(kind, text);
        const raw = try alloc.alloc(u8, codec.byteLength(symbols.len));
        defer alloc.free(raw);
        try codec.decodeBase32(symbols, raw);
        return decodeBytes(alloc, raw);
    }
};

/// A ticket that was read off the wire, and therefore owns its storage.
///
/// The wrapper is not ceremony. A `TransportAddr::Custom` carries a payload
/// that has to outlive the frame the bytes were read in — invariant 6 — so
/// reading one means copying it onto the heap, and the copy is owned by the
/// code that made it. A ticket built from a `NodeAddr` the caller made
/// borrows that address's payloads instead, and a `deinit` that could not tell
/// those two apart would free a borrow. Only `decodeBytes` and `decodeString`
/// produce one of these, so only they can be freed this way.
///
/// Copying a `Decoded` copies the handle, not the storage: both copies name
/// one set of allocations and exactly one of them may be freed.
pub const Decoded = struct {
    /// The ticket. Its `NodeAddr` borrows nothing: every custom payload in
    /// `addr.addrs` is a copy this `Decoded` owns, and the outer list is one
    /// allocation of its own.
    ticket: EndpointTicket,

    /// Free the address list and every custom transport payload in it, each
    /// exactly once. All of them came from the `alloc` given to `decodeBytes`
    /// or `decodeString`, and the allocator that frees them is that same one.
    ///
    /// This is the only release for those allocations, so it runs exactly
    /// once per decode. Inserting a *new* custom address into the list after
    /// the decode borrows that address's payload, and freeing it here would
    /// free a borrow; inserting an address of any other kind is fine, because
    /// the payloads already in the list are the same ones either way.
    ///
    /// The ticket and every copy of it are invalid afterward.
    pub fn deinit(self: Decoded, alloc: Allocator) void {
        freeCustomPayloads(alloc, self.ticket.addr.addrs);
        self.ticket.addr.deinit(alloc);
    }
};

fn freeCustomPayloads(alloc: Allocator, addrs: []const TransportAddr) void {
    for (addrs) |one| {
        if (one == .custom) alloc.free(one.custom.data);
    }
}

const t = std.testing;

// Golden vectors below. The bytes are upstream's own, from
// `test "test_ticket_base32"` in `iroh-tickets` `src/endpoint.rs` at commit
// cec7f1e119003980f238819e0f320ccb0ceaa691, fetched 2026-09-30, read through
// the hexdump comment upstream annotates it with. The ticket string is a real
// published ticket: `tmc/go-iroh` `endpointticket/example_test.go` at commit
// a22a7c30ef8d5892ba144e2f72461edb3c541bdb hands that exact string to its
// decoder and asserts it names the id and two addresses.

// Half-length buffers rule out NoSpaceLeft. Invalid captured hex therefore
// fails the test that requested it, rather than terminating the whole runner.

const golden_hex =
    "00" ++
    "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" ++
    "02" ++
    // TransportAddr::Relay
    "00" ++
    // the relay url, 16 bytes
    "10" ++ "687474703a2f2f646572702e6d652e2f" ++
    // TransportAddr::Ip
    "01" ++
    // SocketAddr::V4
    "00" ++
    // 127.0.0.1, port 1024
    "7f0000018008";

const golden_ticket =
    "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaq" ++
    "acbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

const golden_id_hex = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";

fn expectHexEqual(expected_hex: []const u8, got: []const u8) !void {
    try t.expectEqual(expected_hex.len / 2, got.len);
    var index: usize = 0;
    while (index < got.len) : (index += 1) {
        var nibbles: [1]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nibbles, expected_hex[2 * index ..][0..2]);
        try t.expectEqual(nibbles[0], got[index]);
    }
}

/// The address the golden vector names, built the way a caller would.
fn goldenAddr(alloc: Allocator) !NodeAddr {
    const id = try NodeId.parseHex(golden_id_hex);
    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("http://derp.me./"));
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1024 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    return address;
}

test "golden: the endpoint ticket bytes, iroh-tickets src/endpoint.rs" {
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    const alloc = t.allocator;
    const decoded = try EndpointTicket.decodeBytes(alloc, bytes[0..60]);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(decoded.ticket.addr.addrs[0]));
    try t.expectEqualStrings("derp.me.", decoded.ticket.addr.addrs[0].relay.hostSlice());
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.ticket.addr.addrs[1]));
    try t.expectEqual(@as(u16, 1024), decoded.ticket.addr.addrs[1].ip.port);

    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);

    var again: [64]u8 = undefined;
    try expectHexEqual(golden_hex, try decoded.ticket.encode(&again));
}

test "golden: the endpoint ticket text form, tmc/go-iroh endpointticket" {
    const alloc = t.allocator;
    const decoded = try EndpointTicket.decodeString(alloc, golden_ticket);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);

    var body: [64]u8 = undefined;
    const bytes = try decoded.ticket.encode(&body);
    var text: [128]u8 = undefined;
    try t.expectEqualStrings(golden_ticket, try decoded.ticket.encodeString(bytes, &text));
}

test "the text form is a fixed point" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);

    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    const once = try ticket.encodeString(bytes, &first);
    const twice = try EndpointTicket.decodeString(alloc, once);
    defer twice.deinit(alloc);
    const again = try twice.ticket.encodeString(try twice.ticket.encode(&body), &second);

    try t.expectEqualStrings(once, again);
    try t.expectEqual(codec.textLength(EndpointTicket.kind, bytes.len), once.len);
}

test "the lower casing happens after the prefix, not before it" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);
    var text: [128]u8 = undefined;
    const written = try ticket.encodeString(bytes, &text);

    // The prefix is byte-identical to the kind and is in front.
    try t.expectEqualStrings(EndpointTicket.kind, written[0..EndpointTicket.kind.len]);
    // Nothing in the result is upper case, so the lower casing covered the
    // body. An implementation that lower cased the prefix and appended the
    // base32 untouched would leave 96 upper case bytes here and fail.
    for (written) |c| try t.expect(!std.ascii.isUpper(c));
    // And it covered the concatenation rather than either half: a body
    // assembled from the prefix alone would be the prefix.
    try t.expect(written.len > EndpointTicket.kind.len);

    // Upper case in the *body* is upstream's rule, not ours: `decode_string`
    // upper-cases what is left after the prefix before `data_encoding` sees
    // it. The prefix is not folded, which is the other half of the same
    // function and is checked in the test above.
    var upper: [128]u8 = undefined;
    const shouted_text = upper[0..written.len];
    @memcpy(shouted_text, written);
    const shouted_body = shouted_text[EndpointTicket.kind.len..];
    _ = std.ascii.upperString(shouted_body, written[EndpointTicket.kind.len..]);
    const shouted = try EndpointTicket.decodeString(alloc, shouted_text);
    defer shouted.deinit(alloc);
    try t.expect(std.ascii.eqlIgnoreCase(written, shouted_text));
    try t.expectEqualStrings(golden_id_hex, shouted.ticket.addr.node_id.toHex()[0..]);
}

test "a foreign kind prefix is not a ticket" {
    const alloc = t.allocator;
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, ""));
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, "blob"));
    // The prefix is matched exactly and is lower case. A ticket shouted in
    // its prefix is a different string, which is upstream's rule too: it
    // strips `Self::KIND` and does not fold case.
    try t.expectError(
        error.UnknownKind,
        EndpointTicket.decodeString(alloc, "Endpoint" ++ golden_ticket["endpoint".len..]),
    );
    // A prefix that is a prefix of the kind is a kind of nothing.
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, "endpoin"));
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, " endpoint"));
}

test "a body that is not whole bytes is refused" {
    // One symbol, and then six. Neither is a count `base32Length` produces
    // for any byte count: one is fewer than the two the smallest body needs,
    // and six is between the five a three-byte body produces and the seven a
    // four-byte body does. The text is complete in both cases, which is why
    // this is its own error and not `UnexpectedEnd`.
    try t.expectError(error.BadBase32Length, EndpointTicket.decodeString(t.allocator, "endpointa"));
    try t.expectError(
        error.BadBase32Length,
        EndpointTicket.decodeString(t.allocator, "endpointaaaaaa"),
    );
}

test "a character outside the alphabet is refused" {
    // '0', '1', '8' and '9' are the four symbols RFC 4648 base32 leaves out,
    // and two symbols is a legal body, so the length check passes and this is
    // the failure under test rather than the length one.
    for ("0189!=") |c| {
        var text: [16]u8 = undefined;
        @memcpy(text[0..EndpointTicket.kind.len], EndpointTicket.kind);
        text[EndpointTicket.kind.len] = 'a';
        text[EndpointTicket.kind.len + 1] = c;
        try t.expectError(error.BadBase32Symbol, EndpointTicket.decodeString(t.allocator, &text));
    }
}

test "bytes below the boundary are refused" {
    // 59 bytes is 95 symbols, and 95 * 5 is 475 bits for 472 bits of body,
    // so the last symbol carries two real bits and three pad bits. The
    // captured ticket is 60 bytes and therefore has none, which is why this
    // drops a byte rather than tampering with the ticket: `data-encoding`
    // checks trailing bits, and an encoder that emitted value in them would
    // be giving one ticket two spellings.
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    var buffer: [128]u8 = undefined;
    const body = bytes[0..59];
    @memcpy(buffer[0..EndpointTicket.kind.len], EndpointTicket.kind);
    const symbols = buffer[EndpointTicket.kind.len..][0..codec.base32Length(body.len)];
    codec.encodeBase32(body, symbols);
    const text = buffer[0 .. EndpointTicket.kind.len + symbols.len];
    try t.expectEqual(@as(usize, 95), symbols.len);

    // `encodeBase32` emits upper case — the lower casing belongs to
    // `encodeText` and is applied over the whole string — so the last symbol
    // here is 'A' and all five of its bits are pad.
    try t.expectEqual(@as(u8, 'A'), symbols[symbols.len - 1]);
    symbols[symbols.len - 1] = 'B';
    try t.expectError(error.NonZeroBase32Padding, EndpointTicket.decodeString(t.allocator, text));
}

test "trailing bytes after the body are refused" {
    const alloc = t.allocator;
    // One byte past the vector, so the byte this test adds past the body has
    // somewhere to land.
    var body: [golden_hex.len / 2 + 1]u8 = undefined;
    _ = try std.fmt.hexToBytes(body[0 .. golden_hex.len / 2], golden_hex);
    body[60] = 0x00;

    const decoded = EndpointTicket.decodeBytes(alloc, body[0..61]);
    try t.expectError(error.TrailingBytes, decoded);

    // The same through the text form: two more symbols are one more zero
    // byte, so the length stays legal and the failure is the one under test.
    var text: [128]u8 = undefined;
    @memcpy(text[0..golden_ticket.len], golden_ticket);
    text[golden_ticket.len] = 'a';
    text[golden_ticket.len + 1] = 'a';
    try t.expectError(
        error.TrailingBytes,
        EndpointTicket.decodeString(alloc, text[0 .. golden_ticket.len + 2]),
    );
}

test "a truncated body is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    // Cut inside a fixed-width field, or at the very end of the frame, and it
    // simply stops: `UnexpectedEnd`. Cut just after the address count and the
    // frame is not short — it claims two addresses and does not hold them,
    // which is `BadLength`, and is why the two are separate members of
    // `postcard.Error`.
    for ([_]usize{ 0, 1, 8, 20, 32, 33, 59 }) |length| {
        try t.expectError(error.UnexpectedEnd, EndpointTicket.decodeBytes(alloc, bytes[0..length]));
    }
    for ([_]usize{ 34, 35, 40, 50 }) |length| {
        try t.expectError(error.BadLength, EndpointTicket.decodeBytes(alloc, bytes[0..length]));
    }
}

test "a wire variant this build has no arm for is refused" {
    const alloc = t.allocator;
    var body: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, golden_hex);
    body[0] = 0x01;
    try t.expectError(error.UnknownTicketVariant, EndpointTicket.decodeBytes(alloc, &body));
}

/// `codec.TransportTag` with two discriminants this build writes no arm for:
/// the one immediately past the last arm, and one that needs two varint bytes.
/// `postcard.Writer.writeVariant` takes an enum rather than a number, so a
/// byte no declared arm names can only be produced by declaring the arm — the
/// wire has no such bound, which is the whole reason the decoder needs one.
const UnwrittenTransportTag = enum(u32) { relay = 0, ip = 1, custom = 2, next = 3, far = 128 };

/// The socket address's family, widened the same way. It is not the codec's
/// own enum: that one is private, because writing a family goes through
/// `writeSocketAddr`, and a test that has to name a discriminant no arm
/// covers needs an enum with that arm declared.
const UnwrittenIpFamily = enum(u32) { v4 = 0, v6 = 1, next = 2, far = 128 };

/// An endpoint ticket body naming one address under `tag`, with the rest of
/// that address written only for the tags this build has arms for. The two
/// unwritten tags therefore name a discriminant with nothing behind it, and
/// what a decode says about them cannot be a report of running out of bytes.
fn taggedAddrBody(tag: UnwrittenTransportTag) !struct { body: [128]u8, len: usize } {
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1024 };
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(tag);
    switch (tag) {
        .relay => try codec.writeRelayUrl(&writer, try RelayUrl.parse("https://r.example./")),
        .ip => try codec.writeSocketAddr(&writer, socket),
        .custom => {
            try writer.writeU64(0x2a);
            try writer.writeBytes(&[_]u8{ 0xab, 0xab });
        },
        .next, .far => {},
    }
    return .{ .body = body, .len = writer.finish().len };
}

/// An endpoint ticket body naming one socket address whose family
/// discriminant is `family`, with the address bytes written only for the two
/// families this build has arms for.
fn socketAddrBody(family: UnwrittenIpFamily) !struct { body: [128]u8, len: usize } {
    const v4_octets: [4]u8 = .{ 127, 0, 0, 1 };
    const v6_octets: [16]u8 = [_]u8{ 0x20, 0x01 } ** 8;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(codec.TransportTag.ip);
    try writer.writeVariant(family);
    switch (family) {
        .v4 => try writer.writeArray(4, &v4_octets),
        .v6 => try writer.writeArray(16, &v6_octets),
        .next, .far => {},
    }
    try writer.writeU16(1024);
    return .{ .body = body, .len = writer.finish().len };
}

test "every transport tag decodes to its own address, and every other one is refused by name" {
    const alloc = t.allocator;

    // The three tags `codec.TransportTag` names, each read back through a real
    // ticket decode and compared against the value it was written from.
    const relay = try taggedAddrBody(.relay);
    const from_relay = try EndpointTicket.decodeBytes(alloc, relay.body[0..relay.len]);
    defer from_relay.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_relay.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(from_relay.ticket.addr.addrs[0]));
    try t.expectEqualStrings("r.example.", from_relay.ticket.addr.addrs[0].relay.hostSlice());

    const ip = try taggedAddrBody(.ip);
    const from_ip = try EndpointTicket.decodeBytes(alloc, ip.body[0..ip.len]);
    defer from_ip.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_ip.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(from_ip.ticket.addr.addrs[0]));
    try t.expectEqual(@as(u16, 1024), from_ip.ticket.addr.addrs[0].ip.port);

    const custom = try taggedAddrBody(.custom);
    const from_custom = try EndpointTicket.decodeBytes(alloc, custom.body[0..custom.len]);
    defer from_custom.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_custom.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(from_custom.ticket.addr.addrs[0]));
    try t.expectEqual(@as(u64, 0x2a), from_custom.ticket.addr.addrs[0].custom.id);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, from_custom.ticket.addr.addrs[0].custom.data);

    // `next` is the first discriminant past the last arm and `far` is two
    // varint bytes wide, so between them they cover the whole of what a peer
    // may legally name. Both are refused at the discriminant, before the
    // decoder knows how long the address is, which is the boundary a
    // truncation test cannot see.
    for ([_]UnwrittenTransportTag{ .next, .far }) |tag| {
        const refused = try taggedAddrBody(tag);
        try t.expectError(
            error.UnknownVariant,
            EndpointTicket.decodeBytes(alloc, refused.body[0..refused.len]),
        );
    }
}

test "every ip family decodes to its own address bytes, and every other one is refused by name" {
    const alloc = t.allocator;
    const v4_octets: [4]u8 = .{ 127, 0, 0, 1 };
    const v6_octets: [16]u8 = [_]u8{ 0x20, 0x01 } ** 8;

    const v4 = try socketAddrBody(.v4);
    const from_v4 = try EndpointTicket.decodeBytes(alloc, v4.body[0..v4.len]);
    defer from_v4.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_v4.ticket.addr.addrs.len);
    try t.expectEqual(@as(u16, 1024), from_v4.ticket.addr.addrs[0].ip.port);
    switch (from_v4.ticket.addr.addrs[0].ip.ip) {
        .v4 => |octets| try t.expectEqualSlices(u8, &v4_octets, &octets),
        .v6 => return error.TestUnexpectedResult,
    }

    const v6 = try socketAddrBody(.v6);
    const from_v6 = try EndpointTicket.decodeBytes(alloc, v6.body[0..v6.len]);
    defer from_v6.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_v6.ticket.addr.addrs.len);
    try t.expectEqual(@as(u16, 1024), from_v6.ticket.addr.addrs[0].ip.port);
    switch (from_v6.ticket.addr.addrs[0].ip.ip) {
        .v6 => |octets| try t.expectEqualSlices(u8, &v6_octets, &octets),
        .v4 => return error.TestUnexpectedResult,
    }

    // Same boundary as the transport tag: the family is an exhaustive enum, so
    // the discriminant past `v6` is refused rather than read as a length that
    // happens to be short.
    for ([_]UnwrittenIpFamily{ .next, .far }) |family| {
        const refused = try socketAddrBody(family);
        try t.expectError(
            error.UnknownVariant,
            EndpointTicket.decodeBytes(alloc, refused.body[0..refused.len]),
        );
    }
}

test "an address list longer than the body is refused" {
    const alloc = t.allocator;
    var body: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, golden_hex);
    // The count is at offset 33. A peer may name any `u64` it likes and the
    // bytes behind it do not have to exist.
    body[33] = 0xff;
    body[34] = 0xff;
    body[35] = 0xff;
    body[36] = 0x7f;
    try t.expectError(error.BadLength, EndpointTicket.decodeBytes(alloc, &body));
}

test "a custom transport survives an endpoint ticket" {
    const alloc = t.allocator;
    var storage: [addr.max_inline_length]u8 = undefined;

    const id = try NodeId.parseHex(golden_id_hex);
    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("https://a.example./"));
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 41641 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    const transport = try CustomAddr.parse("2a_abab", &storage);
    address = (try address.insert(alloc, .{ .custom = transport })) orelse
        return error.TestUnexpectedResult;
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [128]u8 = undefined;
    const bytes = try ticket.encode(&body);
    var text: [256]u8 = undefined;
    const written = try ticket.encodeString(bytes, &text);

    const decoded = try EndpointTicket.decodeString(alloc, written);
    defer decoded.deinit(alloc);

    try t.expectEqual(@as(usize, 3), decoded.ticket.addr.addrs.len);
    const custom = decoded.ticket.addr.addrs[2];
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(custom));
    try t.expectEqual(@as(u64, 0x2a), custom.custom.id);
    try t.expectEqualSlices(u8, &.{ 0xab, 0xab }, custom.custom.data);

    // `EndpointTicket` is lossless, which is the whole difference from a blob
    // ticket: a re-encode is the same bytes.
    var again: [128]u8 = undefined;
    try t.expectEqualSlices(u8, bytes, try decoded.ticket.encode(&again));
}

test "a custom payload longer than a CustomAddr holds is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(codec.TransportTag.custom);
    try writer.writeU64(1);
    try writer.writeBytes(&[_]u8{0xaa} ** (addr.max_inline_length + 1));

    try t.expectError(error.CustomAddrTooLong, EndpointTicket.decodeBytes(alloc, writer.finish()));
}

test "a relay url the address layer will not take is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(codec.TransportTag.relay);
    try writer.writeStr("not a url");

    try t.expectError(error.BadRelayUrl, EndpointTicket.decodeBytes(alloc, writer.finish()));
}

test "an endpoint id that is not a point is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(body[0 .. golden_hex.len / 2], golden_hex);
    @memset(body[1..33], 0xff);
    try t.expectError(error.NotANodeId, EndpointTicket.decodeBytes(alloc, &body));
}

test "maxEncodedLength bounds every encoding this module writes" {
    const alloc = t.allocator;
    var storage: [addr.max_inline_length]u8 = undefined;
    const id = try NodeId.parseHex(golden_id_hex);

    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("https://a.example./"));
    const socket: SocketAddr = .{ .ip = .{ .v6 = [_]u8{ 0x20, 0x01 } ** 8 }, .port = 65535 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    const custom = try CustomAddr.parse(
        "ffffffffffffffff_00112233445566778899aabbccddeeff",
        &storage,
    );
    address = (try address.insert(alloc, .{ .custom = custom })) orelse
        return error.TestUnexpectedResult;
    defer address.deinit(alloc);

    const ticket = EndpointTicket.new(address);
    var body: [1024]u8 = undefined;
    const bytes = try ticket.encode(&body);
    try t.expect(bytes.len <= ticket.maxEncodedLength());
    try t.expect(ticket.maxEncodedLength() < body.len);
}

test "encodeString refuses a buffer it cannot fill" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);
    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);

    var text: [128]u8 = undefined;
    try t.expectError(
        error.BufferFull,
        ticket.encodeString(bytes, text[0 .. golden_ticket.len - 1]),
    );
}

test "a decoded address list is sorted and duplicate-free whatever order it arrives in" {
    const alloc = t.allocator;
    // Four addresses, the two from the golden vector twice over and out of
    // order. postcard reads a `BTreeSet` by inserting, so a peer that sends
    // this gets the same two addresses upstream would have built, and the
    // re-encode is the captured spelling rather than this one.
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(4);
    const ip: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1024 };
    const relay: RelayUrl = try RelayUrl.parse("http://derp.me./");
    try codec.writeTransportAddr(&writer, .{ .ip = ip });
    try codec.writeTransportAddr(&writer, .{ .relay = relay });
    try codec.writeTransportAddr(&writer, .{ .relay = relay });
    try codec.writeTransportAddr(&writer, .{ .ip = ip });

    const decoded = try EndpointTicket.decodeBytes(alloc, writer.finish());
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(decoded.ticket.addr.addrs[0]));
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.ticket.addr.addrs[1]));

    var again: [64]u8 = undefined;
    try expectHexEqual(golden_hex, try decoded.ticket.encode(&again));
}

/// An endpoint ticket body whose address list is the given number of copies
/// of one custom transport, so a decode has to collapse duplicates that each
/// carry their own payload.
fn duplicateCustomBody(copies: usize) !struct { body: [256]u8, len: usize } {
    var body: [256]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(copies);
    for (0..copies) |_| {
        try codec.writeTransportAddr(&writer, .{ .custom = .{ .id = 42, .data = "duplicate" } });
    }
    return .{ .body = body, .len = writer.finish().len };
}

/// Accounting wrapper: `EndpointTicket.decodeBytes` is the only allocator user
/// here, so the bytes it allocates and frees are the whole balance.
fn decodeAccounting(alloc: Allocator, bytes: []const u8) !void {
    var tracking = t.FailingAllocator.init(alloc, .{});
    const decoded = try EndpointTicket.decodeBytes(tracking.allocator(), bytes);
    decoded.deinit(tracking.allocator());
    try t.expectEqual(
        tracking.allocated_bytes,
        tracking.freed_bytes,
    );
}

test "a duplicate custom payload is freed exactly once, and only the survivor is copied" {
    const alloc = t.allocator;
    // Two copies of one address: the decode keeps one entry and must own one
    // payload for it. The dropped copy is never allocated, so the balance
    // after `deinit` is zero rather than one leaked payload.
    const made = try duplicateCustomBody(2);
    const body = made.body[0..made.len];

    var tracking = t.FailingAllocator.init(alloc, .{});
    const decoded = try EndpointTicket.decodeBytes(tracking.allocator(), body);
    try t.expectEqual(@as(usize, 1), decoded.ticket.addr.addrs.len);
    const custom = decoded.ticket.addr.addrs[0];
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(custom));
    try t.expectEqual(@as(u64, 42), custom.custom.id);
    try t.expectEqualSlices(u8, "duplicate", custom.custom.data);
    // The surviving payload is a copy, not the frame's bytes: the frame is
    // about to be freed, and the payload is still readable.
    try t.expect(custom.custom.data.ptr != "duplicate".ptr);
    decoded.deinit(tracking.allocator());
    try t.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);

    // A single copy is the same balance, so the fix is not "free the tail".
    const one = try duplicateCustomBody(1);
    try decodeAccounting(alloc, one.body[0..one.len]);
}

test "a malformed body copies nothing, and every allocation index frees what it took" {
    const alloc = t.allocator;
    // Three distinct custom addresses, so a successful decode holds three
    // payload copies and a failure part way through the copies has something
    // to hand back.
    const made = try threeCustomBody();
    const whole = made.body[0..made.len];

    // Truncated inside the third address. The payload copies come after the
    // whole body is read, so this fails having allocated only the address
    // list, and the list is what has to come back. The decoder names the
    // refusal by the field it could not read, not by the truncation.
    try t.expectError(
        error.BadLength,
        EndpointTicket.decodeBytes(alloc, whole[0 .. whole.len - 4]),
    );

    // And a body that would otherwise succeed, at every allocation index: the
    // copies are the last thing a decode does, so these are the indices where
    // one, two or three payloads have already been taken.
    try t.checkAllAllocationFailures(alloc, threePayloadsAccounting, .{whole});
}

/// An endpoint ticket body whose address list is three distinct custom
/// transports, so a decode that succeeds holds three payload copies and a
/// refusal part way through the copies has something to hand back. The same
/// shape as `duplicateCustomBody`, with the ids differing so no two entries
/// are duplicates.
fn threeCustomBody() !struct { body: [256]u8, len: usize } {
    var body: [256]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(3);
    try codec.writeTransportAddr(&writer, .{ .custom = .{ .id = 1, .data = "first" } });
    try codec.writeTransportAddr(&writer, .{ .custom = .{ .id = 2, .data = "second" } });
    try codec.writeTransportAddr(&writer, .{ .custom = .{ .id = 3, .data = "third" } });
    return .{ .body = body, .len = writer.finish().len };
}

/// Whether `pointer` names a byte inside `region`. A payload a decode copied
/// is its own allocation, so one pointing into the frame it was read out of
/// is a borrow a `Decoded` would later hand back as an owned copy.
fn insideRegion(region: []const u8, pointer: anytype) bool {
    const at = @intFromPtr(pointer);
    const low = @intFromPtr(region.ptr);
    return at >= low and at < low + region.len;
}

/// The ticket a decode of `threeCustomBody` owes its caller: the captured id,
/// three custom entries in id order, each payload equal to the bytes the body
/// named and copied out of the frame rather than borrowed from it.
///
/// This is the half of the sweep a balance cannot do. A decode that handed
/// back fewer payload copies, borrowed them, or reordered them still balances
/// its books exactly the same way, and this is what tells those three apart.
fn expectThreeCustomPayloads(decoded: *const Decoded, frame: []const u8) !void {
    try t.expectEqualStrings(golden_id_hex, decoded.ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(@as(usize, 3), decoded.ticket.addr.addrs.len);
    const wanted = [_]struct { id: u64, data: []const u8 }{
        .{ .id = 1, .data = "first" },
        .{ .id = 2, .data = "second" },
        .{ .id = 3, .data = "third" },
    };
    for (wanted, 0..) |want, at| {
        const one = decoded.ticket.addr.addrs[at];
        try t.expectEqual(TransportAddr.custom, std.meta.activeTag(one));
        try t.expectEqual(want.id, one.custom.id);
        try t.expectEqualSlices(u8, want.data, one.custom.data);
        try t.expect(!insideRegion(frame, one.custom.data.ptr));
    }
}

/// One run of `decodeBytes` for `t.checkAllAllocationFailures`: the answer is
/// checked and released, so a refusal anywhere in the address list or in the
/// payload copies has to hand all of it back before it returns.
fn threePayloadsAccounting(alloc: Allocator, bytes: []const u8) !void {
    const decoded = try EndpointTicket.decodeBytes(alloc, bytes);
    try expectThreeCustomPayloads(&decoded, bytes);
    decoded.deinit(alloc);
}

/// The same run through the text form, which allocates the base32 body before
/// it decodes anything and so stands one allocation further along.
fn threePayloadsTextAccounting(alloc: Allocator, text: []const u8) !void {
    const decoded = try EndpointTicket.decodeString(alloc, text);
    try expectThreeCustomPayloads(&decoded, text);
    // Releasing it under the testing allocator is the ownership check the
    // pointer comparison above cannot be: a payload pointing into the buffer
    // `decodeString` allocated and released on the way out would be freed
    // twice here, and the allocator says so by name.
    decoded.deinit(alloc);
}

test "every allocation a ticket's text decode makes can fail on its own" {
    const alloc = t.allocator;
    const made = try threeCustomBody();
    const whole = made.body[0..made.len];
    var text: [512]u8 = undefined;
    const written = try codec.encodeText(EndpointTicket.kind, whole, &text);

    // One allocation more than the binary form: the base32 body is decoded
    // through a fresh buffer, so the sweep runs over it and over everything
    // the binary sweep already reaches, and ends on the run nothing is
    // refused on.
    try t.checkAllAllocationFailures(alloc, threePayloadsTextAccounting, .{written});

    // The eventual consumer result: the text form names the same ticket the
    // bytes did, to the value and not merely to a length.
    const decoded = try EndpointTicket.decodeString(alloc, written);
    defer decoded.deinit(alloc);
    try expectThreeCustomPayloads(&decoded, written);
    var again: [128]u8 = undefined;
    try t.expectEqualSlices(u8, whole, try decoded.ticket.encode(&again));
}
