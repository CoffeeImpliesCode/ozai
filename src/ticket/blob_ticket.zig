//! `blob` tickets: a provider, a hash, and the addresses variant 0 can carry.
//!
//! Ported from `n0-computer/iroh-blobs` `src/ticket.rs` and `src/hash.rs`, at
//! commit `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`, fetched 2026-09-30 — the
//! same commit `blobs/range_spec.zig` cites. The shared text form, the RFC
//! 4648 alphabet and the field writers live in `endpoint_ticket.zig`, which
//! is where upstream's `Ticket` trait lives; see that file for why.
//!
//! # Variant 0 is a projection, and this module says so
//!
//! Upstream's `BlobTicket` holds a whole `EndpointAddr`, and its `encode_bytes`
//! throws most of that away without a word:
//!
//! ```ignore
//! info: Variant0AddrInfo {
//!     relay_url: self.addr.relay_urls().next().cloned(),
//!     direct_addresses: self.addr.ip_addrs().cloned().collect(),
//! },
//! ```
//!
//! The wire shape is `Option<RelayUrl>` plus `BTreeSet<SocketAddr>`. There is
//! no arm for `TransportAddr::Custom`, so every custom transport is gone; and
//! one `Option` holds one relay, so an address with two of them keeps the
//! first. `encode_bytes` returns a `Vec<u8>` and the caller has no way to
//! learn either happened.
//!
//! The bytes here are upstream's, byte for byte. What is different is the
//! return: `encode` hands back an `Encoded` carrying a `Loss` next to the
//! bytes, and `loss()` answers the same question without encoding. A round
//! trip that quietly changed the value is worse than one that fails, so this
//! one cannot look like success. Nothing refuses the ticket, because a relay
//! and a set of direct addresses is a complete answer to "where do I fetch
//! this blob from" on any network where a custom transport is not in play —
//! it just is not the whole answer, and now the caller is told which part it
//! is missing.
//!
//! # Ownership
//!
//! A decoded ticket's address list is the only thing it owns, and variant 0
//! cannot put a custom payload in it, so `deinit` is `NodeAddr.deinit` and
//! nothing more. That is why this kind returns a bare `BlobTicket` where
//! `EndpointTicket` returns a `Decoded` wrapper: the wrapper exists for the
//! custom payload copy, and there is no such copy here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");
const shared = @import("endpoint_ticket.zig");

const Allocator = std.mem.Allocator;

pub const NodeId = key.NodeId;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const SocketAddr = addr.SocketAddr;
pub const RelayUrl = addr.RelayUrl;

const writeNodeId = shared.writeNodeId;
const readNodeId = shared.readNodeId;
const writeRelayUrl = shared.writeRelayUrl;
const readRelayUrl = shared.readRelayUrl;
const writeSocketAddr = shared.writeSocketAddr;
const readSocketAddr = shared.readSocketAddr;
const canonicalizeAddrs = shared.canonicalizeAddrs;

pub const TextError = shared.TextError;
pub const BodyError = shared.BodyError;
pub const DecodeError = shared.DecodeError;

/// 32 bytes, the hash a blob is named by.
///
/// iroh-blobs wraps a `blake3::Hash` and calls it `Hash`. The content
/// addressed type that gives those bytes meaning arrives with M11, and until
/// then a ticket carries the bytes and nothing claims to know what they are.
pub const Hash = [32]u8;

pub const hash_length = 32;

pub const hash_hex_length = hash_length * 2;

/// Lowercase hex, the form a ticket's hash is printed and pasted in.
pub fn hashToHex(hash: Hash) [hash_hex_length]u8 {
    return std.fmt.bytesToHex(&hash, .lower);
}

pub const HashParseError = error{
    /// Not `hash_hex_length` characters.
    BadLength,
    /// Not a hex digit.
    NotHex,
};

pub fn parseHashHex(text: []const u8) HashParseError!Hash {
    if (text.len != hash_hex_length) return error.BadLength;
    var hash: Hash = undefined;
    _ = std.fmt.hexToBytes(&hash, text) catch return error.NotHex;
    return hash;
}

/// The shape of a blob, and the thing that says whether one hash names a blob
/// or a sequence of them.
///
/// The discriminants are `Raw = 0` and `HashSeq = 1`, and they are postcard
/// `varint(u32)`s like every other enum on these wires.
pub const BlobFormat = enum(u32) {
    /// One blob at this hash.
    raw = 0,
    /// A sequence of BLAKE3 hashes whose first member is a metadata blob.
    hash_seq = 1,
};

/// The ticket layout this build has an arm for. Upstream declares one variant
/// and the comment above it says the others may come later, so the discriminant
/// is read as a number rather than as an enum: a wrong one is a layout this
/// build does not have, not an unknown arm of a layout it does.
const WireVariant = enum(u32) { variant0 = 0 };

/// What variant 0 cannot carry.
///
/// See the module comment. Both members are counts, not flags, because "this
/// address had two home relays" and "this address had four custom transports"
/// are different problems for whoever reads the answer.
pub const Loss = struct {
    /// `TransportAddr::Custom` values the address carried. Variant 0 has no
    /// arm for a custom transport at all, so every one of them is dropped and
    /// a peer given this ticket cannot reach the node over one.
    custom: usize = 0,
    /// Relay URLs past the first. Variant 0 carries a single
    /// `Option<RelayUrl>`, and upstream fills it from `relay_urls().next()`.
    /// The one that survives is the first in `TransportAddr.order`, which is
    /// the lowest relay URL and not necessarily the one a caller would have
    /// called the home relay.
    relays: usize = 0,

    pub fn isEmpty(self: Loss) bool {
        return self.custom == 0 and self.relays == 0;
    }
};

/// What one `encode` produced: the bytes, and what they could not carry.
pub const Encoded = struct {
    /// postcard variant 0. Byte for byte what upstream writes.
    bytes: []const u8,
    /// What the projection dropped. Read it; an `encode` that lost nothing
    /// and one that lost a custom transport return the same `bytes` type and
    /// the same `error` set, and the difference is the whole point.
    loss: Loss,
};

/// `blob` — everything needed to fetch one blob from one provider.
///
/// A ticket that came off the wire carries at most one relay and any number
/// of direct addresses, because that is all variant 0 has room for. A ticket
/// built here can carry more, and `loss` is how a caller finds out before it
/// relies on the round trip.
pub const BlobTicket = struct {
    /// The kind prefix, and the only spelling `decodeString` accepts.
    pub const kind = "blob";

    addr: NodeAddr,
    format: BlobFormat,
    hash: Hash,

    pub fn new(address: NodeAddr, hash: Hash, format: BlobFormat) BlobTicket {
        return .{ .addr = address, .hash = hash, .format = format };
    }

    /// Free the address list, which is the only thing a decoded ticket owns.
    ///
    /// There is no custom payload to free, because variant 0 has nowhere to
    /// put one. `EndpointTicket` needs a wrapper for exactly that copy; this
    /// does not, and saying so is why the two differ.
    pub fn deinit(self: BlobTicket, alloc: Allocator) void {
        self.addr.deinit(alloc);
    }

    /// What an `encode` of this ticket would drop.
    ///
    /// The same answer `encode` reports, without the bytes. A caller that has
    /// to decide whether a ticket is safe to share — a custom transport may
    /// be the only path to the node — asks this before it commits to the
    /// string.
    pub fn loss(self: BlobTicket) Loss {
        var dropped: Loss = .{};
        var relays: usize = 0;
        for (self.addr.addrs) |one| switch (one) {
            .relay => {
                relays += 1;
                // The first one is the one `Option<RelayUrl>` keeps.
                if (relays > 1) dropped.relays += 1;
            },
            .ip => {},
            .custom => dropped.custom += 1,
        };
        return dropped;
    }

    /// postcard variant 0: the ticket discriminant, the provider's node id,
    /// one optional relay URL, the direct addresses as a length and that many
    /// `SocketAddr`s, the format, and the hash.
    ///
    /// The direct addresses are written in `NodeAddr.addrs` order, which is
    /// `SocketAddr.order` order and duplicate-free, and that is the order
    /// upstream's `BTreeSet<SocketAddr>` iterates. A custom transport and
    /// every relay past the first are not written at all; `loss` says so.
    pub fn encode(self: BlobTicket, out: []u8) postcard.Error!Encoded {
        var writer = postcard.Writer.init(out);
        try writer.writeVariant(WireVariant.variant0);
        try writeNodeId(&writer, self.addr.node_id);

        const relay = firstRelay(self.addr.addrs);
        try writer.writeOption(relay != null);
        if (relay) |url| try writeRelayUrl(&writer, url);

        try writer.writeLen(directCount(self.addr.addrs));
        for (self.addr.addrs) |one| {
            if (one == .ip) try writeSocketAddr(&writer, one.ip);
        }

        try writer.writeVariant(self.format);
        try writer.writeArray(hash_length, &self.hash);
        return .{ .bytes = writer.finish(), .loss = self.loss() };
    }

    /// An upper bound on the postcard size, so one buffer can hold both the
    /// bytes and the text form.
    pub fn maxEncodedLength(self: BlobTicket) usize {
        var total: usize =
            1 + // the ticket discriminant
            key.NodeId.byte_length +
            1 + // the relay option tag
            postcard.varintMax(u64) + shared.relay_url_text_max +
            postcard.varintMax(u64) + // the direct address count
            postcard.varintMax(u32) + // the format
            hash_length;
        for (self.addr.addrs) |one| {
            switch (one) {
                .ip => total += 1 + 1 + 16 + postcard.varintMax(u16),
                else => {},
            }
        }
        return total;
    }

    /// The canonical text form of `encoded.bytes`, which must be what `encode`
    /// produced. `shared.textLength(kind, …)` sizes `out`.
    pub fn encodeString(
        self: BlobTicket,
        encoded: Encoded,
        out: []u8,
    ) TextError![]const u8 {
        _ = self;
        return shared.encodeText(kind, encoded.bytes, out);
    }

    /// postcard bytes to a ticket. The address list comes from `alloc`; see
    /// `deinit`.
    pub fn decodeBytes(bytes: []const u8, alloc: Allocator) DecodeError!BlobTicket {
        var reader = postcard.Reader.init(bytes);
        if (try reader.readU32() != @intFromEnum(WireVariant.variant0)) {
            return error.UnknownTicketVariant;
        }
        const id = try readNodeId(&reader);

        var addrs: std.ArrayList(TransportAddr) = .empty;
        errdefer addrs.deinit(alloc);
        // The relay goes in first, and relay sorts before ip, so appending in
        // wire order already lands in `TransportAddr.order`. A peer is free to
        // send the direct addresses in another order, or the same one twice,
        // and upstream's `BTreeSet` would absorb both; `canonicalizeAddrs`
        // does the same and is why the re-encode of a decoded ticket is
        // postcard's canonical spelling rather than the one that was sent.
        if (try reader.readOption()) {
            try addrs.append(alloc, .{ .relay = try readRelayUrl(&reader) });
        }
        const count = try reader.readLen();
        for (0..count) |_| try addrs.append(alloc, .{ .ip = try readSocketAddr(&reader) });

        const format = try reader.readVariant(BlobFormat);
        const hash = try reader.readArray(hash_length);
        try reader.finish();
        addrs.items = canonicalizeAddrs(addrs.items);

        return .{
            .addr = .{ .node_id = id, .addrs = try addrs.toOwnedSlice(alloc) },
            .format = format,
            .hash = hash,
        };
    }

    /// A ticket's text form to a ticket. The base32 body is decoded through a
    /// fresh allocation, because its length is whatever the text said it was.
    pub fn decodeString(text: []const u8, alloc: Allocator) DecodeError!BlobTicket {
        const symbols = try shared.splitBody(kind, text);
        const raw = try alloc.alloc(u8, shared.byteLength(symbols.len));
        defer alloc.free(raw);
        try shared.decodeBase32(symbols, raw);
        return decodeBytes(raw, alloc);
    }
};

/// The relay variant 0 keeps: the first in `TransportAddr.order`, which is
/// what `relay_urls().next()` walks to upstream. `addrs` is sorted, so that
/// is the first `.relay` in the slice.
fn firstRelay(addrs: []const TransportAddr) ?RelayUrl {
    for (addrs) |one| {
        if (one == .relay) return one.relay;
    }
    return null;
}

fn directCount(addrs: []const TransportAddr) usize {
    var count: usize = 0;
    for (addrs) |one| {
        if (one == .ip) count += 1;
    }
    return count;
}

const t = std.testing;

// Golden vector below: `test "test_ticket_base32"` in iroh-blobs `src/ticket.rs`
// at commit e82cbdcbdac9a78033174aad55e3199b2cf4c0dc, fetched 2026-09-30, read
// through the `parse_hexdump` comment upstream annotates it with. The ticket
// *string* is derived from those bytes by the captured `Ticket::encode_string`
// — no iroh implementation publishes a blob ticket in text form — and is
// pinned here so the derivation cannot drift.

const golden_hex =
    "00" ++
    // endpoint id, 32 bytes
    "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" ++
    // relay url: none
    "00" ++
    // direct addresses: none
    "00" ++
    // format: raw
    "00" ++
    // hash, 32 bytes
    "0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072";

const golden_ticket =
    "blobacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublma" ++
    "aaaafyju2y4tel43bymjvsdax7k5mbrotl2p2lsbdetff6ctftksqhe";

const golden_id_hex = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";

const golden_hash_hex = "0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072";

fn expectHexEqual(expected_hex: []const u8, got: []const u8) !void {
    try t.expectEqual(expected_hex.len / 2, got.len);
    var index: usize = 0;
    while (index < got.len) : (index += 1) {
        var nibble: [1]u8 = undefined;
        _ = std.fmt.hexToBytes(&nibble, expected_hex[2 * index ..][0..2]) catch unreachable;
        try t.expectEqual(nibble[0], got[index]);
    }
}

/// A provider reachable at 127.0.0.1:1234, which is the address upstream's
/// own `make_ticket` uses.
fn providerAddr(alloc: Allocator) !NodeAddr {
    const id = try NodeId.parseHex(golden_id_hex);
    var address = NodeAddr.init(id);
    return (try address.insert(alloc, .{
        .ip = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 },
    })).?;
}

test "golden: the blob ticket bytes, iroh-blobs src/ticket.rs" {
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;

    const alloc = t.allocator;
    const decoded = try BlobTicket.decodeBytes(bytes[0..68], alloc);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.addr.node_id.toHex()[0..]);
    try t.expectEqual(BlobFormat.raw, decoded.format);
    try t.expectEqualStrings(golden_hash_hex, hashToHex(decoded.hash)[0..]);
    // The vector is the *no address* case: one relay slot and zero direct
    // addresses is the whole of what the provider half can say.
    try t.expectEqual(@as(usize, 0), decoded.addr.addrs.len);

    var again: [72]u8 = undefined;
    try expectHexEqual(golden_hex, (try decoded.encode(&again)).bytes);
}

test "golden: the blob ticket text form" {
    const alloc = t.allocator;
    const decoded = try BlobTicket.decodeString(golden_ticket, alloc);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.addr.node_id.toHex()[0..]);
    try t.expectEqualStrings(golden_hash_hex, hashToHex(decoded.hash)[0..]);
    try t.expectEqual(BlobFormat.raw, decoded.format);

    var body: [72]u8 = undefined;
    const encoded = try decoded.encode(&body);
    var text: [128]u8 = undefined;
    try t.expectEqualStrings(golden_ticket, try decoded.encodeString(encoded, &text));
    try t.expect(encoded.loss.isEmpty());
}

test "the text form is a fixed point" {
    const alloc = t.allocator;
    const address = try providerAddr(alloc);
    defer address.deinit(alloc);
    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .hash_seq);

    var body: [256]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expect(encoded.loss.isEmpty());

    var first: [512]u8 = undefined;
    var second: [512]u8 = undefined;
    const once = try ticket.encodeString(encoded, &first);
    const twice = try BlobTicket.decodeString(once, alloc);
    defer twice.deinit(alloc);
    const again = try twice.encodeString(try twice.encode(&body), &second);

    try t.expectEqualStrings(once, again);
    try t.expectEqual(shared.textLength(BlobTicket.kind, encoded.bytes.len), once.len);
}

test "a ticket with no custom transport round trips through variant 0 unchanged" {
    const alloc = t.allocator;
    var address = try NodeAddr.withRelay(
        alloc,
        try NodeId.parseHex(golden_id_hex),
        try RelayUrl.parse("https://relay.example/"),
    );
    address = (try address.insert(alloc, .{ .ip = .{
        .ip = .{ .v4 = .{ 192, 0, 2, 7 } },
        .port = 41641,
    } })).?;
    address = (try address.insert(alloc, .{ .ip = .{
        .ip = .{ .v6 = [_]u8{ 0x20, 0x01 } ** 8 },
        .port = 443,
    } })).?;
    defer address.deinit(alloc);

    const hash = try parseHashHex(golden_hash_hex);
    const ticket = BlobTicket.new(address, hash, .hash_seq);
    // Nothing to report is the precondition for trusting the round trip, so
    // it is checked before the round trip rather than inferred from it.
    try t.expect(ticket.loss().isEmpty());

    var body: [256]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expect(encoded.loss.isEmpty());
    try t.expect(encoded.bytes.len <= ticket.maxEncodedLength());

    var text: [512]u8 = undefined;
    const written = try ticket.encodeString(encoded, &text);

    const decoded = try BlobTicket.decodeString(written, alloc);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.addr.node_id.toHex()[0..]);
    try t.expectEqual(hash, decoded.hash);
    try t.expectEqual(BlobFormat.hash_seq, decoded.format);
    try t.expectEqual(@as(usize, 3), decoded.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(decoded.addr.addrs[0]));
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.addr.addrs[1]));
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.addr.addrs[2]));

    // `IpAddress.order` puts v4 before v6, so the direct set comes back in
    // that order; the caller above inserted the v6 address second and it is
    // still the one that sorts last.
    for (decoded.addr.addrs[1..]) |one| {
        try t.expectEqual(TransportAddr.ip, std.meta.activeTag(one));
    }
    try t.expectEqual(@as(usize, 1), decoded.addr.relayCount());
    try t.expectEqual(@as(u16, 41641), decoded.addr.addrs[1].ip.port);
    try t.expectEqual(@as(u16, 443), decoded.addr.addrs[2].ip.port);
    var again: [256]u8 = undefined;
    try t.expectEqualSlices(u8, encoded.bytes, (try decoded.encode(&again)).bytes);
    // A ticket that came off the wire is one variant 0 could have written.
    try t.expect(decoded.loss().isEmpty());
}

test "variant 0 drops a custom transport, and the ticket says so" {
    const alloc = t.allocator;
    var storage: [addr.max_inline_length]u8 = undefined;

    var address = try NodeAddr.withRelay(
        alloc,
        try NodeId.parseHex(golden_id_hex),
        try RelayUrl.parse("https://relay.example/"),
    );
    address = (try address.insert(alloc, .{
        .custom = try addr.CustomAddr.parse("2a_abab", &storage),
    })).?;
    defer address.deinit(alloc);

    const hash = try parseHashHex(golden_hash_hex);
    const ticket = BlobTicket.new(address, hash, .raw);

    // The question can be asked before anything is written.
    try t.expectEqual(@as(usize, 1), ticket.loss().custom);
    try t.expectEqual(@as(usize, 0), ticket.loss().relays);
    try t.expect(!ticket.loss().isEmpty());

    var body: [256]u8 = undefined;
    const encoded = try ticket.encode(&body);
    // And the encode reports it, so a caller that only kept the bytes is
    // still holding the answer.
    try t.expectEqual(@as(usize, 1), encoded.loss.custom);
    try t.expect(!encoded.loss.isEmpty());

    var text: [512]u8 = undefined;
    const written = try ticket.encodeString(encoded, &text);

    const decoded = try BlobTicket.decodeString(written, alloc);
    defer decoded.deinit(alloc);

    // The loss is real, not a report of one: the custom transport is simply
    // not there, and nothing about the decode says so unless the encode said
    // so first. That asymmetry is the whole reason `Loss` exists.
    try t.expectEqual(@as(usize, 1), decoded.addr.addrs.len);
    for (decoded.addr.addrs) |one| {
        try t.expect(one != .custom);
    }
    try t.expect(decoded.loss().isEmpty());
}

test "variant 0 keeps one relay out of several, and the ticket says which" {
    const alloc = t.allocator;
    const id = try NodeId.parseHex(golden_id_hex);
    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("https://a.example./"));
    const second: TransportAddr = .{ .relay = try RelayUrl.parse("https://b.example./") };
    const third: TransportAddr = .{ .relay = try RelayUrl.parse("https://c.example./") };
    address = (try address.insert(alloc, second)).?;
    address = (try address.insert(alloc, third)).?;
    defer address.deinit(alloc);

    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .raw);
    try t.expectEqual(@as(usize, 2), ticket.loss().relays);
    try t.expectEqual(@as(usize, 0), ticket.loss().custom);

    var body: [512]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expectEqual(@as(usize, 2), encoded.loss.relays);

    const decoded = try BlobTicket.decodeBytes(encoded.bytes, alloc);
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 1), decoded.addr.addrs.len);
    // `relay_urls().next()` is the first in `TransportAddr.order`, which is
    // the lowest URL. The ticket does not get to choose.
    try t.expectEqualStrings("a.example.", decoded.addr.addrs[0].relay.hostSlice());
}

test "a foreign kind prefix is not a blob ticket" {
    const alloc = t.allocator;
    try t.expectError(error.UnknownKind, BlobTicket.decodeString("", alloc));
    try t.expectError(error.UnknownKind, BlobTicket.decodeString("endpoint", alloc));
    try t.expectError(
        error.UnknownKind,
        BlobTicket.decodeString("Blob" ++ golden_ticket["blob".len..], alloc),
    );
    try t.expectError(error.UnknownKind, BlobTicket.decodeString(" blob", alloc));
    try t.expectError(error.UnknownKind, BlobTicket.decodeString("bl", alloc));
}

test "a body that is not whole bytes is refused" {
    try t.expectError(error.BadBase32Length, BlobTicket.decodeString("bloba", t.allocator));
    try t.expectError(error.BadBase32Length, BlobTicket.decodeString("blobaaaaaa", t.allocator));
}

test "a character outside the alphabet is refused" {
    try t.expectError(error.BadBase32Symbol, BlobTicket.decodeString("bloba0", t.allocator));
    try t.expectError(error.BadBase32Symbol, BlobTicket.decodeString("bloba!", t.allocator));
}

test "trailing bytes after the body are refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    bytes[68] = 0x00;
    try t.expectError(error.TrailingBytes, BlobTicket.decodeBytes(bytes[0..69], alloc));

    var text: [128]u8 = undefined;
    @memcpy(text[0..golden_ticket.len], golden_ticket);
    text[golden_ticket.len] = 'a';
    text[golden_ticket.len + 1] = 'a';
    try t.expectError(
        error.TrailingBytes,
        BlobTicket.decodeString(text[0 .. golden_ticket.len + 2], alloc),
    );
}

test "a truncated body is refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    // Every cut of this vector is `UnexpectedEnd` and none of them is
    // `BadLength`, which is a fact about the vector and not a rule: its only
    // length prefix is a zero direct-address count, so no cut can leave a
    // prefix claiming more than the bytes behind it. The case where it does
    // is a test of its own below.
    for ([_]usize{ 0, 1, 8, 32, 33, 34, 35, 36, 40, 67 }) |length| {
        try t.expectError(error.UnexpectedEnd, BlobTicket.decodeBytes(bytes[0..length], alloc));
    }
}

test "a format this build has no arm for is refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    // 68 bytes, laid out: variant 0, the id at 1..33, the relay option at 33,
    // the direct count at 34, the format at 35, and the hash at 36..68.
    bytes[35] = 0x07;
    try t.expectError(error.UnknownVariant, BlobTicket.decodeBytes(bytes[0..68], alloc));
}

test "a wire variant this build has no arm for is refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    bytes[0] = 0x01;
    try t.expectError(error.UnknownTicketVariant, BlobTicket.decodeBytes(bytes[0..68], alloc));
}

test "an endpoint id that is not a point is refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    @memset(bytes[1..33], 0xff);
    try t.expectError(error.NotANodeId, BlobTicket.decodeBytes(bytes[0..68], alloc));
}

test "a relay url the address layer will not take is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(true);
    try writer.writeStr("ftp://example.com./");
    try writer.writeLen(0);
    try writer.writeVariant(BlobFormat.raw);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));

    try t.expectError(error.BadRelayUrl, BlobTicket.decodeBytes(writer.finish(), alloc));
}

test "a direct address list longer than the body is refused" {
    const alloc = t.allocator;
    var bytes: [72]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, golden_hex) catch unreachable;
    // A peer may name any `u64` and the bytes behind it do not have to exist.
    bytes[34] = 0xff;
    bytes[35] = 0xff;
    bytes[36] = 0xff;
    bytes[37] = 0x7f;
    try t.expectError(error.BadLength, BlobTicket.decodeBytes(bytes[0..68], alloc));
}

test "a direct address sent twice is one address" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(false);
    try writer.writeLen(2);
    const ip: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 };
    try writeSocketAddr(&writer, ip);
    try writeSocketAddr(&writer, ip);
    try writer.writeVariant(BlobFormat.raw);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));

    // postcard reads a `BTreeSet` by inserting, so upstream collapses this
    // too, and the re-encode is the shorter spelling.
    const decoded = try BlobTicket.decodeBytes(writer.finish(), alloc);
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 1), decoded.addr.addrs.len);

    const address = try providerAddr(alloc);
    defer address.deinit(alloc);
    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .raw);
    var canonical: [128]u8 = undefined;
    const ticket_bytes = (try ticket.encode(&canonical)).bytes;
    const decoded_bytes = (try decoded.encode(&canonical)).bytes;
    try t.expectEqualSlices(u8, ticket_bytes, decoded_bytes);
}

test "the hash round trips through hex" {
    const hash = try parseHashHex(golden_hash_hex);
    try t.expectEqualSlices(u8, golden_hash_hex, &hashToHex(hash));
    try t.expectError(error.BadLength, parseHashHex("0b84"));
    const not_hex = golden_hash_hex[0 .. golden_hash_hex.len - 1] ++ "z";
    try t.expectError(error.NotHex, parseHashHex(not_hex));
}
