//! `blob` tickets: a provider, a hash, and the addresses variant 0 can carry.
//!
//! Ported from `n0-computer/iroh-blobs` `src/ticket.rs` and `src/hash.rs`, at
//! commit `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`, fetched 2026-09-30 — the
//! same commit `blobs/range_spec.zig` cites. The shared text form, the RFC
//! 4648 alphabet and the address field writers live in `ticket_codec.zig`,
//! which is the half of upstream's `Ticket` trait that is not a kind; see that
//! file for why.
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
//! A ticket's address list is the only thing it owns, and `new` takes that
//! list over from the caller's `NodeAddr` while variant 0 cannot put a custom
//! payload in it, so `deinit` is `NodeAddr.deinit` and nothing more. That is
//! why this kind returns a bare `BlobTicket` where `EndpointTicket` returns a
//! `Decoded` wrapper: the wrapper exists for the custom payload copy, and
//! there is no such copy here. It is also why `new` transfers rather than
//! borrows — a type that frees its address list cannot also be lent one.

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

/// 32 bytes, the hash a blob is named by.
///
/// iroh-blobs wraps a `blake3::Hash` and calls it `Hash`. The content
/// addressed type that gives those bytes meaning arrives with M11, and until
/// then a ticket carries the bytes and nothing claims to know what they are.
pub const Hash = [32]u8;

/// Bytes in a hash. A value, not an array the caller sizes.
pub const hash_length = 32;
/// Characters in the hex form `hashToHex` writes and `parseHashHex` reads.
pub const hash_hex_length = hash_length * 2;

/// Lowercase hex, the form a ticket's hash is printed and pasted in.
pub fn hashToHex(hash: Hash) [hash_hex_length]u8 {
    return std.fmt.bytesToHex(&hash, .lower);
}

/// Everything a hash's hex form is refused for, checked in that order: the
/// length first, then the digits.
pub const HashParseError = error{
    /// Not `hash_hex_length` characters.
    BadLength,
    /// Not a hex digit.
    NotHex,
};

/// `text` as a hash: exactly `hash_hex_length` hex digits, either case.
///
/// The two failures are separate so a caller can tell a truncated paste
/// from a corrupted one. Nothing else is checked: these 32 bytes are a
/// name, and whether one names a blob is the transfer's question.
///
/// Returns the bytes by value; `text` is borrowed for the call only.
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

    /// Whether the round trip loses nothing, which is the precondition for
    /// treating a ticket's bytes as a stand-in for the address that produced
    /// them.
    ///
    /// A ticket that came off the wire is always empty: nothing was dropped to
    /// decode it.
    pub fn isEmpty(self: Loss) bool {
        return self.custom == 0 and self.relays == 0;
    }
};

/// What one `encode` produced: the bytes, and what they could not carry.
pub const Encoded = struct {
    /// postcard variant 0. Byte for byte what upstream writes.
    ///
    /// These are the caller's `out` and not a copy of it. The slice is the
    /// prefix the writer filled, so `out` must stay alive and unwritten for as
    /// long as the bytes are read, and writing `out` again — a second `encode`
    /// into it included — invalidates the slice and every slice taken from it.
    /// `BlobTicket.encode` says the same where the buffer is named.
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
///
/// A `BlobTicket` owns `addr.addrs`: `new` takes the list over from the
/// caller's `NodeAddr` and `decodeBytes` builds one, and `deinit` releases it
/// either way. One `deinit` per ticket frees it exactly once.
///
/// The custom payloads inside the list are *not* owned by the ticket. They
/// are the same borrows `NodeAddr` carries, so they have to outlive the
/// ticket; see `NodeAddr` and `Decoded` for the other side of that borrow.
pub const BlobTicket = struct {
    /// The kind prefix, and the only spelling `decodeString` accepts.
    pub const kind = "blob";

    /// The provider's address. Its list is this ticket's to release; its
    /// custom payloads, if any, are still the caller's borrow.
    addr: NodeAddr,
    /// One blob at this hash, or a sequence of them.
    format: BlobFormat,
    /// The blob's BLAKE3 hash, or the first hash of a sequence.
    hash: Hash,

    /// A ticket for `hash` on `address`, taking over `address.addrs`.
    ///
    /// The list is moved, not copied, so nothing is allocated here and
    /// `address` is spent: the caller must not free it, keep reading through
    /// it, or hand it to a second owner, and releases it through
    /// `ticket.deinit(alloc)` instead. Custom payloads inside the list stay
    /// borrows and must outlive the ticket.
    pub fn new(address: NodeAddr, hash: Hash, format: BlobFormat) BlobTicket {
        return .{ .addr = address, .hash = hash, .format = format };
    }

    /// Free the address list, which is the only thing a ticket owns.
    ///
    /// Whether the ticket came from `new` or from `decodeBytes`, this is the
    /// one release for that list and it runs once. Nothing else is freed: a
    /// custom payload in the list is a borrow, and variant 0 has nowhere to
    /// put one anyway. `EndpointTicket` needs a wrapper for its payload copy;
    /// this does not, and saying so is why the two differ.
    ///
    /// The ticket and every copy of it are invalid afterward.
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
    ///
    /// The result borrows `out`: `Encoded.bytes` is the prefix the writer
    /// filled, not a copy of it, so `out` must stay alive and unwritten for as
    /// long as those bytes are read, and a later write through `out`
    /// invalidates them. A buffer too short for the ticket is
    /// `error.BufferFull`, and `out` then holds the prefix the writer
    /// committed before it ran out of room — a partial encoding rather than a
    /// ticket, which is why nothing is returned for it and it must not reach
    /// `decodeBytes`.
    pub fn encode(self: BlobTicket, out: []u8) postcard.Error!Encoded {
        var writer = postcard.Writer.init(out);
        try writer.writeVariant(WireVariant.variant0);
        try codec.writeNodeId(&writer, self.addr.node_id);

        const relay = firstRelay(self.addr.addrs);
        try writer.writeOption(relay != null);
        if (relay) |url| try codec.writeRelayUrl(&writer, url);

        try writer.writeLen(directCount(self.addr.addrs));
        for (self.addr.addrs) |one| {
            if (one == .ip) try codec.writeSocketAddr(&writer, one.ip);
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
            postcard.varintMax(u64) + codec.relay_url_text_max +
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
    /// produced. `codec.textLength(kind, …)` sizes `out`.
    ///
    /// The text returned is the prefix of `out` that was filled and not a copy
    /// of it, so `out` must stay alive and unwritten for as long as it is read,
    /// and a later write through `out` invalidates it. An `out` shorter than
    /// that length is `error.BufferFull`, and it writes nothing.
    pub fn encodeString(
        self: BlobTicket,
        encoded: Encoded,
        out: []u8,
    ) codec.TextError![]const u8 {
        _ = self;
        return codec.encodeText(kind, encoded.bytes, out);
    }

    /// postcard bytes to a ticket. The address list comes from `alloc`; see
    /// `deinit`.
    pub fn decodeBytes(alloc: Allocator, bytes: []const u8) codec.DecodeError!BlobTicket {
        var reader = postcard.Reader.init(bytes);
        if (try reader.readU32() != @intFromEnum(WireVariant.variant0)) {
            return error.UnknownTicketVariant;
        }
        const id = try codec.readNodeId(&reader);

        var addrs: std.ArrayList(TransportAddr) = .empty;
        errdefer addrs.deinit(alloc);
        // The relay goes in first, and relay sorts before ip, so appending in
        // wire order already lands in `TransportAddr.order`. A peer is free to
        // send the direct addresses in another order, or the same one twice,
        // and upstream's `BTreeSet` would absorb both; `codec.canonicalizeAddrs`
        // does the same and is why the re-encode of a decoded ticket is
        // postcard's canonical spelling rather than the one that was sent.
        if (try reader.readOption()) {
            try addrs.append(alloc, .{ .relay = try codec.readRelayUrl(&reader) });
        }
        const count = try reader.readLen();
        for (0..count) |_| try addrs.append(alloc, .{ .ip = try codec.readSocketAddr(&reader) });

        const format = try reader.readVariant(BlobFormat);
        const hash = try reader.readArray(hash_length);
        try reader.finish();
        addrs.items = codec.canonicalizeAddrs(addrs.items);

        return .{
            .addr = .{ .node_id = id, .addrs = try addrs.toOwnedSlice(alloc) },
            .format = format,
            .hash = hash,
        };
    }

    /// A ticket's text form to a ticket. The base32 body is decoded through a
    /// fresh allocation, because its length is whatever the text said it was.
    pub fn decodeString(alloc: Allocator, text: []const u8) codec.DecodeError!BlobTicket {
        const symbols = try codec.splitBody(kind, text);
        const raw = try alloc.alloc(u8, codec.byteLength(symbols.len));
        defer alloc.free(raw);
        try codec.decodeBase32(symbols, raw);
        return decodeBytes(alloc, raw);
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

// Half-length buffers rule out NoSpaceLeft. Invalid captured hex therefore
// fails the test that requested it, rather than terminating the whole runner.

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
        _ = try std.fmt.hexToBytes(&nibble, expected_hex[2 * index ..][0..2]);
        try t.expectEqual(nibble[0], got[index]);
    }
}

/// A provider reachable at 127.0.0.1:1234, which is the address upstream's
/// own `make_ticket` uses.
fn providerAddr(alloc: Allocator) !NodeAddr {
    const id = try NodeId.parseHex(golden_id_hex);
    var address = NodeAddr.init(id);
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 };
    return (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
}

test "golden: the blob ticket bytes, iroh-blobs src/ticket.rs" {
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    const alloc = t.allocator;
    const decoded = try BlobTicket.decodeBytes(alloc, bytes[0..68]);
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
    const decoded = try BlobTicket.decodeString(alloc, golden_ticket);
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
    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .hash_seq);
    // `new` took the list over, so the ticket releases it.
    defer ticket.deinit(alloc);

    var body: [256]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expect(encoded.loss.isEmpty());

    var first: [512]u8 = undefined;
    var second: [512]u8 = undefined;
    const once = try ticket.encodeString(encoded, &first);
    const twice = try BlobTicket.decodeString(alloc, once);
    defer twice.deinit(alloc);
    const again = try twice.encodeString(try twice.encode(&body), &second);

    try t.expectEqualStrings(once, again);
    try t.expectEqual(codec.textLength(BlobTicket.kind, encoded.bytes.len), once.len);
}

test "a ticket with no custom transport round trips through variant 0 unchanged" {
    const alloc = t.allocator;
    var address = try NodeAddr.withRelay(
        alloc,
        try NodeId.parseHex(golden_id_hex),
        try RelayUrl.parse("https://relay.example/"),
    );
    const v4: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 41641 };
    const v6: SocketAddr = .{ .ip = .{ .v6 = [_]u8{ 0x20, 0x01 } ** 8 }, .port = 443 };
    address = (try address.insert(alloc, .{ .ip = v4 })) orelse
        return error.TestUnexpectedResult;
    address = (try address.insert(alloc, .{ .ip = v6 })) orelse
        return error.TestUnexpectedResult;

    const hash = try parseHashHex(golden_hash_hex);
    const ticket = BlobTicket.new(address, hash, .hash_seq);
    defer ticket.deinit(alloc);
    // Nothing to report is the precondition for trusting the round trip, so
    // it is checked before the round trip rather than inferred from it.
    try t.expect(ticket.loss().isEmpty());

    var body: [256]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expect(encoded.loss.isEmpty());
    try t.expect(encoded.bytes.len <= ticket.maxEncodedLength());

    var text: [512]u8 = undefined;
    const written = try ticket.encodeString(encoded, &text);

    const decoded = try BlobTicket.decodeString(alloc, written);
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
    const custom = try CustomAddr.parse("2a_abab", &storage);
    address = (try address.insert(alloc, .{ .custom = custom })) orelse
        return error.TestUnexpectedResult;

    const hash = try parseHashHex(golden_hash_hex);
    const ticket = BlobTicket.new(address, hash, .raw);
    defer ticket.deinit(alloc);

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

    const decoded = try BlobTicket.decodeString(alloc, written);
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
    address = (try address.insert(alloc, second)) orelse
        return error.TestUnexpectedResult;
    address = (try address.insert(alloc, third)) orelse
        return error.TestUnexpectedResult;

    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .raw);
    defer ticket.deinit(alloc);
    try t.expectEqual(@as(usize, 2), ticket.loss().relays);
    try t.expectEqual(@as(usize, 0), ticket.loss().custom);

    var body: [512]u8 = undefined;
    const encoded = try ticket.encode(&body);
    try t.expectEqual(@as(usize, 2), encoded.loss.relays);

    const decoded = try BlobTicket.decodeBytes(alloc, encoded.bytes);
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 1), decoded.addr.addrs.len);
    // `relay_urls().next()` is the first in `TransportAddr.order`, which is
    // the lowest URL. The ticket does not get to choose.
    try t.expectEqualStrings("a.example.", decoded.addr.addrs[0].relay.hostSlice());
}

test "a foreign kind prefix is not a blob ticket" {
    const alloc = t.allocator;
    try t.expectError(error.UnknownKind, BlobTicket.decodeString(alloc, ""));
    try t.expectError(error.UnknownKind, BlobTicket.decodeString(alloc, "endpoint"));
    try t.expectError(
        error.UnknownKind,
        BlobTicket.decodeString(alloc, "Blob" ++ golden_ticket["blob".len..]),
    );
    try t.expectError(error.UnknownKind, BlobTicket.decodeString(alloc, " blob"));
    try t.expectError(error.UnknownKind, BlobTicket.decodeString(alloc, "bl"));
}

test "a body that is not whole bytes is refused" {
    try t.expectError(error.BadBase32Length, BlobTicket.decodeString(t.allocator, "bloba"));
    try t.expectError(error.BadBase32Length, BlobTicket.decodeString(t.allocator, "blobaaaaaa"));
}

test "a character outside the alphabet is refused" {
    try t.expectError(error.BadBase32Symbol, BlobTicket.decodeString(t.allocator, "bloba0"));
    try t.expectError(error.BadBase32Symbol, BlobTicket.decodeString(t.allocator, "bloba!"));
}

test "trailing bytes after the body are refused" {
    const alloc = t.allocator;
    // One byte past the vector, so the byte this test adds past the body has
    // somewhere to land.
    var bytes: [golden_hex.len / 2 + 1]u8 = undefined;
    _ = try std.fmt.hexToBytes(bytes[0 .. golden_hex.len / 2], golden_hex);
    bytes[68] = 0x00;
    try t.expectError(error.TrailingBytes, BlobTicket.decodeBytes(alloc, bytes[0..69]));

    var text: [128]u8 = undefined;
    @memcpy(text[0..golden_ticket.len], golden_ticket);
    text[golden_ticket.len] = 'a';
    text[golden_ticket.len + 1] = 'a';
    try t.expectError(
        error.TrailingBytes,
        BlobTicket.decodeString(alloc, text[0 .. golden_ticket.len + 2]),
    );
}

test "a truncated body is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);
    // Every cut of this vector is `UnexpectedEnd` and none of them is
    // `BadLength`, which is a fact about the vector and not a rule: its only
    // length prefix is a zero direct-address count, so no cut can leave a
    // prefix claiming more than the bytes behind it. The case where it does
    // is a test of its own below.
    for ([_]usize{ 0, 1, 8, 32, 33, 34, 35, 36, 40, 67 }) |length| {
        try t.expectError(error.UnexpectedEnd, BlobTicket.decodeBytes(alloc, bytes[0..length]));
    }
}

test "a format this build has no arm for is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);
    // 68 bytes, laid out: variant 0, the id at 1..33, the relay option at 33,
    // the direct count at 34, the format at 35, and the hash at 36..68.
    bytes[35] = 0x07;
    try t.expectError(error.UnknownVariant, BlobTicket.decodeBytes(alloc, bytes[0..68]));
}

/// The socket address's family, with two discriminants this build writes no arm
/// for: the one immediately past the last arm, and one that needs two varint
/// bytes. `postcard.Writer.writeVariant` takes an enum rather than a number,
/// so a byte no declared arm names can only be produced by declaring the arm.
const UnwrittenIpFamily = enum(u32) { v4 = 0, v6 = 1, next = 2, far = 128 };

/// A blob ticket body naming one direct address whose family discriminant is
/// `family`, with the address bytes written only for the two families this
/// build has arms for. Variant 0's direct addresses are bare `SocketAddr`s
/// with no transport tag in front, which is what places `family` there.
fn directAddrBody(family: UnwrittenIpFamily) !struct { body: [128]u8, len: usize } {
    const v4_octets: [4]u8 = .{ 127, 0, 0, 1 };
    const v6_octets: [16]u8 = [_]u8{ 0x20, 0x01 } ** 8;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(false);
    try writer.writeLen(1);
    try writer.writeVariant(family);
    switch (family) {
        .v4 => try writer.writeArray(4, &v4_octets),
        .v6 => try writer.writeArray(16, &v6_octets),
        // Refused at the discriminant, so there is nothing behind it.
        .next, .far => {},
    }
    try writer.writeU16(1234);
    try writer.writeVariant(BlobFormat.raw);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));
    return .{ .body = body, .len = writer.finish().len };
}

test "both ip families decode through variant 0, and neither discriminant past them does" {
    const alloc = t.allocator;
    const v4_octets: [4]u8 = .{ 127, 0, 0, 1 };
    const v6_octets: [16]u8 = [_]u8{ 0x20, 0x01 } ** 8;

    const v4 = try directAddrBody(.v4);
    const from_v4 = try BlobTicket.decodeBytes(alloc, v4.body[0..v4.len]);
    defer from_v4.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_v4.addr.addrs.len);
    try t.expectEqual(@as(u16, 1234), from_v4.addr.addrs[0].ip.port);
    switch (from_v4.addr.addrs[0].ip.ip) {
        .v4 => |octets| try t.expectEqualSlices(u8, &v4_octets, &octets),
        .v6 => return error.TestUnexpectedResult,
    }

    const v6 = try directAddrBody(.v6);
    const from_v6 = try BlobTicket.decodeBytes(alloc, v6.body[0..v6.len]);
    defer from_v6.deinit(alloc);
    try t.expectEqual(@as(usize, 1), from_v6.addr.addrs.len);
    try t.expectEqual(@as(u16, 1234), from_v6.addr.addrs[0].ip.port);
    switch (from_v6.addr.addrs[0].ip.ip) {
        .v6 => |octets| try t.expectEqualSlices(u8, &v6_octets, &octets),
        .v4 => return error.TestUnexpectedResult,
    }

    // The same boundary `endpoint_ticket` pins, reached through the other
    // kind's decoder because both read their socket addresses through the one
    // codec. It is refused by the discriminant rather than by running out of
    // address bytes, which is the distinction a truncation cannot make.
    for ([_]UnwrittenIpFamily{ .next, .far }) |family| {
        const refused = try directAddrBody(family);
        try t.expectError(
            error.UnknownVariant,
            BlobTicket.decodeBytes(alloc, refused.body[0..refused.len]),
        );
    }
}

test "a wire variant this build has no arm for is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);
    bytes[0] = 0x01;
    try t.expectError(error.UnknownTicketVariant, BlobTicket.decodeBytes(alloc, bytes[0..68]));
}

test "an endpoint id that is not a point is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);
    @memset(bytes[1..33], 0xff);
    try t.expectError(error.NotANodeId, BlobTicket.decodeBytes(alloc, bytes[0..68]));
}

test "a relay url the address layer will not take is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(true);
    try writer.writeStr("ftp://example.com./");
    try writer.writeLen(0);
    try writer.writeVariant(BlobFormat.raw);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));

    try t.expectError(error.BadRelayUrl, BlobTicket.decodeBytes(alloc, writer.finish()));
}

test "a direct address list longer than the body is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);
    // A peer may name any `u64` and the bytes behind it do not have to exist.
    bytes[34] = 0xff;
    bytes[35] = 0xff;
    bytes[36] = 0xff;
    bytes[37] = 0x7f;
    try t.expectError(error.BadLength, BlobTicket.decodeBytes(alloc, bytes[0..68]));
}

test "a direct address sent twice is one address" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(false);
    try writer.writeLen(2);
    const ip: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 };
    try codec.writeSocketAddr(&writer, ip);
    try codec.writeSocketAddr(&writer, ip);
    try writer.writeVariant(BlobFormat.raw);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));

    // postcard reads a `BTreeSet` by inserting, so upstream collapses this
    // too, and the re-encode is the shorter spelling.
    const decoded = try BlobTicket.decodeBytes(alloc, writer.finish());
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 1), decoded.addr.addrs.len);

    const address = try providerAddr(alloc);
    const ticket = BlobTicket.new(address, try parseHashHex(golden_hash_hex), .raw);
    defer ticket.deinit(alloc);
    // Two buffers, because one would compare a slice with itself: encoding
    // the decoded ticket into the storage the first encoding borrowed
    // overwrites those bytes, and `expectEqualSlices` would then be reading
    // the second answer twice. Written this way, a `canonicalizeAddrs` that
    // dropped, duplicated or reordered an address fails the comparison
    // instead of passing it.
    var built: [128]u8 = undefined;
    var from_wire: [128]u8 = undefined;
    const ticket_bytes = (try ticket.encode(&built)).bytes;
    const decoded_bytes = (try decoded.encode(&from_wire)).bytes;
    try t.expectEqualSlices(u8, ticket_bytes, decoded_bytes);
}

test "the hash round trips through hex" {
    const hash = try parseHashHex(golden_hash_hex);
    try t.expectEqualSlices(u8, golden_hash_hex, &hashToHex(hash));
    try t.expectError(error.BadLength, parseHashHex("0b84"));
    const not_hex = golden_hash_hex[0 .. golden_hash_hex.len - 1] ++ "z";
    try t.expectError(error.NotHex, parseHashHex(not_hex));
}

/// A provider body carrying one relay and three direct addresses, written in
/// an order canonicalization has to change: the v6 socket first and the
/// higher v4 before the lower one. A decode that appended in wire order would
/// answer with a list this body did not name. Three of them also grow the
/// address list more than once, which is where most of the refusals are.
fn providerBody() !struct { body: [256]u8, len: usize } {
    var body: [256]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant0);
    try codec.writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeOption(true);
    try writer.writeStr("https://relay.example./");
    try writer.writeLen(3);
    const v6: SocketAddr = .{ .ip = .{ .v6 = [_]u8{ 0x20, 0x01 } ** 8 }, .port = 443 };
    const far: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 41641 };
    const near: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 };
    try codec.writeSocketAddr(&writer, v6);
    try codec.writeSocketAddr(&writer, far);
    try codec.writeSocketAddr(&writer, near);
    try writer.writeVariant(BlobFormat.hash_seq);
    try writer.writeArray(hash_length, &try parseHashHex(golden_hash_hex));
    return .{ .body = body, .len = writer.finish().len };
}

/// Whether `pointer` names a byte inside `region`. A decoded ticket's address
/// list is an allocation of its own, so one pointing back into the frame the
/// caller is about to reuse is a borrow `deinit` would then free.
fn insideRegion(region: []const u8, pointer: anytype) bool {
    const at = @intFromPtr(pointer);
    const low = @intFromPtr(region.ptr);
    return at >= low and at < low + region.len;
}

/// The ticket a decode of `providerBody` owes its caller: the captured id and
/// hash, the format, the relay, and the three direct addresses in
/// `SocketAddr.order` rather than in the order the body sent them.
///
/// This is the half of the sweep a balance cannot do. A decode that dropped
/// the relay, kept a socket twice, or appended in wire order still balances
/// its books exactly the same way.
fn expectDecodedProvider(ticket: *const BlobTicket, frame: []const u8) !void {
    try t.expectEqualStrings(golden_id_hex, ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(BlobFormat.hash_seq, ticket.format);
    try t.expectEqualStrings(golden_hash_hex, &hashToHex(ticket.hash));
    try t.expectEqual(@as(usize, 4), ticket.addr.addrs.len);
    try t.expectEqual(@as(usize, 1), ticket.addr.relayCount());

    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(ticket.addr.addrs[0]));
    try t.expectEqualStrings("relay.example.", ticket.addr.addrs[0].relay.hostSlice());
    try t.expectEqual(RelayUrl.default_https_port, ticket.addr.addrs[0].relay.port);
    // v4 before v6, and the two v4s by their own bytes: the list is the
    // canonical one whatever order the peer wrote it in.
    const ports = [_]u16{ 1234, 41641, 443 };
    for (ports, ticket.addr.addrs[1..]) |port, one| {
        try t.expectEqual(TransportAddr.ip, std.meta.activeTag(one));
        try t.expectEqual(port, one.ip.port);
    }
    try t.expect(!insideRegion(frame, ticket.addr.addrs.ptr));
}

/// One run of `decodeBytes` for `t.checkAllAllocationFailures`: the answer is
/// checked and released, so a refusal in the relay slot, in the direct
/// addresses, or in the list they share has to hand all of it back.
fn blobBytesAccounting(alloc: Allocator, bytes: []const u8) !void {
    const decoded = try BlobTicket.decodeBytes(alloc, bytes);
    try expectDecodedProvider(&decoded, bytes);
    decoded.deinit(alloc);
}

/// The same run through the text form, which allocates the base32 body before
/// it decodes anything and so stands one allocation further along.
fn blobTextAccounting(alloc: Allocator, text: []const u8) !void {
    const decoded = try BlobTicket.decodeString(alloc, text);
    try expectDecodedProvider(&decoded, text);
    // Releasing it under the testing allocator is the ownership check the
    // pointer comparison above cannot be: a list pointing into the buffer
    // `decodeString` allocated and released on the way out would be freed
    // twice here, and the allocator says so by name.
    decoded.deinit(alloc);
}

test "every allocation a blob ticket decode makes can fail on its own" {
    const alloc = t.allocator;
    const made = try providerBody();
    const body = made.body[0..made.len];

    try t.checkAllAllocationFailures(alloc, blobBytesAccounting, .{body});

    // And through the text form, which is one allocation further along because
    // the base32 body is decoded through a buffer of its own.
    var text: [512]u8 = undefined;
    const written = try codec.encodeText(BlobTicket.kind, body, &text);
    try t.checkAllAllocationFailures(alloc, blobTextAccounting, .{written});

    // The eventual consumer result, on a plain allocator: the same provider
    // and the same canonical list, however the body ordered it.
    const decoded = try BlobTicket.decodeBytes(alloc, body);
    defer decoded.deinit(alloc);
    try expectDecodedProvider(&decoded, body);
    try t.expect(decoded.loss().isEmpty());

    // And the fixed point the wire order made worth checking: what a decode
    // writes is the canonical spelling, so decoding those bytes answers the
    // same ticket again and re-encoding it changes nothing.
    var canonical_buffer: [256]u8 = undefined;
    const canonical = (try decoded.encode(&canonical_buffer)).bytes;
    const again = try BlobTicket.decodeBytes(alloc, canonical);
    defer again.deinit(alloc);
    try expectDecodedProvider(&again, canonical);
    var third: [256]u8 = undefined;
    try t.expectEqualSlices(u8, canonical, (try again.encode(&third)).bytes);
}
