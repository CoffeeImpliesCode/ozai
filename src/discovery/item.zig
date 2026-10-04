//! What a discovery result is, which service produced it, and how two results
//! compare.
//!
//! Captured from n0-computer/iroh, `iroh/src/address_lookup.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30.
//!
//! Upstream has no `DiscoveryItem` enum any more. `Item` (that file's lines
//! 372–385) is a plain struct of three fields, deriving only `Debug, Clone,
//! Eq, PartialEq`: the `EndpointInfo` a service discovered, a `&'static str`
//! naming the service, and `Option<u64>` microseconds since the unix epoch.
//! All three are here. So is the absence of an ordering: the `last_updated`
//! field carries a `TODO(ramfox)` at line 383 saying it is unused, and
//! nothing in the tree sorts an `Item`. The order below is therefore ozai's,
//! and it is the reason this module exists.
//!
//! Two divergences from upstream. The first is already recorded in
//! `docs/ARCHITECTURE.md`, under "No `DiscoveryItem` enum":
//!
//! * `Provenance` is a closed enum. Upstream types the tag `&'static str` and
//!   lets `MemoryLookup::with_provenance` and every test double invent one, so
//!   a typo is a value that matches nothing. The *set* is upstream's: the
//!   three strings its shipped services pass, at
//!   `iroh/src/address_lookup/dns.rs:130`, `pkarr.rs:546` and `memory.rs:102`.
//!
//! The second has no upstream counterpart at all and wants a bullet of its own
//! in the same list:
//!
//! * The tiebreak is `base/transport_addr.zig`'s value order —
//!   `TransportAddr.order`, the order a `NodeAddr` list is kept in and a
//!   ticket canonicalizes its addresses by — and not a wire format. The wire
//!   formats are another module's business and they change; an order that
//!   moved when a ticket encoding moved would reorder zones for a reason
//!   nobody could see, and one that read a different order than the address
//!   lists would pick a different relay than the list it was handed. Nothing
//!   here is ever sent to a peer.
//!
//! The stream plumbing — the `AddressLookup` trait, the resolvers implementing
//! it, the handle whose drop cancels them — is a later slice. What is here is
//! the part that does not need it: the result, its origin, the order, and the
//! difference between "cannot resolve" and "resolved to nothing".

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const node_addr = @import("../base/node_addr.zig");
const relay_url = @import("../base/relay_url.zig");
const transport_addr = @import("../base/transport_addr.zig");

/// Which lookup service produced an `Item`.
///
/// Upstream's tag is a `&'static str`; the set and the spellings are
/// upstream's, the type is not. That is the divergence under "No
/// `DiscoveryItem` enum" in `docs/ARCHITECTURE.md`: a string tag is a value
/// nothing checks, and a service that misspells its own name produces results
/// no log line can be grouped by.
pub const Provenance = enum {
    /// `DnsAddressLookup`, reading `_iroh.<z32>.<origin>` TXT records.
    /// Upstream passes `"dns"` at `iroh/src/address_lookup/dns.rs:130`.
    dns,
    /// `PkarrResolver`. Upstream passes `"pkarr"` at
    /// `iroh/src/address_lookup/pkarr.rs:546`.
    pkarr,
    /// `MemoryLookup`: what a test or a static configuration hands the
    /// endpoint, never a network query. Upstream's constant is
    /// `"memory_lookup"` at `iroh/src/address_lookup/memory.rs:102`.
    memory_lookup,

    /// Every arm, for iteration. A test holds this list against the enum so
    /// the two cannot drift apart unnoticed.
    pub const all = [_]Provenance{ .dns, .pkarr, .memory_lookup };

    /// Precedence, used only as the last tiebreak of `Item.order`.
    ///
    /// Declaration order is the order. This switch has no `else`, so adding a
    /// provenance without ranking it here is a compile error rather than a tag
    /// that quietly sorts last and loses every merge it enters.
    pub fn rank(self: Provenance) u8 {
        return switch (self) {
            .dns => 0,
            .pkarr => 1,
            .memory_lookup => 2,
        };
    }

    /// Upstream's own spelling, for log lines and metrics labels, where the
    /// string is the interface an operator reads.
    pub fn name(self: Provenance) []const u8 {
        return switch (self) {
            .dns => "dns",
            .pkarr => "pkarr",
            .memory_lookup => "memory_lookup",
        };
    }
};

/// Tag byte per `TransportAddr` arm, in the union's declaration order, so the
/// first byte of a record names its variant in the rank order
/// `TransportAddr.order` gives the three. It is a name and not a sort
/// position: nothing here compares records against one another.
const tag_relay = 0;
const tag_ip = 1;
const tag_custom = 2;

/// Longest record `encodeAddr` writes: the relay arm, being tag, scheme,
/// port, host length and a maximal host. A new `TransportAddr` arm that
/// encodes longer has to raise this; the switch in `encodeAddr` is exhaustive,
/// so such an arm cannot be added without the compiler pointing at it.
pub const max_encoded_addr_length = 1 + 1 + 2 + 1 + relay_url.RelayUrl.max_host_length;

/// Why an item cannot be written in its canonical encoding: the caller's buffer
/// was too small for it, or one of its addresses is one no record can hold.
///
/// Only `canonicalBytes` returns this. `Item.order` compares address values
/// and never goes through the encoder, which is why an address no record can
/// hold still has a total order and why this error set is not in `order`'s.
pub const EncodeError = error{
    /// `out` cannot hold the whole encoding. Size it with `maxEncodedLength`.
    BufferTooSmall,
    /// A `CustomAddr` in the address carries more data than a `CustomAddr`
    /// holds inline. `CustomAddr.parse` cannot produce one; an `Item` built by
    /// hand can, and a resolver never does.
    CustomAddrTooLong,
};

/// One discovery result: an address, the service that reported it, and when.
///
/// An `Item` is a shallow value over somebody else's address list: it owns the
/// `NodeAddr` struct, not the `addrs` slice behind it, and a copy of an `Item`
/// shares that slice with the original rather than duplicating it. So an item
/// read out of a `resolve.Stream` is valid exactly as long as that stream is,
/// and an item to keep past it is an item to copy the addresses into. Who
/// allocated the list, and who releases it, is `base/node_addr.zig`'s rule.
pub const Item = struct {
    /// Upstream's `endpoint_info: EndpointInfo`. ozai's `NodeAddr` carries the
    /// node id beside the paths, so the whole upstream struct is one field
    /// here, and `addrs` is sorted and duplicate-free as invariant 2 requires.
    endpoint: node_addr.NodeAddr,
    /// The service that produced this item. Not a tiebreak on its own: two
    /// services reporting the same address are agreeing, not conflicting.
    provenance: Provenance,
    /// Microseconds since the unix epoch, counted the way upstream counts
    /// them, or null when the service does not say. A resolver stamps this
    /// from the network it queried; nothing in this module reads a clock.
    last_updated: ?u64,

    /// An item over `endpoint`, storing its address list rather than taking it.
    /// The caller still owns that list and still releases it, and the returned
    /// item is valid for as long as the list is.
    pub fn init(
        endpoint: node_addr.NodeAddr,
        provenance: Provenance,
        last_updated: ?u64,
    ) Item {
        return .{ .endpoint = endpoint, .provenance = provenance, .last_updated = last_updated };
    }

    /// The total order of `docs/ARCHITECTURE.md` invariant 12: timestamp
    /// first, the discovered address as the tiebreak, the source last.
    ///
    /// Three components, compared in that order, each one total and each one
    /// injective on its own field, so `.eq` comes back for two items only when
    /// every field matches. That is the property a zone flap is made of: a
    /// comparator that calls two different results equal hands two sources
    /// the same answer, and the zone then keeps whichever arrived first.
    ///
    /// * `last_updated`, null before any stamp. A service that does not vouch
    ///   for freshness must not outrank one that does, or a stream that
    ///   stamps nothing wins every merge and pins the zone to the stalest
    ///   view anyone holds. Null is therefore infinitely old: not infinitely
    ///   new, and not unordered.
    /// * The address: the node id's own bytes, then its paths one at a time in
    ///   `TransportAddr.order`, and only then how many there are. It
    ///   determines the address, so it never ties. Reading the values is what
    ///   keeps a merge and the `NodeAddr` lists a caller sorts from
    ///   disagreeing about which of two relays is the greater one.
    /// * `Provenance.rank`, for the pair that differs in nothing else. Same
    ///   address and same stamp is the same fact about the world; the tag only
    ///   says which of them said it, and a fixed order keeps that choice out
    ///   of the zone's hands.
    pub fn order(self: Item, other: Item) std.math.Order {
        const by_time = orderTimestamp(self.last_updated, other.last_updated);
        if (by_time != .eq) return by_time;

        const by_id = self.endpoint.node_id.order(other.endpoint.node_id);
        if (by_id != .eq) return by_id;

        // Address by address, and only then by how many addresses there are. A
        // stream that stops is smaller than one that continues, and the two
        // are not the same question: a two-address list whose first address
        // sorts low still loses to a one-address list whose first address
        // sorts high, so counting first would answer a different one.
        const shared = @min(self.endpoint.addrs.len, other.endpoint.addrs.len);
        for (self.endpoint.addrs[0..shared], other.endpoint.addrs[0..shared]) |left, right| {
            const by_value = left.order(right);
            if (by_value != .eq) return by_value;
        }
        if (self.endpoint.addrs.len != other.endpoint.addrs.len) {
            return std.math.order(self.endpoint.addrs.len, other.endpoint.addrs.len);
        }
        return std.math.order(self.provenance.rank(), other.provenance.rank());
    }

    /// Upstream's derived `PartialEq`: equal when every field is equal.
    ///
    /// It is written out rather than written as `==` because Zig 0.16 refuses
    /// `==` on any type containing a slice, and an `Item` is one. Upstream
    /// derives the same thing over a `Vec`, where Rust compares contents;
    /// this compares contents too, through `TransportAddr.order`, so two
    /// addresses built in different buffers are the same item here as they
    /// are there.
    pub fn eql(self: Item, other: Item) bool {
        if (self.provenance != other.provenance) return false;
        if (self.last_updated != other.last_updated) return false;
        const self_id = self.endpoint.node_id.toBytes();
        const other_id = other.endpoint.node_id.toBytes();
        if (!std.mem.eql(u8, &self_id, &other_id)) return false;
        if (self.endpoint.addrs.len != other.endpoint.addrs.len) return false;
        for (self.endpoint.addrs, other.endpoint.addrs) |left, right| {
            if (left.order(right) != .eq) return false;
        }
        return true;
    }

    /// The canonical encoding of the discovered address, written into caller
    /// storage: the node id, then one self-delimiting record per address.
    ///
    /// **This is not the sort key, and its byte order is not
    /// `TransportAddr.order`'s.** A relay and a custom record write their
    /// length before their bytes, so `https://aa.example./` outranks
    /// `https://b.example./` as records while the value order ranks it below,
    /// and the same goes for two custom payloads. What the encoding owes a
    /// caller is the other half of that: two items share bytes exactly when
    /// they name the same endpoint, whatever their stamp or their provenance
    /// say. Use it as a map key or a log key, and let `order` do the sorting.
    ///
    /// The result borrows `out`, and how long the borrow lives is the
    /// caller's decision. This is `CustomAddr.parse`'s discipline, invariant
    /// 6: a function that fills a local and hands back a slice of it returns
    /// a pointer to a frame that is gone by the time the caller reads it.
    pub fn canonicalBytes(self: Item, out: []u8) EncodeError![]const u8 {
        const id = self.endpoint.node_id.toBytes();
        if (out.len < id.len) return error.BufferTooSmall;
        @memcpy(out[0..id.len], &id);
        var at = id.len;
        for (self.endpoint.addrs) |value| {
            var record: [max_encoded_addr_length]u8 = undefined;
            const bytes = try encodeAddr(value, &record);
            if (out.len - at < bytes.len) return error.BufferTooSmall;
            @memcpy(out[at..][0..bytes.len], bytes);
            at += bytes.len;
        }
        return out[0..at];
    }

    /// Buffer size `canonicalBytes` needs for an address list of this many
    /// addresses. The encoding has no fixed length, because the address list
    /// has none, so the caller sizes the buffer and owns it.
    pub fn maxEncodedLength(addrs: usize) usize {
        return key.NodeId.byte_length + addrs * max_encoded_addr_length;
    }
};

/// Null is infinitely old. See `Item.order`.
fn orderTimestamp(a: ?u64, b: ?u64) std.math.Order {
    if (a == null) return if (b == null) .eq else .lt;
    if (b == null) return .gt;
    return std.math.order(a.?, b.?);
}

/// One address, canonically encoded and self-delimiting, so the records of
/// two different addresses can be walked in step without either list's shape
/// being known in advance. Nothing compares them; see `canonicalBytes`.
fn encodeAddr(
    value: transport_addr.TransportAddr,
    out: *[max_encoded_addr_length]u8,
) EncodeError![]const u8 {
    return switch (value) {
        .relay => |url| record: {
            out[0] = tag_relay;
            out[1] = @intFromEnum(url.scheme);
            std.mem.writeInt(u16, out[2..4], url.port, .big);
            const host = url.hostSlice();
            // `hostSlice` is `host[0..host_length]`, so the slice is that `u8`
            // field widened: the record takes the field, and needs no cast.
            out[4] = url.host_length;
            @memcpy(out[5..][0..host.len], host);
            break :record out[0 .. 5 + host.len];
        },
        .ip => |socket| record: {
            out[0] = tag_ip;
            out[1] = switch (socket.ip) {
                .v4 => 0,
                .v6 => 1,
            };
            // One field for both families, so a v4 record and a v6 record are
            // the same shape. The v4 case zero-fills, which loses nothing: a
            // v4 address is four bytes and the other twelve are the padding.
            @memset(out[2..18], 0);
            switch (socket.ip) {
                .v4 => |bytes| @memcpy(out[2..6], &bytes),
                .v6 => |bytes| @memcpy(out[2..18], &bytes),
            }
            std.mem.writeInt(u16, out[18..20], socket.port, .big);
            break :record out[0..20];
        },
        // Big-endian id, unlike the little-endian `CustomAddr.writeBinary`
        // writes for the wire. This record is a local key and is never sent,
        // so the two spellings are free to differ — and they do, which is how
        // a reader who confuses one for the other finds out.
        .custom => |custom| record: {
            // Narrow once, where the bound is proved: the cast admits only a
            // length the record's length byte holds, and the comparison is
            // this arm's own ceiling. One error answers both, because a
            // payload the record cannot spell is one it cannot hold either.
            const data_length = std.math.cast(u8, custom.data.len) orelse
                return error.CustomAddrTooLong;
            if (data_length > addr.max_inline_length) return error.CustomAddrTooLong;
            out[0] = tag_custom;
            std.mem.writeInt(u64, out[1..9], custom.id, .big);
            out[9] = data_length;
            @memcpy(out[10..][0..data_length], custom.data);
            break :record out[0 .. 10 + @as(usize, data_length)];
        },
    };
}

/// The best item of `items`, or null when there is none. The one place a merge
/// asks which of two results wins, so nothing else needs an opinion of its own.
///
/// Returns a copy of that item, not a reference to it, and the copy is as
/// shallow as `Item` is: it borrows the winner's address list, so reading it
/// after the list is released reads freed memory.
pub fn winner(items: []const Item) ?Item {
    var best: ?Item = null;
    for (items) |item| {
        const held = best orelse {
            best = item;
            continue;
        };
        best = if (item.order(held) == .gt) item else held;
    }
    return best;
}

/// Every distinct item of `items`, best first, in storage this call allocates
/// from `alloc` and the caller releases with `alloc.free`.
///
/// Not a second precedence rule: this is the input sorted and deduplicated
/// under `Item.order`, so it is the same answer whatever order the sources
/// answered in. Two items that compare `.eq` are equal in every field, which
/// is what makes dropping one of them drop nothing.
///
/// Only the array is new. Every `Item` in it is a shallow copy of an input, so
/// the merged list owns no address and releases none: `alloc.free` hands back
/// the array alone, and the merged list is dead as soon as the addresses behind
/// its items are — which for items out of a resolve is when that stream is
/// closed. A caller that wants the merge to outlive them copies each address
/// list out first.
///
/// `error.OutOfMemory` allocates nothing that survives: the sorted copy is
/// released before the error leaves, and the output array was never built.
pub fn merge(alloc: std.mem.Allocator, items: []const Item) std.mem.Allocator.Error![]Item {
    const sorted = try alloc.dupe(Item, items);
    defer alloc.free(sorted);
    std.mem.sort(Item, sorted, {}, bestFirst);

    var distinct: usize = 0;
    for (sorted, 0..) |item, at| {
        if (at == 0 or !sorted[at - 1].eql(item)) distinct += 1;
    }
    const merged = try alloc.alloc(Item, distinct);
    var at: usize = 0;
    for (sorted) |item| {
        if (at == 0 or !merged[at - 1].eql(item)) {
            merged[at] = item;
            at += 1;
        }
    }
    return merged;
}

/// `std.mem.sort` takes a free function, not a method, and a merged list is
/// read from the front, so the best item has to sort first. Descending is not
/// a second opinion about precedence: it is the same total order, pointed the
/// way the caller reads it.
fn bestFirst(_: void, a: Item, b: Item) bool {
    return a.order(b) == .gt;
}

/// `-order`, so antisymmetry is stated once and nowhere else re-derives it.
fn negate(order: std.math.Order) std.math.Order {
    return switch (order) {
        .lt => .gt,
        .eq => .eq,
        .gt => .lt,
    };
}

/// What one resolve attempt came to.
///
/// The arms are different facts about the world and must not be collapsed.
/// `cannot_resolve` is "this service will not answer for this node id at all":
/// no work started, nothing to cancel, no error either. `resolved` is "the
/// service was asked and finished", and its items may be empty, because a
/// node that has published nothing is a fact about the network rather than a
/// failure to go looking.
///
/// The later stream carries the same distinction in the same shape. `resolve`
/// hands back an optional owning handle: null for `cannot_resolve`, otherwise
/// a stream of items that ends by yielding this value. A stream that ends with
/// an empty `resolved` resolved to nothing; a null stream never resolved at
/// all. Dropping either cancels the service's work, which is invariant 13 and
/// the reason the handle owns its stream instead of handing out an iterator.
pub const Resolution = union(enum) {
    cannot_resolve,
    /// The items the attempt produced, borrowed from whoever produced them.
    resolved: []const Item,

    /// How many items came back, or null when nothing was ever asked. There
    /// is deliberately no `items` accessor here: handing back an empty slice
    /// for `cannot_resolve` is exactly the conflation this type exists to
    /// stop, and one accessor is all it takes to bring it back.
    pub fn itemCount(self: Resolution) ?usize {
        return switch (self) {
            .cannot_resolve => null,
            .resolved => |items| items.len,
        };
    }

    /// True only for a service that answered and had nothing to say. A
    /// service that would not answer at all is not an empty result.
    pub fn isEmptyResult(self: Resolution) bool {
        return switch (self) {
            .cannot_resolve => false,
            .resolved => |items| items.len == 0,
        };
    }
};

const t = std.testing;

/// Node ids from fixed seeds. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so the corpus draws from a pool of
/// three rather than from noise. The pool is also what lets two generated
/// items be equal in every field, which the order properties need.
fn corpusIds() key.KeyError![3]key.NodeId {
    var ids: [3]key.NodeId = undefined;
    for (&ids, 1..) |*id, seed| {
        var bytes: [key.SecretKey.seed_length]u8 = undefined;
        @memset(&bytes, @intCast(seed));
        id.* = (try key.SecretKey.fromSeed(bytes)).nodeId();
    }
    return ids;
}

const pool_length = 15;

/// A small pool of addresses, so a generated item can differ from another in
/// one field and in no other.
fn pool() relay_url.RelayUrlParseError![pool_length]transport_addr.TransportAddr {
    return .{
        .{ .relay = try relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./") },
        .{ .relay = try relay_url.RelayUrl.parse("https://use1-2.relay.iroh.network./") },
        .{ .relay = try relay_url.RelayUrl.parse("http://relay.example./") },
        .{ .ip = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 } },
        .{
            .ip = .{
                .ip = .{ .v6 = .{
                    0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 1,
                    0,    0,    0,    0,    0,    0,    0, 1,
                } },
                .port = 12345,
            },
        },
        // Two custom addresses whose data is a prefix of the other's, and two
        // ids a little-endian field would order the other way round.
        .{ .custom = .{ .id = 1, .data = &.{} } },
        .{ .custom = .{ .id = 1, .data = &.{0xab} } },
        .{ .custom = .{ .id = 256, .data = &.{ 0xab, 0xcd } } },
        .{ .custom = .{ .id = 1 << 40, .data = &.{} } },
        // The same relay host over the other scheme and on another port.
        .{ .relay = try relay_url.RelayUrl.parse("http://use1-1.relay.iroh.network./") },
        .{ .relay = try relay_url.RelayUrl.parse("https://relay.example.:8443/") },
        // Two pairs whose length order and lexical order pull in opposite
        // directions: in each the longer value is the lexically lower one, so
        // anything that reads a length prefix before the bytes ranks the pair
        // the other way round from `TransportAddr.order`. Nothing above can
        // tell the two orders apart.
        .{ .relay = try relay_url.RelayUrl.parse("https://aa.example./") },
        .{ .relay = try relay_url.RelayUrl.parse("https://b.example./") },
        .{ .custom = .{ .id = 5, .data = &.{ 0x61, 0x61 } } },
        .{ .custom = .{ .id = 5, .data = &.{0x62} } },
    };
}

/// A seeded set of items, at least two of which are equal in every field, and
/// owned by the caller's allocator. The seed is fixed, so a failure here is
/// the same failure tomorrow.
fn corpus(alloc: std.mem.Allocator, count: usize) ![]Item {
    std.debug.assert(count >= 2);
    var prng = std.Random.DefaultPrng.init(0x6974_656d);
    const random = prng.random();
    const ids = try corpusIds();
    const addresses = try pool();
    const items = try alloc.alloc(Item, count);
    for (items[0 .. count - 2]) |*item| {
        const id = ids[random.intRangeLessThan(usize, 0, ids.len)];
        var endpoint = node_addr.NodeAddr.init(id);
        const address_count = random.intRangeLessThan(usize, 0, 4);
        for (0..address_count) |_| {
            const pick = random.intRangeLessThan(usize, 0, addresses.len);
            // A repeated pick is a duplicate, and `insert` reports a
            // duplicate by returning null. The address list is
            // duplicate-free; the draw is not.
            if (try endpoint.insert(alloc, addresses[pick])) |next| endpoint = next;
        }
        const kinds = Provenance.all.len;
        const provenance = Provenance.all[random.intRangeLessThan(usize, 0, kinds)];
        const stamp: ?u64 = if (random.boolean()) null else random.intRangeLessThan(u64, 0, 3);
        item.* = .init(endpoint, provenance, stamp);
    }
    // A guaranteed equal pair. Deduplication and the `.eq` branch of the
    // order are only exercised by a set that really does contain two items
    // equal in every field, and a draw from a pool is not evidence of that.
    items[count - 2] = try single(alloc, ids[0], addresses[0], .pkarr, 1);
    items[count - 1] = try single(alloc, ids[0], addresses[0], .pkarr, 1);
    return items;
}

fn freeItems(alloc: std.mem.Allocator, items: []Item) void {
    for (items) |item| item.endpoint.deinit(alloc);
    alloc.free(items);
}

/// One address, one service, one stamp.
fn single(
    alloc: std.mem.Allocator,
    id: key.NodeId,
    transport: transport_addr.TransportAddr,
    provenance: Provenance,
    last_updated: ?u64,
) !Item {
    var endpoint = node_addr.NodeAddr.init(id);
    endpoint = (try endpoint.insert(alloc, transport)) orelse
        return error.TestUnexpectedResult;
    return .init(endpoint, provenance, last_updated);
}

/// The canonical encoding with its length, because two buffers of the same
/// capacity are not two encodings to compare: only the written bytes are.
const Encoded = struct {
    bytes: [Item.maxEncodedLength(4)]u8,
    length: usize,

    fn slice(self: *const Encoded) []const u8 {
        return self.bytes[0..self.length];
    }

    fn of(item: Item) !Encoded {
        var encoded: Encoded = .{ .bytes = undefined, .length = 0 };
        encoded.length = (try item.canonicalBytes(&encoded.bytes)).len;
        return encoded;
    }
};

/// The same node and the same paths — what `canonicalBytes` is a function of,
/// and what `Item.order` falls through to once the stamp has had its say.
fn sameEndpoint(left: Item, right: Item) bool {
    if (left.endpoint.node_id.order(right.endpoint.node_id) != .eq) return false;
    if (left.endpoint.addrs.len != right.endpoint.addrs.len) return false;
    for (left.endpoint.addrs, right.endpoint.addrs) |one, other| {
        if (one.order(other) != .eq) return false;
    }
    return true;
}

/// Longer than `addr.max_inline_length`, which `CustomAddr.parse` refuses to
/// produce. A caller that built one anyway is owed an answer, and a total one:
/// a comparator that could not answer would be a comparator a zone could
/// stall on.
const oversized_data: [addr.max_inline_length + 1]u8 = @splat(0x5a);

test "the provenance set is upstream's three services" {
    try t.expectEqual(@as(usize, 3), Provenance.all.len);
    // `all` is what a caller iterates. An arm missing from it would be
    // rankable and unnameable, so the list is held to the enum here.
    try t.expectEqual(Provenance.all.len, @typeInfo(Provenance).@"enum".fields.len);
    inline for (Provenance.all, 0..) |provenance, rank| {
        try t.expectEqual(@as(u8, @intCast(rank)), provenance.rank());
    }
    // The spellings, which are the upstream facts: `address_lookup/dns.rs:130`,
    // `pkarr.rs:546`, `memory.rs:102`.
    try t.expectEqualStrings("dns", Provenance.dns.name());
    try t.expectEqualStrings("pkarr", Provenance.pkarr.name());
    try t.expectEqualStrings("memory_lookup", Provenance.memory_lookup.name());
}

test "a missing timestamp loses to a stamped one" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const id = (try corpusIds())[0];

    const unstamped = try single(alloc, id, addresses[0], .pkarr, null);
    const oldest = try single(alloc, id, addresses[0], .pkarr, 0);
    const newest = try single(alloc, id, addresses[0], .pkarr, std.math.maxInt(u64));
    try t.expectEqual(std.math.Order.lt, unstamped.order(oldest));
    try t.expectEqual(std.math.Order.gt, newest.order(unstamped));
    try t.expectEqual(std.math.Order.eq, unstamped.order(unstamped));
}

test "equal timestamps fall through to the address" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const id = (try corpusIds())[0];

    // Same node, same service, same stamp, and one address differing only in
    // its host: the tiebreak has to be the address, or the zone has nothing to
    // decide on. These two hosts are the same length, so the pair cannot tell
    // the value order from a length-prefixed one; the next test is the pair
    // that can.
    const first = try single(alloc, id, addresses[0], .pkarr, 17);
    const second = try single(alloc, id, addresses[1], .pkarr, 17);
    try t.expectEqual(std.math.Order.lt, first.order(second));

    // Two addresses are not automatically the larger item. Addresses are
    // compared one at a time: `with_two` starts with the lower host, so it
    // loses to a one-address item that starts with the higher one, and a
    // comparator that counted first would have got this exactly backwards.
    var grown = node_addr.NodeAddr.init(id);
    if (try grown.insert(alloc, addresses[0])) |next| grown = next;
    if (try grown.insert(alloc, addresses[1])) |next| grown = next;
    const with_two = Item.init(grown, .pkarr, 17);
    try t.expectEqual(std.math.Order.lt, with_two.order(second));
    // With the first address equal, the extra one is what decides.
    try t.expectEqual(std.math.Order.gt, with_two.order(first));
}

test "the tiebreak is the address value order, not the encoded record" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const id = (try corpusIds())[0];

    // The last four pool entries are two pairs whose length order and
    // lexical order disagree, one of relays and one of custom addresses: in
    // each pair the longer value is the lexically lower one. A record writes
    // the length before the bytes, so a comparator that reads records ranks
    // each pair the other way round from `TransportAddr.order` — the order
    // `NodeAddr.insert` sorts a list with and a ticket writes its addresses
    // in. A merge that picked the other one would hand a caller a relay that
    // every other sorted list in ozai ranks below its rival.
    inline for (.{ 11, 13 }) |index| {
        const lower = addresses[index];
        const higher = addresses[index + 1];
        try t.expectEqual(std.math.Order.lt, lower.order(higher));

        const first = try single(alloc, id, lower, .pkarr, 5);
        const second = try single(alloc, id, higher, .pkarr, 5);
        try t.expectEqual(std.math.Order.lt, first.order(second));
        try t.expectEqual(std.math.Order.gt, second.order(first));

        // Both ways round: the two entry points a caller reaches for are
        // handed the answers in whatever order its services replied, and a
        // winner that depended on that would be a flap waiting for a retry.
        try t.expect(second.eql(winner(&.{ first, second }).?));
        try t.expect(second.eql(winner(&.{ second, first }).?));

        const merged = try merge(alloc, &.{ first, second });
        defer alloc.free(merged);
        try t.expectEqual(@as(usize, 2), merged.len);
        try t.expect(merged[0].eql(second));
        try t.expectEqual(std.math.Order.gt, merged[0].order(merged[1]));

        // The list a caller sorts with `insert` agrees, because it is the same
        // order: the address the merge picked is the one that lands last.
        var both = node_addr.NodeAddr.init(id);
        if (try both.insert(alloc, lower)) |next| both = next;
        if (try both.insert(alloc, higher)) |next| both = next;
        try t.expectEqual(@as(usize, 2), both.addrs.len);
        try t.expectEqual(std.math.Order.lt, both.addrs[0].order(both.addrs[1]));
        try t.expectEqual(std.math.Order.eq, both.addrs[1].order(higher));
    }
}

test "the order is antisymmetric, transitive and total" {
    const items = try corpus(t.allocator, 24);
    defer freeItems(t.allocator, items);

    var keys: [24]Encoded = undefined;
    for (items, 0..) |item, at| keys[at] = try Encoded.of(item);
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        try t.expectEqual(std.math.Order.eq, items[i].order(items[i]));
        var j: usize = 0;
        while (j < items.len) : (j += 1) {
            const forward = items[i].order(items[j]);
            // Antisymmetry, which also gives trichotomy: one of the three
            // orders or the comparison is not an order at all.
            try t.expectEqual(negate(items[j].order(items[i])), forward);
            // The canonical encoding carries the node id and the address list
            // and nothing else, so two items share bytes exactly when they
            // name the same endpoint — whatever their stamp or their
            // provenance say. It is a key and not the sort key: the pool
            // carries the pairs whose length order and lexical order
            // disagree, and for those the bytes rank the two the other way
            // round from `Item.order`.
            try t.expectEqual(
                sameEndpoint(items[i], items[j]),
                std.mem.eql(u8, keys[i].slice(), keys[j].slice()),
            );
            if (forward == .eq) {
                // The whole point. Equal means equal in every field, so two
                // sources that agree on an address are not a tie to break and
                // cannot become a flap.
                try t.expect(items[i].eql(items[j]));
            } else {
                try t.expect(!items[i].eql(items[j]));
            }
            // Transitivity, over every triple. 24 items make this 13 824
            // comparisons, which costs nothing and is the only way the
            // property is checked at all rather than on three hand-picked
            // items.
            var k: usize = 0;
            while (k < items.len) : (k += 1) {
                if (forward == .lt and items[j].order(items[k]) == .lt) {
                    try t.expectEqual(std.math.Order.lt, items[i].order(items[k]));
                }
            }
        }
    }
}

test "two items differing only in provenance order deterministically" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const id = (try corpusIds())[0];
    const dns = try single(alloc, id, addresses[3], .dns, 42);
    const pkarr = try single(alloc, id, addresses[3], .pkarr, 42);
    const memory = try single(alloc, id, addresses[3], .memory_lookup, 42);

    try t.expectEqual(std.math.Order.lt, dns.order(pkarr));
    try t.expectEqual(std.math.Order.lt, pkarr.order(memory));
    try t.expectEqual(std.math.Order.lt, dns.order(memory));
    // Not a tie: same address, same stamp, different source is a different
    // item, and every permutation of the three has to pick the same one.
    try t.expect(!dns.eql(pkarr));
    try t.expect(!pkarr.eql(memory));
    // Every pair, in both directions, and through a merge, so the choice is
    // the same one whichever of the two sources a caller happens to list
    // first.
    inline for (Provenance.all) |left| {
        inline for (Provenance.all) |right| {
            const first = try single(alloc, id, addresses[3], left, 42);
            const second = try single(alloc, id, addresses[3], right, 42);
            const better = @max(left.rank(), right.rank());
            try t.expectEqual(better, winner(&.{ first, second }).?.provenance.rank());
            try t.expectEqual(better, winner(&.{ second, first }).?.provenance.rank());
        }
    }
}

test "merge keeps the winner and does not care what order the sources answered in" {
    const items = try corpus(t.allocator, 24);
    defer freeItems(t.allocator, items);

    const expected = try merge(t.allocator, items);
    defer t.allocator.free(expected);
    try t.expect(expected.len > 0);
    // Best first, and the best is the one `winner` names.
    try t.expect(expected[0].eql(winner(items).?));
    var at: usize = 1;
    while (at < expected.len) : (at += 1) {
        try t.expectEqual(std.math.Order.gt, expected[at - 1].order(expected[at]));
    }
    // The corpus holds a guaranteed equal pair, so the deduplication below is
    // doing something the permutation check can then be said to preserve.
    try t.expect(expected.len < items.len);

    var prng = std.Random.DefaultPrng.init(0x7065_726d);
    const random = prng.random();
    var round: usize = 0;
    while (round < 16) : (round += 1) {
        const shuffled = try t.allocator.dupe(Item, items);
        defer t.allocator.free(shuffled);
        var pick = shuffled.len;
        while (pick > 1) {
            pick -= 1;
            const swap = random.intRangeLessThan(usize, 0, pick + 1);
            std.mem.swap(Item, &shuffled[pick], &shuffled[swap]);
        }
        const again = try merge(t.allocator, shuffled);
        defer t.allocator.free(again);
        try t.expectEqual(expected.len, again.len);
        for (expected, again) |left, right| try t.expect(left.eql(right));
    }
}

test "an empty result set has an answer, and the answer is none" {
    const merged = try merge(t.allocator, &.{});
    defer t.allocator.free(merged);
    try t.expectEqual(@as(usize, 0), merged.len);
    try t.expect(winner(&.{}) == null);
    const empty: Resolution = .{ .resolved = &.{} };
    try t.expectEqual(@as(?usize, 0), empty.itemCount());
}

test "cannot resolve is not resolved to nothing" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const cannot: Resolution = .cannot_resolve;
    const nothing: Resolution = .{ .resolved = &.{} };

    // Both are "no items" to a caller that only counts, and the type is the
    // only thing telling them apart. That is the entire reason it exists.
    try t.expectEqual(@as(?usize, null), cannot.itemCount());
    try t.expectEqual(@as(?usize, 0), nothing.itemCount());
    try t.expect(!cannot.isEmptyResult());
    try t.expect(nothing.isEmptyResult());
    try t.expect(std.meta.activeTag(cannot) != std.meta.activeTag(nothing));

    // A service that answered with something is neither of those.
    const item = try single(alloc, (try corpusIds())[0], addresses[0], .dns, 1);
    const answered: Resolution = .{ .resolved = try alloc.dupe(Item, &.{item}) };
    try t.expectEqual(@as(?usize, 1), answered.itemCount());
    try t.expect(!answered.isEmptyResult());
}

test "an address the encoder cannot hold still has a total order" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const id = (try corpusIds())[0];
    const item = try single(
        alloc,
        id,
        .{ .custom = .{ .id = 7, .data = &oversized_data } },
        .pkarr,
        3,
    );
    // The order compares values and never asks whether a record can spell
    // them, so it is total for this address for the same reason it is for
    // every other one. Only `canonicalBytes` refuses it, and it refuses it
    // rather than writing a short record.
    var buffer: [Item.maxEncodedLength(1)]u8 = undefined;
    try t.expectError(error.CustomAddrTooLong, item.canonicalBytes(&buffer));

    const other = try single(alloc, id, addresses[5], .pkarr, 3);
    try t.expectEqual(negate(other.order(item)), item.order(other));
    try t.expectEqual(std.math.Order.eq, item.order(item));
}

test "a buffer too small is refused before the record it could not hold" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try pool();
    const item = try single(alloc, (try corpusIds())[0], addresses[0], .dns, 3);
    const host = addresses[0].relay.hostSlice();

    // What a record spells for this address: the node id, then tag, scheme,
    // port, host length and the host. `maxEncodedLength` is the bound and not
    // the answer, so the length is stated rather than compared against it.
    var buffer: [Item.maxEncodedLength(1)]u8 = undefined;
    try t.expectEqual(key.NodeId.byte_length + 5 + host.len, (try item.canonicalBytes(&buffer)).len);

    // Too small for the node id: refused before the first byte is written, so
    // the buffer is not touched at all.
    try t.expectError(
        error.BufferTooSmall,
        item.canonicalBytes(buffer[0 .. key.NodeId.byte_length - 1]),
    );

    // Big enough for the id and not for the record behind it: refused part
    // way through, after the id has gone in, which is what makes this a
    // second check rather than the first one again. A buffer refused half
    // way holds the prefix the encoder committed to, because that is the
    // whole of what a caller can reuse.
    var id_only: [key.NodeId.byte_length]u8 = undefined;
    try t.expectError(error.BufferTooSmall, item.canonicalBytes(&id_only));
    try t.expectEqualSlices(u8, &item.endpoint.node_id.toBytes(), &id_only);
}

/// The answer `merge` returned, checked against the inputs rather than
/// against itself.
///
/// Three separate claims, because a length is not any of them: the list is
/// exactly as long as the inputs hold that many *different* answers, its head
/// is the answer `winner` names out of the inputs, and it is strictly
/// decreasing, which is what says it is both in `Item.order` and free of the
/// duplicates `merge` exists to drop.
fn expectMergeAnswered(merged: []const Item, items: []const Item) !void {
    // Counted without sorting and without `merge`, so a list that dropped an
    // answer or kept two of them fails here rather than agreeing with itself.
    var distinct: usize = 0;
    for (items, 0..) |item, at| {
        var repeated = false;
        for (items[0..at]) |earlier| {
            if (earlier.eql(item)) repeated = true;
        }
        if (!repeated) distinct += 1;
    }
    try t.expectEqual(distinct, merged.len);
    if (distinct == 0) return;
    try t.expect(merged[0].eql(winner(items) orelse return error.TestUnexpectedResult));

    var at: usize = 1;
    while (at < merged.len) : (at += 1) {
        try t.expectEqual(std.math.Order.gt, merged[at - 1].order(merged[at]));
    }
}

/// One run of `merge` for `t.checkAllAllocationFailures`.
///
/// Two allocations stand between the inputs and the answer: the sorted copy
/// `merge` deduplicates out of, and the array it writes. Both refusals return
/// rather than being handled, so the sweep sees them as failures instead of
/// as a run that recovered from one.
///
/// The answer is checked on the run that succeeds, and the inputs are checked
/// on every run that does not: `merge` sorts a copy, so a refusal can hand
/// back the sorted copy and nothing else, and every input still reads as it
/// did when the sweep started.
fn mergeAccounting(alloc: std.mem.Allocator, items: []const Item, before: []const Item) !void {
    const merged = merge(alloc, items) catch |err| {
        try t.expectEqual(error.OutOfMemory, err);
        for (items, before) |left, right| try t.expect(left.eql(right));
        return err;
    };
    try expectMergeAnswered(merged, items);
    // A merged list owns no address and releases none, so the array is the
    // whole of what has to come back.
    alloc.free(merged);
}

test "every allocation a merge makes can fail on its own" {
    const alloc = t.allocator;
    const items = try corpus(alloc, 24);
    defer freeItems(alloc, items);
    // What the caller handed over, so "nothing was changed" is a claim about
    // these items and not about a list `merge` never saw.
    const before = try alloc.dupe(Item, items);
    defer alloc.free(before);

    try t.checkAllAllocationFailures(alloc, mergeAccounting, .{ items, before });

    // The eventual consumer result, on a plain allocator: a zone reading this
    // list gets the same answer whichever of the two allocations it did not
    // have to pay for.
    const merged = try merge(alloc, items);
    defer alloc.free(merged);
    try expectMergeAnswered(merged, items);
}
