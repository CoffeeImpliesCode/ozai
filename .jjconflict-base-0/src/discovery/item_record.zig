//! What one discovery result *is*: the address, the service that reported it,
//! and the total order two results are compared under.
//!
//! This is the "what" half of what `discovery/item.zig` used to be one file
//! for, and the half that has an upstream counterpart to argue with. The three
//! other modules that file became are each a different question about the same
//! value: `discovery/item_encode.zig` is what a record looks like in bytes,
//! `discovery/item_merge.zig` is the answer over a *set* of records, and
//! `discovery/item_resolution.zig` is what one resolve attempt came to. The
//! boundaries are those questions and not the file's own layout, so a change to
//! one of them lands in one module.
//!
//! # What did not move
//!
//! `Provenance`, `Item`, its `init`, `order`, `eql`, `canonicalBytes` and
//! `maxEncodedLength` are here verbatim, and so are the order properties
//! below them. `Item.canonicalBytes` now calls
//! `discovery/item_encode.zig`'s `encodeAddr` across the module boundary; the
//! bytes it writes, the errors it returns and the doc that says what they are
//! for are unchanged.
//!
//! # The order is the whole of the answer
//!
//! `Item.order` is invariant 12: timestamp first, address value second,
//! provenance last, each component total and injective on its own field. The
//! doc on the method is the authority on why each arm is there; what this
//! module owns is that there is exactly one such comparator in the tree, and
//! that the tests below check it over a corpus rather than on three
//! hand-picked records.
//!
//! The fixtures those tests share — the seed pool, the three node ids and the
//! item builders — are `discovery/item_fixture.zig`, because the merge module's
//! tests need the same pool and a fixture module is the honest name for it.

const std = @import("std");
const addr = @import("../base/addr.zig");
const encode = @import("item_encode.zig");
const fixture = @import("item_fixture.zig");
const t = std.testing;

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

/// One discovery result: an address, the service that reported it, and when.
///
/// An `Item` is a shallow value over somebody else's address list: it owns the
/// `NodeAddr` struct, not the `addrs` slice behind it, and a copy of an `Item`
/// shares that slice with the original rather than duplicating it. So an item
/// read out of a `resolve.Stream` is valid exactly as long as that stream is,
/// and an item to keep past it is an item to copy the addresses into. Who
/// allocated the list, and who releases it, is `base/addr.zig`'s rule.
pub const Item = struct {
    /// Upstream's `endpoint_info: EndpointInfo`. ozai's `NodeAddr` carries the
    /// node id beside the paths, so the whole upstream struct is one field
    /// here, and `addrs` is sorted and duplicate-free as invariant 2 requires.
    endpoint: addr.NodeAddr,
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
        endpoint: addr.NodeAddr,
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
    pub fn canonicalBytes(self: Item, out: []u8) encode.EncodeError![]const u8 {
        const id = self.endpoint.node_id.toBytes();
        if (out.len < id.len) return error.BufferTooSmall;
        @memcpy(out[0..id.len], &id);
        var at = id.len;
        for (self.endpoint.addrs) |value| {
            var record: [encode.max_encoded_addr_length]u8 = undefined;
            const bytes = try encode.encodeAddr(value, &record);
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
        return addr.NodeId.byte_length + addrs * encode.max_encoded_addr_length;
    }
};

/// Null is infinitely old. See `Item.order`.
fn orderTimestamp(a: ?u64, b: ?u64) std.math.Order {
    if (a == null) return if (b == null) .eq else .lt;
    if (b == null) return .gt;
    return std.math.order(a.?, b.?);
}

/// `-order`, so antisymmetry is stated once and nowhere else re-derives it.
fn negate(order: std.math.Order) std.math.Order {
    return switch (order) {
        .lt => .gt,
        .eq => .eq,
        .gt => .lt,
    };
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
    const addresses = try fixture.pool();
    const id = (try fixture.corpusIds())[0];

    const unstamped = try fixture.single(alloc, id, addresses[0], .pkarr, null);
    const oldest = try fixture.single(alloc, id, addresses[0], .pkarr, 0);
    const newest = try fixture.single(alloc, id, addresses[0], .pkarr, std.math.maxInt(u64));
    try t.expectEqual(std.math.Order.lt, unstamped.order(oldest));
    try t.expectEqual(std.math.Order.gt, newest.order(unstamped));
    try t.expectEqual(std.math.Order.eq, unstamped.order(unstamped));
}

test "equal timestamps fall through to the address" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try fixture.pool();
    const id = (try fixture.corpusIds())[0];

    // Same node, same service, same stamp, and one address differing only in
    // its host: the tiebreak has to be the address, or the zone has nothing to
    // decide on. These two hosts are the same length, so the pair cannot tell
    // the value order from a length-prefixed one; the next test is the pair
    // that can.
    const first = try fixture.single(alloc, id, addresses[0], .pkarr, 17);
    const second = try fixture.single(alloc, id, addresses[1], .pkarr, 17);
    try t.expectEqual(std.math.Order.lt, first.order(second));

    // Two addresses are not automatically the larger item. Addresses are
    // compared one at a time: `with_two` starts with the lower host, so it
    // loses to a one-address item that starts with the higher one, and a
    // comparator that counted first would have got this exactly backwards.
    var grown = addr.NodeAddr.init(id);
    if (try grown.insert(alloc, addresses[0])) |next| grown = next;
    if (try grown.insert(alloc, addresses[1])) |next| grown = next;
    const with_two = Item.init(grown, .pkarr, 17);
    try t.expectEqual(std.math.Order.lt, with_two.order(second));
    // With the first address equal, the extra one is what decides.
    try t.expectEqual(std.math.Order.gt, with_two.order(first));
}

test "the order is antisymmetric, transitive and total" {
    const items = try fixture.corpus(t.allocator, 24);
    defer fixture.freeItems(t.allocator, items);

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

test "an address the encoder cannot hold still has a total order" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try fixture.pool();
    const id = (try fixture.corpusIds())[0];
    const item = try fixture.single(
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

    const other = try fixture.single(alloc, id, addresses[5], .pkarr, 3);
    try t.expectEqual(negate(other.order(item)), item.order(other));
    try t.expectEqual(std.math.Order.eq, item.order(item));
}
