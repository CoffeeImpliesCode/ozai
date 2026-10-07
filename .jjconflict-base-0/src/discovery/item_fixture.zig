//! The fixed corpus the discovery record's properties are checked over.
//!
//! `discovery/item_record.zig` checks `Item.order` over a seeded set, and
//! `discovery/item_merge.zig` checks that `merge` and `winner` agree with it
//! whichever way round the services answered. Both need the same three node
//! ids and the same fifteen addresses, and both need to be sure they are
//! looking at the *same* set — so the pool lives here rather than being drawn
//! twice from a seed that happens to agree.
//!
//! # Why the pool is shaped the way it is
//!
//! Not noise. Four of the fifteen entries are two pairs whose length order and
//! lexical order pull in opposite directions, so a comparator that read a
//! length prefix before the bytes ranks each pair the other way round from
//! `addr.TransportAddr.order`. The remaining entries vary one field at a time,
//! which is what lets a generated item differ from another in exactly one
//! component of the order. The doc on `pool` is the authority on the list
//! itself; this module exists so that list has one owner.
//!
//! Nothing here is production code. It is reached only from the test regions of
//! the two modules above, and `src/root.zig` references it so those blocks run.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const record = @import("item_record.zig");

/// Node ids from fixed seeds. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so the corpus draws from a pool of
/// three rather than from noise. The pool is also what lets two generated
/// items be equal in every field, which the order properties need.
pub fn corpusIds() key.KeyError![3]addr.NodeId {
    var ids: [3]addr.NodeId = undefined;
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
pub fn pool() addr.RelayUrlParseError![pool_length]addr.TransportAddr {
    return .{
        .{ .relay = try addr.RelayUrl.parse("https://use1-1.relay.iroh.network./") },
        .{ .relay = try addr.RelayUrl.parse("https://use1-2.relay.iroh.network./") },
        .{ .relay = try addr.RelayUrl.parse("http://relay.example./") },
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
        .{ .relay = try addr.RelayUrl.parse("http://use1-1.relay.iroh.network./") },
        .{ .relay = try addr.RelayUrl.parse("https://relay.example.:8443/") },
        // Two pairs whose length order and lexical order pull in opposite
        // directions: in each the longer value is the lexically lower one, so
        // anything that reads a length prefix before the bytes ranks the pair
        // the other way round from `TransportAddr.order`. Nothing above can
        // tell the two orders apart.
        .{ .relay = try addr.RelayUrl.parse("https://aa.example./") },
        .{ .relay = try addr.RelayUrl.parse("https://b.example./") },
        .{ .custom = .{ .id = 5, .data = &.{ 0x61, 0x61 } } },
        .{ .custom = .{ .id = 5, .data = &.{0x62} } },
    };
}

/// A seeded set of items, at least two of which are equal in every field, and
/// owned by the caller's allocator. The seed is fixed, so a failure here is
/// the same failure tomorrow.
pub fn corpus(alloc: std.mem.Allocator, count: usize) ![]record.Item {
    std.debug.assert(count >= 2);
    var prng = std.Random.DefaultPrng.init(0x6974_656d);
    const random = prng.random();
    const ids = try corpusIds();
    const addresses = try pool();
    const items = try alloc.alloc(record.Item, count);
    for (items[0 .. count - 2]) |*item| {
        const id = ids[random.intRangeLessThan(usize, 0, ids.len)];
        var endpoint = addr.NodeAddr.init(id);
        const address_count = random.intRangeLessThan(usize, 0, 4);
        for (0..address_count) |_| {
            const pick = random.intRangeLessThan(usize, 0, addresses.len);
            // A repeated pick is a duplicate, and `insert` reports a
            // duplicate by returning null. The address list is
            // duplicate-free; the draw is not.
            if (try endpoint.insert(alloc, addresses[pick])) |next| endpoint = next;
        }
        const kinds = record.Provenance.all.len;
        const provenance = record.Provenance.all[random.intRangeLessThan(usize, 0, kinds)];
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

pub fn freeItems(alloc: std.mem.Allocator, items: []record.Item) void {
    for (items) |item| item.endpoint.deinit(alloc);
    alloc.free(items);
}

/// One address, one service, one stamp.
pub fn single(
    alloc: std.mem.Allocator,
    id: addr.NodeId,
    transport: addr.TransportAddr,
    provenance: record.Provenance,
    last_updated: ?u64,
) !record.Item {
    var endpoint = addr.NodeAddr.init(id);
    endpoint = (try endpoint.insert(alloc, transport)) orelse
        return error.TestUnexpectedResult;
    return .init(endpoint, provenance, last_updated);
}
