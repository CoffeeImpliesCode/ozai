//! Contact data is bounded, and both bounds are proved at the copy rather
//! than at the use.

const std = @import("std");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const sim = @import("sim.zig");

const t = std.testing;

const peer_data_max = bounds.peer_data_max;
const PeerData = peers.PeerData;
const PeerDataMap = peers.PeerDataMap;

// Contact data is bounded, and the bound is reported rather than truncated.
test "contact data over the bound is refused" {
    const long = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(long);
    @memset(long, 0x11);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(long));
    // A length the length field cannot spell is refused the same way, by the
    // narrowing rather than by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x33);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(unspellable));
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x22);
    const data = try PeerData.fromBytes(exact);
    try t.expectEqual(peer_data_max, data.slice().len);
    try t.expectEqual(@as(usize, 0), (try PeerData.fromBytes(&.{})).slice().len);
}

// The contact table proves the same bound at the copy, where nothing above it
// has: the slice is a peer's claim about itself, and a message is not obliged
// to be short.
test "the contact table refuses what a record cannot spell" {
    var map: PeerDataMap = .{};
    const peer = try sim.nodeIdFor(2);
    // One byte over the ceiling, and still a length a `u16` spells: only the
    // comparison refuses this one, so only the comparison keeps the copy in
    // bounds.
    const over = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(over);
    @memset(over, 0x44);
    try t.expectError(error.PeerDataTooLong, map.put(peer, over));
    // A length the length field cannot spell is refused by the narrowing, and
    // not by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x55);
    try t.expectError(error.PeerDataTooLong, map.put(peer, unspellable));
    // Nothing refused left a half-written entry behind, and the ceiling is a
    // length rather than a hint.
    try t.expectEqual(@as(usize, 0), map.count());
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x66);
    try map.put(peer, exact);
    try t.expectEqualSlices(u8, exact, map.get(peer).?.slice());
}
