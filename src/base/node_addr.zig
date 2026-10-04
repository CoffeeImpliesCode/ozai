//! A node id plus the paths that might reach it.
//!
//! A node id alone is not an address. `NodeAddr` pairs it with the paths that
//! might reach the node — relay servers, direct IP addresses, and opaque custom
//! transports — sorted and deduplicated so that the same address always
//! produces the same bytes in a ticket.
//!
//! This is the one address module that owns an allocation: the list is made by
//! `withRelay` or by a successful `insert` and released by exactly one
//! `deinit`. Everything it holds is borrowed or inline, and the primitive
//! shapes it sorts come from `addr.zig`.

const std = @import("std");
const key = @import("key.zig");
const primitive = @import("addr.zig");
const relay_url = @import("relay_url.zig");
const transport_addr = @import("transport_addr.zig");

const CustomAddr = primitive.CustomAddr;
const IpAddress = primitive.IpAddress;
const NodeId = key.NodeId;
const RelayUrl = relay_url.RelayUrl;
const TransportAddr = transport_addr.TransportAddr;
const max_inline_length = primitive.max_inline_length;
const orderTransport = transport_addr.orderTransport;

pub const NodeAddr = struct {
    /// The identity every one of `addrs` is a path to.
    node_id: NodeId,
    /// Sorted by `TransportAddr.order`, unique. Mutate only through `insert`.
    addrs: []TransportAddr,

    /// An address with no paths: the empty list. It owns nothing, so `deinit`
    /// on it frees nothing and is safe.
    pub fn init(node_id: NodeId) NodeAddr {
        return .{ .node_id = node_id, .addrs = &.{} };
    }

    /// Insert keeping the slice sorted and unique. Returns `null`, with
    /// nothing allocated and the receiver unchanged, when the address was
    /// already present.
    ///
    /// On success the returned `NodeAddr` holds a *new* allocation — `realloc`
    /// may also have moved the old one — so the receiver and every copy of it
    /// are invalid: do not read through them and do not free them. Adopt the
    /// returned value from here on.
    ///
    /// `error.OutOfMemory` leaves the receiver exactly as it was and still
    /// valid, so the caller keeps owning its list; nothing was allocated.
    ///
    /// Either way the caller keeps ownership of `addr`: a successful insert
    /// copies the `TransportAddr` shallowly, so a `.custom` payload stays a
    /// borrow the caller must keep alive for as long as the list is read.
    pub fn insert(
        self: NodeAddr,
        alloc: std.mem.Allocator,
        addr: TransportAddr,
    ) std.mem.Allocator.Error!?NodeAddr {
        const at = std.sort.lowerBound(TransportAddr, self.addrs, addr, orderTransport);
        if (at < self.addrs.len and self.addrs[at].order(addr) == .eq) return null;
        const grown = try alloc.realloc(self.addrs, self.addrs.len + 1);
        // `@memmove`, not `@memcpy`: the destination starts one element
        // *after* the source, so the two ranges overlap and a forward copy
        // would write each element over the one the next step still has to
        // read. `@memmove` is the only one of the two that is defined for
        // overlap, so the direction is its problem to get right and not the
        // caller's to reason about.
        @memmove(grown[at + 1 ..], grown[at..self.addrs.len]);
        grown[at] = addr;
        return .{ .node_id = self.node_id, .addrs = grown };
    }

    /// A one-address `NodeAddr` carrying `url`, with a new list allocation.
    ///
    /// `error.OutOfMemory` allocates nothing, and `url` is a value, so the
    /// caller's copy is unaffected either way.
    pub fn withRelay(
        alloc: std.mem.Allocator,
        node_id: NodeId,
        url: RelayUrl,
    ) std.mem.Allocator.Error!NodeAddr {
        const one = try alloc.dupe(TransportAddr, &.{.{ .relay = url }});
        return .{ .node_id = node_id, .addrs = one };
    }

    /// Free the address list, and nothing else.
    ///
    /// Custom payloads in the list are the caller's and are left untouched;
    /// whoever allocated one still owns it. The address and every copy of it
    /// are invalid afterward, and a second call is a double free.
    pub fn deinit(self: NodeAddr, alloc: std.mem.Allocator) void {
        alloc.free(self.addrs);
    }

    /// How many of `addrs` are relay addresses.
    pub fn relayCount(self: NodeAddr) usize {
        var count: usize = 0;
        for (self.addrs) |addr| {
            if (addr == .relay) count += 1;
        }
        return count;
    }

    /// The node id in hex, then every address as `relay:`, `ip:` or
    /// `custom:`, separated by spaces.
    pub fn format(self: NodeAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.node_id.format(writer);
        for (self.addrs) |addr| {
            try writer.writeAll(" ");
            try addr.format(writer);
        }
    }
};

const t = std.testing;

const clobberStack = primitive.clobberStack;

test "custom address outlives the copy into a node address" {
    const node_id = (try key.SecretKey.fromSeed([_]u8{2} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;
    var storage: [max_inline_length]u8 = undefined;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);

    const custom = try CustomAddr.parse("2a_abab", &storage);
    addr = (try addr.insert(alloc, .{ .custom = custom })) orelse
        return error.TestUnexpectedResult;
    @call(.never_inline, clobberStack, .{});

    // The heap slice now holds what `parse` handed back, so this is the same
    // dangling read `CustomAddr.parse`'s own test pins, one lifetime longer,
    // read the same way.
    const stored = addr.addrs[1].custom;
    const seen = [_]u8{ stored.data[0], stored.data[1] };
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, &seen);
    try t.expectEqual(@as(u64, 0x2a), stored.id);
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(addr.addrs[1]));
}

test "node addr keeps its address list sorted and unique" {
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;

    var addr = try NodeAddr.withRelay(alloc, node_id, try RelayUrl.parse("https://z.example./"));
    defer addr.deinit(alloc);
    try t.expectEqual(@as(usize, 1), addr.addrs.len);

    const host = IpAddress.parse("10.0.0.1") orelse return error.TestUnexpectedResult;
    const direct: TransportAddr = .{ .ip = .{ .ip = host, .port = 9 } };
    addr = (try addr.insert(alloc, direct)) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // The duplicate must be rejected, and must not have grown the slice.
    try t.expectEqual(@as(?NodeAddr, null), try addr.insert(alloc, direct));
    try t.expectEqual(@as(usize, 2), addr.addrs.len);

    // Relay sorts before ip by variant, so it stays at index 0.
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(addr.addrs[0]));
    try t.expectEqual(@as(usize, 1), addr.relayCount());

    var index: usize = 1;
    while (index < addr.addrs.len) : (index += 1) {
        try t.expectEqual(std.math.Order.lt, addr.addrs[index - 1].order(addr.addrs[index]));
    }
}

/// Strictly increasing is sorted *and* unique in one pass, which is the whole
/// invariant `insert` exists to maintain.
fn expectSortedAndUnique(addrs: []const TransportAddr) !void {
    var index: usize = 1;
    while (index < addrs.len) : (index += 1) {
        try t.expectEqual(std.math.Order.lt, addrs[index - 1].order(addrs[index]));
    }
}

test "a mid-list insert keeps every address it shifted" {
    // The relay sorts ahead of both sockets by variant order, so it lands at
    // index 0 with two addresses behind it. Every other insert in this file
    // appended, where the shift copies nothing and a copy in the wrong
    // direction is indistinguishable from a copy in the right one.
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;
    const first_host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    const first: TransportAddr = .{ .ip = .{ .ip = first_host, .port = 60165 } };
    const second_host = IpAddress.parse("213.208.157.87") orelse return error.TestUnexpectedResult;
    const second: TransportAddr = .{ .ip = .{ .ip = second_host, .port = 60165 } };
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://relay.example./") };

    var addr: NodeAddr = .{
        .node_id = node_id,
        .addrs = try alloc.dupe(TransportAddr, &.{ first, second }),
    };
    defer addr.deinit(alloc);

    addr = (try addr.insert(alloc, relay)) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 3), addr.addrs.len);
    try expectSortedAndUnique(addr.addrs);

    // Copied forwards, the shift writes `first` over `second`: the length and
    // the variant order both still look right, so the values themselves are
    // the only thing that catches it.
    try t.expectEqual(std.math.Order.eq, addr.addrs[0].order(relay));
    try t.expectEqual(std.math.Order.eq, addr.addrs[1].order(first));
    try t.expectEqual(std.math.Order.eq, addr.addrs[2].order(second));

    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try addr.format(&writer);
    const text = writer.buffered();
    try t.expect(std.mem.indexOf(u8, text, "relay:https://relay.example./") != null);
    try t.expect(std.mem.indexOf(u8, text, "ip:192.168.96.145:60165") != null);
    try t.expect(std.mem.indexOf(u8, text, "ip:213.208.157.87:60165") != null);
}

test "a duplicate with addresses behind it is rejected and changes nothing" {
    // `first` has `second` behind it, so the lower bound lands short of the
    // end. A duplicate at the last index cannot tell a rejection that fires
    // before the shift from one that fires because nothing had to move.
    const node_id = (try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length)).nodeId();
    const alloc = t.allocator;
    const first_host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    const first: TransportAddr = .{ .ip = .{ .ip = first_host, .port = 60165 } };
    const second_host = IpAddress.parse("213.208.157.87") orelse return error.TestUnexpectedResult;
    const second: TransportAddr = .{ .ip = .{ .ip = second_host, .port = 60165 } };
    const relay: TransportAddr = .{ .relay = try RelayUrl.parse("https://relay.example./") };

    const addr: NodeAddr = .{
        .node_id = node_id,
        .addrs = try alloc.dupe(TransportAddr, &.{ relay, first, second }),
    };
    defer addr.deinit(alloc);

    try t.expectEqual(@as(?NodeAddr, null), try addr.insert(alloc, first));
    try t.expectEqual(@as(usize, 3), addr.addrs.len);
    try expectSortedAndUnique(addr.addrs);
    try t.expectEqual(std.math.Order.eq, addr.addrs[1].order(first));
    try t.expectEqual(std.math.Order.eq, addr.addrs[2].order(second));
}

/// One run of `withRelay` followed by one `insert`, for
/// `t.checkAllAllocationFailures`.
///
/// Both refusals are checked where they happen rather than by a balance at
/// the end. A refused `withRelay` hands the caller its own `RelayUrl` back
/// untouched, and a refused `insert` leaves a receiver that is still exactly
/// what it was and still the caller's to release — that is the whole of the
/// contract `insert` states, and a counter cannot see either. Both refusals
/// are then returned rather than swallowed, so the sweep sees the failures
/// they are instead of `error.SwallowedOutOfMemoryError`.
///
/// `insert` is run from both starting points a caller has: the empty literal
/// `init` returns, and a list a previous insert already grew. They are
/// different branches — `realloc` on a zero-length slice allocates, and on a
/// list of any length it asks the backend to grow the one it has — and both
/// are allocations the sweep has to reach.
fn nodeAddrAccounting(alloc: std.mem.Allocator) !void {
    const node_id = (try key.SecretKey.fromSeed([_]u8{3} ** key.SecretKey.seed_length)).nodeId();
    const relay = try RelayUrl.parse("https://relay.example./");
    const host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    const socket: TransportAddr = .{ .ip = .{ .ip = host, .port = 60165 } };

    const seeded = NodeAddr.withRelay(alloc, node_id, relay) catch |err| {
        try t.expectEqual(error.OutOfMemory, err);
        // `url` is a value, so a refusal that never built a list cost the
        // caller nothing and the url is still theirs to hand to the next try.
        try t.expectEqualStrings("relay.example.", relay.hostSlice());
        try t.expectEqual(RelayUrl.default_https_port, relay.port);
        return err;
    };
    try expectRelayOnly(&seeded);

    const outcome = seeded.insert(alloc, socket);
    if (outcome) |maybe_grown| {
        const grown = maybe_grown orelse {
            seeded.deinit(alloc);
            return error.TestUnexpectedResult;
        };
        defer grown.deinit(alloc);
        // A successful `insert` replaced the allocation, so `seeded` is gone
        // and the returned value is the only one that may be freed.
        try t.expectEqual(@as(usize, 2), grown.addrs.len);
        try expectSortedAndUnique(grown.addrs);
        try t.expectEqualStrings("relay.example.", grown.addrs[0].relay.hostSlice());
        try t.expectEqual(std.math.Order.eq, grown.addrs[1].order(socket));
        try t.expectEqual(@as(usize, 1), grown.relayCount());
    } else |err| {
        try t.expectEqual(error.OutOfMemory, err);
        // Old state: unchanged, still valid, and still the caller's list.
        try expectRelayOnly(&seeded);
        seeded.deinit(alloc);
        return err;
    }

    const empty = NodeAddr.init(node_id);
    try t.expectEqual(@as(usize, 0), empty.addrs.len);
    const from_empty = empty.insert(alloc, socket);
    if (from_empty) |maybe_grown| {
        const grown = maybe_grown orelse return error.TestUnexpectedResult;
        defer grown.deinit(alloc);
        try t.expectEqual(@as(usize, 1), grown.addrs.len);
        try expectSortedAndUnique(grown.addrs);
        try t.expectEqual(std.math.Order.eq, grown.addrs[0].order(socket));
    } else |err| {
        try t.expectEqual(error.OutOfMemory, err);
        // Old state: the empty literal, which owns nothing and reads as the
        // empty list it was handed out as.
        try t.expectEqual(@as(usize, 0), empty.addrs.len);
        try t.expectEqual(node_id, empty.node_id);
        empty.deinit(alloc);
        return err;
    }

    // Negative space, and it belongs here rather than in a test of its own:
    // an address the list already holds is refused before the allocator is
    // asked at all, so it can neither be turned into an `error.OutOfMemory`
    // nor have grown the list.
    const held = try NodeAddr.withRelay(alloc, node_id, relay);
    var refusing = t.FailingAllocator.init(alloc, .{ .fail_index = 0, .resize_fail_index = 0 });
    const duplicate = try held.insert(refusing.allocator(), .{ .relay = relay });
    try t.expectEqual(@as(?NodeAddr, null), duplicate);
    try t.expect(!refusing.has_induced_failure);
    try t.expectEqual(@as(usize, 0), refusing.allocations);
    try expectRelayOnly(&held);
    held.deinit(alloc);
}

/// The one-address state every refusal above has to leave behind: a list that
/// is still sorted, still unique, and still carrying the relay it was built
/// with rather than a half-written shift.
fn expectRelayOnly(address: *const NodeAddr) !void {
    try t.expectEqual(@as(usize, 1), address.addrs.len);
    try expectSortedAndUnique(address.addrs);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(address.addrs[0]));
    try t.expectEqualStrings("relay.example.", address.addrs[0].relay.hostSlice());
    try t.expectEqual(RelayUrl.default_https_port, address.addrs[0].relay.port);
    try t.expectEqual(@as(usize, 1), address.relayCount());
}

test "every allocation a node address makes can fail on its own" {
    // Three allocations stand between a node id and a two-address list: the
    // relay list, the growth that holds the socket, and the growth of the
    // empty list the same insert starts from. The sweep refuses each of them
    // in turn and ends on the run nothing is refused on.
    try t.checkAllAllocationFailures(t.allocator, nodeAddrAccounting, .{});

    // The eventual consumer result, on a plain allocator: a sorted, duplicate
    // free list of exactly the two addresses the sweep asked for.
    const node_id = (try key.SecretKey.fromSeed([_]u8{3} ** key.SecretKey.seed_length)).nodeId();
    const relay = try RelayUrl.parse("https://relay.example./");
    const host = IpAddress.parse("192.168.96.145") orelse return error.TestUnexpectedResult;
    var address = try NodeAddr.withRelay(t.allocator, node_id, relay);
    address = (try address.insert(t.allocator, .{ .ip = .{ .ip = host, .port = 60165 } })) orelse
        return error.TestUnexpectedResult;
    defer address.deinit(t.allocator);
    try expectSortedAndUnique(address.addrs);
    try t.expectEqual(@as(usize, 2), address.addrs.len);
    try t.expectEqualStrings("relay.example.", address.addrs[0].relay.hostSlice());
    try t.expectEqual(@as(u16, 60165), address.addrs[1].ip.port);
}
