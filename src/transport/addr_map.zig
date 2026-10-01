//! The synthetic-ULA allocation: which key owns which address, both ways.
//!
//! `base/ula.zig` builds an address and recognises one. This remembers the
//! choice: a key answers with the same address for as long as the map lives,
//! and an address that came back off the wire names the key that owns it. The
//! reverse direction is not a convenience. A departing path is known by its
//! addresses, and the map is what turns one back into the peers that care.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `AddrMap` and `AddrMapInner` at
//! `iroh/src/socket/mapped_addrs.rs:315-376`; the three `MappedAddr::generate`
//! bodies that fill octets 8..16 from `rand::rng()` at `mapped_addrs.rs:136`,
//! `:197` and `:257`; the maps `MappedAddrs` holds at
//! `iroh/src/socket/remote_map.rs:75-83`.
//!
//! Upstream keys those three maps on `EndpointId`, on `(RelayUrl, EndpointId)`
//! and on `CustomAddr` (`remote_map.rs:77-81`), which is what `Key` is here.
//! They are three maps only because upstream has three address newtypes;
//! `ula.Path` already collapsed those into one tagged enum, so the three maps
//! are one and the /64 each address carries keeps the three arms apart.
//!
//! Two deliberate departures, both recorded in `docs/ARCHITECTURE.md`: the map
//! is a value the caller owns rather than an `Arc<Mutex<AddrMapInner>>`, and
//! the host bits come from a generator the caller passes rather than from
//! `rand::rng()`.

const std = @import("std");
// Named for the layer, not the file: a parameter called `key` or `addr` is
// this module's own vocabulary and a parameter may not shadow a declaration.
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");

const NodeId = base_key.NodeId;
const RelayUrl = base_addr.RelayUrl;
const CustomAddr = base_addr.CustomAddr;
const Ula = ula.Ula;
const HostBits = ula.HostBits;

/// Both tables at the std default load, named once so the two directions
/// cannot drift apart.
const max_load = std.hash_map.default_max_load_percentage;

/// A custom transport address, owned.
///
/// `base_addr.CustomAddr` borrows its data and an entry here outlives whatever
/// frame produced the address, so a key pointing into a popped frame would be
/// read back minutes later, on another stack, over bytes already reused. This
/// is invariant 6 as a type rather than as a comment.
pub const CustomKey = struct {
    id: u64,
    data: [base_addr.max_inline_length]u8,
    data_length: u8,

    /// Copy `custom` into a key.
    ///
    /// Fails on more data than a `CustomAddr` can carry. `parse` and
    /// `parseBinary` both reject that already, so the only caller that gets
    /// here with it built the struct by hand — and a key that silently
    /// truncated it would send the peer somewhere that is not here.
    pub fn from(custom: CustomAddr) base_addr.CustomAddrParseError!CustomKey {
        // Narrow once, where the bound is proved: the cast admits only a
        // length a `u8` holds, and the comparison is the field's own
        // ceiling. One error answers both, because a length this key
        // cannot spell is a length it cannot own.
        const data_length: u8 = std.math.cast(u8, custom.data.len) orelse
            return error.DataTooLong;
        if (data_length > base_addr.max_inline_length) return error.DataTooLong;
        var owned: CustomKey = undefined;
        owned.id = custom.id;
        // Zero the tail: the key is copied whole, and an indeterminate byte in
        // it is a value that does not equal itself.
        owned.data = @splat(0);
        owned.data_length = data_length;
        @memcpy(owned.data[0..data_length], custom.data);
        return owned;
    }

    /// The data half, borrowed.
    ///
    /// A pointer receiver for the reason `RelayUrl.hostSlice` takes one: the
    /// caller has to own the `CustomKey` the borrow points into.
    pub fn dataSlice(self: *const CustomKey) []const u8 {
        return self.data[0..self.data_length];
    }
};

/// One `(relay, node)` pair. Upstream keys `relay_addrs` on
/// `(RelayUrl, EndpointId)` (`remote_map.rs:79`) with the relay first, and
/// the field order here follows it.
pub const RelayNode = struct {
    relay: RelayUrl,
    node: NodeId,
};

/// What an address stands for: the three key arms upstream gives a map each.
pub const Key = union(enum) {
    /// `fd15:70a:510b::/64`. The peer itself, before a path is chosen.
    any_path: NodeId,
    /// `fd15:70a:510b:1::/64`. One `(peer, relay)` pair.
    relay: RelayNode,
    /// `fd15:70a:510b:3::/64`. One custom transport address.
    custom: CustomKey,
};

/// How many host values `get` draws before it gives up.
///
/// Upstream loops until it draws something unused (`mapped_addrs.rs:341-346`),
/// which is a hang when the source repeats. A generator drawing uniform 64-bit
/// values exhausts this budget with probability below 2**-27 for any map that
/// fits in memory, so a caller that reaches the bound has a generator that is
/// not producing new values rather than bad luck.
pub const max_generate_attempts = 32;

/// Why a key could not be answered with an address.
pub const GetError = error{
    /// The caller's allocator refused the entry.
    OutOfMemory,
    /// `max_generate_attempts` candidates, every one of them already handed
    /// out. The generator is repeating, and a hang is not an answer.
    HostBitsExhausted,
};

/// Hash and equality for the forward table.
///
/// Not `std.hash_map.AutoContext`: `autoHash` walks `RelayUrl`'s whole
/// 253-byte host field, and `parse` leaves everything past the host unwritten,
/// so two equal relay URLs built by two calls would hash differently and never
/// find each other. Only the bytes a relay URL is made of are hashed, and the
/// integers go in native order because the hash never leaves the process.
pub const KeyContext = struct {
    pub fn hash(_: KeyContext, key: Key) u64 {
        var hasher = std.hash.Wyhash.init(0);
        // The arm, so two keys whose payloads collide do not share a bucket on
        // the strength of the tag alone.
        hasher.update(&[_]u8{@intFromEnum(std.meta.activeTag(key))});
        switch (key) {
            .any_path => |node| hasher.update(&node.toBytes()),
            .relay => |pair| {
                hasher.update(&[_]u8{@intFromEnum(pair.relay.scheme)});
                hasher.update(std.mem.asBytes(&pair.relay.port));
                hasher.update(pair.relay.hostSlice());
                hasher.update(&pair.node.toBytes());
            },
            .custom => |custom| {
                hasher.update(std.mem.asBytes(&custom.id));
                hasher.update(custom.dataSlice());
            },
        }
        return hasher.final();
    }

    pub fn eql(_: KeyContext, a: Key, b: Key) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .any_path => |node| node.order(b.any_path) == .eq,
            .relay => |pair| pair.relay.order(b.relay.relay) == .eq and
                pair.node.order(b.relay.node) == .eq,
            .custom => |custom| custom.id == b.custom.id and
                std.mem.eql(u8, custom.dataSlice(), b.custom.dataSlice()),
        };
    }
};

/// One direction of the map. Unmanaged, because the allocator belongs to the
/// caller on every call and an empty map allocates nothing.
// HashMapUnmanaged returns a type; PascalCase is required for this binding.
// zwanzig-disable-next-line: identifier-style
const Forward = std.HashMapUnmanaged(Key, Ula, KeyContext, max_load);
// This reverse index is another type returned by the same factory.
// zwanzig-disable-next-line: identifier-style
const Reverse = std.HashMapUnmanaged(Ula, Key, std.hash_map.AutoContext(Ula), max_load);

/// The bidirectional map between a key and the synthetic address it answers
/// with. Upstream's `MappedAddrs` holds one `AddrMap` per key arm; with the
/// arms in one `Key` and the addresses in one `Ula`, one map does that work.
pub const MappedAddrs = struct {
    by_key: Forward,
    by_addr: Reverse,

    /// An empty map.
    pub fn init() MappedAddrs {
        return .{ .by_key = .empty, .by_addr = .empty };
    }

    /// Free both tables and leave the map empty: a `deinit`ed map is still a
    /// value, and saying so keeps a second `deinit` a second no-op rather
    /// than a double free.
    // Both tables are reset to empty by init; Z030 does not recognize a
    // whole-receiver constructor assignment as a terminal empty state.
    // ziglint-ignore: Z030
    pub fn deinit(self: *MappedAddrs, gpa: std.mem.Allocator) void {
        self.by_key.deinit(gpa);
        self.by_addr.deinit(gpa);
        self.* = .init();
    }

    /// The address `key` answers with, the same one for the life of the map.
    ///
    /// Upstream `AddrMap::get` (`mapped_addrs.rs:336-353`). The two
    /// properties that carry over are the two the map exists for: the first
    /// draw is kept, so a key is allocated once and not once per call, and a
    /// candidate the reverse index already holds is drawn again rather than
    /// handed out twice.
    ///
    /// `random` is where this leaves upstream. `MappedAddr::generate` calls
    /// `rand::rng()` inside the loop (`mapped_addrs.rs:141`), and a
    /// process-global RNG is what AGENTS.md §2 forbids, so the host bits come
    /// from a generator the caller owns. It is read only on a miss: a second
    /// `get` for a key already in the table draws nothing at all.
    ///
    /// The bits have to be unpredictable in production, which is upstream's
    /// reason for drawing them at all (`mapped_addrs.rs:63`): a peer that can
    /// guess a live address can address a path it was never given. A caller
    /// that wants a reproducible test passes a seeded engine instead. Nothing
    /// in this file reaches for entropy on its own.
    pub fn get(
        self: *MappedAddrs,
        gpa: std.mem.Allocator,
        key: Key,
        random: std.Random,
    ) GetError!Ula {
        if (self.by_key.get(key)) |existing| return existing;
        return self.allocate(gpa, key, random);
    }

    /// The key an address belongs to, or `null` for an address this map never
    /// handed out: anything `ula.classify` called a direct path, and a
    /// synthetic address belonging to somebody else's map.
    pub fn lookup(self: *const MappedAddrs, addr: Ula) ?Key {
        return self.by_addr.get(addr);
    }

    /// Draw host bits until one lands on an address the reverse index does not
    /// hold, then record the allocation in both directions.
    ///
    /// Upstream's loop, with a bound. An unbounded retry over entropy the
    /// caller supplied is a hang, and a caller whose generator repeats is told
    /// so instead.
    fn allocate(
        self: *MappedAddrs,
        gpa: std.mem.Allocator,
        key: Key,
        random: std.Random,
    ) GetError!Ula {
        const path = pathOf(key);
        var attempts: usize = 0;
        while (attempts < max_generate_attempts) : (attempts += 1) {
            const candidate = ula.ulaFor(path, drawHostBits(random));
            if (self.by_addr.contains(candidate)) continue;
            try self.insert(gpa, key, candidate);
            return candidate;
        }
        return error.HostBitsExhausted;
    }

    /// Record an allocation in both directions, or in neither.
    ///
    /// The reverse index goes in first and comes back out on failure. A
    /// forward entry with no reverse one is the map's one broken state: the
    /// address answers `null` from the direction a departing path uses to find
    /// the peers that care, and nothing anywhere reports it.
    fn insert(
        self: *MappedAddrs,
        gpa: std.mem.Allocator,
        key: Key,
        addr: Ula,
    ) std.mem.Allocator.Error!void {
        try self.by_addr.put(gpa, addr, key);
        errdefer _ = self.by_addr.fetchRemove(addr);
        try self.by_key.put(gpa, key, addr);
    }
};

/// The subnet a key's address sits in. The arm of the key is the whole of it.
fn pathOf(key: Key) ula.Path {
    return switch (key) {
        .any_path => .any_path,
        .relay => .relay,
        .custom => .custom,
    };
}

/// The eight host bits upstream fills from `rand::rng()` (`mapped_addrs.rs:141`,
/// `:202`, `:262`).
fn drawHostBits(random: std.Random) HostBits {
    var host: HostBits = undefined;
    random.bytes(&host);
    return host;
}

/// The host bits of an address this map handed out.
///
/// A caller holding an address and a `TransportAddr` wants the socket address
/// the QUIC stack takes, and `ula.syntheticSocketAddr` wants the host bits
/// rather than the whole address. Without this the octet split would be
/// repeated at every call site, and it is `ula`'s business, not the caller's.
pub fn hostBitsOf(addr: Ula) HostBits {
    return addr[8..16].*;
}

const t = std.testing;

/// Two host values, so a test can say which draw it got.
const host_a: HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
const host_b: HostBits = .{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

/// A key from a fixed seed, so a test names the same node on every run.
///
/// The only failure `fromSeed` has is a degenerate seed, and finding one takes
/// a specific byte pattern rather than any uniform fill. It is propagated
/// anyway: a test that cannot name the node it meant to name is a failing
/// test, and it fails as one here rather than taking the binary with it.
fn testNodeId(seed: u8) base_key.KeyError!NodeId {
    return (try base_key.SecretKey.fromSeed(@splat(seed))).nodeId();
}

/// Compare two keys the way the map does, failing the test rather than the
/// runner when a lookup answers nothing. `KeyContext.eql` is the definition
/// of key sameness here, and `==` is not: `RelayUrl.parse` leaves everything
/// past the host unwritten, so two equal relay URLs from two calls can differ
/// in bytes no comparison of a key is allowed to look at.
fn expectSameKey(want: Key, got: ?Key) !void {
    // The address under test came out of this map, so a null answer is a
    // failed assertion and not a reason to take the test binary with it.
    const found = got orelse return error.TestUnexpectedResult;
    try t.expect(KeyContext.eql(.{}, want, found));
}

/// A generator that walks a fixed script of host values and then repeats its
/// last entry forever.
///
/// The repetition is the point: a real generator does not do it, and it is
/// what puts `max_generate_attempts` within reach of a test.
const ScriptedBits = struct {
    script: []const HostBits,
    at: usize = 0,
    drawn: usize = 0,

    fn fill(self: *ScriptedBits, buf: []u8) void {
        std.debug.assert(buf.len == @sizeOf(HostBits));
        const step = @min(self.at, self.script.len - 1);
        self.at = step + 1;
        self.drawn += 1;
        @memcpy(buf, &self.script[step]);
    }

    fn random(self: *ScriptedBits) std.Random {
        std.debug.assert(self.script.len > 0);
        return std.Random.init(self, fill);
    }
};

test "one key is allocated once, however often it is asked" {
    var script: ScriptedBits = .{ .script = &.{ host_a, host_b } };
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const path_key: Key = .{ .any_path = try testNodeId(1) };
    const first = try map.get(t.allocator, path_key, script.random());
    const second = try map.get(t.allocator, path_key, script.random());
    try t.expectEqual(first, second);
    try t.expectEqual(host_a, hostBitsOf(first));

    // The generator was read once. A map that drew per call would have taken
    // the second entry and answered with a different address.
    try t.expectEqual(@as(usize, 1), script.drawn);
}

test "a candidate the reverse index holds is drawn again, not handed out twice" {
    var script: ScriptedBits = .{ .script = &.{ host_a, host_a, host_b } };
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const one: Key = .{ .any_path = try testNodeId(1) };
    const two: Key = .{ .any_path = try testNodeId(2) };
    const first = try map.get(t.allocator, one, script.random());
    const second = try map.get(t.allocator, two, script.random());

    try t.expect(!std.mem.eql(u8, &first, &second));
    try t.expectEqual(host_a, hostBitsOf(first));
    try t.expectEqual(host_b, hostBitsOf(second));
    // One wasted draw, and not one more.
    try t.expectEqual(@as(usize, 3), script.drawn);
    try expectSameKey(one, map.lookup(first));
    try expectSameKey(two, map.lookup(second));
}

test "an address that arrives off the wire names the key that owns it" {
    const url = try base_addr.RelayUrl.parse("https://use1-1.relay.iroh.network./");
    const path_key: Key = .{ .relay = .{ .relay = url, .node = try testNodeId(1) } };
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const allocated = try map.get(t.allocator, path_key, prng.random());
    // The address as the QUIC stack carries it, and back out of the wire.
    const socket = ula.syntheticSocketAddr(.{ .relay = url }, hostBitsOf(allocated));
    try t.expectEqual(ula.Classification{ .relay = allocated }, ula.classify(socket));
    try expectSameKey(path_key, map.lookup(allocated));
}

test "an address the map never handed out has no key" {
    var prng: std.Random.DefaultPrng = .init(1);
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const live = try map.get(
        t.allocator,
        .{ .any_path = try testNodeId(1) },
        prng.random(),
    );
    try t.expect(map.lookup(live) != null);
    // Same subnet, same peer, one bit of the host value different. All 16
    // octets key the reverse index, so a near miss reads as unknown rather
    // than as a live address one bit away.
    var near = live;
    near[15] ^= 1;
    try t.expect(map.lookup(near) == null);
}

test "a generator that repeats forever is refused, and the map keeps working" {
    var stuck: ScriptedBits = .{ .script = &.{host_a} };
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const one: Key = .{ .any_path = try testNodeId(1) };
    const two: Key = .{ .any_path = try testNodeId(2) };
    // The first draw is free: nothing holds it yet.
    const first = try map.get(t.allocator, one, stuck.random());
    try t.expectEqual(host_a, hostBitsOf(first));

    // Every draw after that is a repeat. Upstream loops here forever.
    try t.expectError(error.HostBitsExhausted, map.get(t.allocator, two, stuck.random()));
    try t.expectEqual(@as(usize, 1 + max_generate_attempts), stuck.drawn);

    // The refusal left the map as it was: the first key still answers, the
    // second is still unknown, and neither table grew.
    try t.expectEqual(first, try map.get(t.allocator, one, stuck.random()));
    try t.expect(map.by_key.get(two) == null);
    try t.expectEqual(@as(u32, 1), map.by_key.count());
    try t.expectEqual(@as(u32, 1), map.by_addr.count());

    // And a map whose generator moves again takes the key that was refused,
    // with the two tables still holding the same number of entries.
    var script: ScriptedBits = .{ .script = &.{host_b} };
    const second = try map.get(t.allocator, two, script.random());
    try t.expectEqual(host_b, hostBitsOf(second));
    try expectSameKey(one, map.lookup(first));
    try expectSameKey(two, map.lookup(second));
    try t.expectEqual(@as(u32, 2), map.by_key.count());
    try t.expectEqual(@as(u32, 2), map.by_addr.count());
}

test "the same injected sequence allocates the same addresses" {
    // What makes this testable at all: no clock, no environment, no global
    // generator, and therefore the same addresses on every run. Two engines
    // seeded alike are the same sequence.
    const keys = [_]Key{
        .{ .any_path = try testNodeId(1) },
        .{ .relay = .{
            .relay = try base_addr.RelayUrl.parse("https://a.example./"),
            .node = try testNodeId(2),
        } },
        .{ .custom = try CustomKey.from(.{ .id = 0x2a, .data = &.{ 0xab, 0xcd } }) },
    };

    var first_map: MappedAddrs = .init();
    defer first_map.deinit(t.allocator);
    var second_map: MappedAddrs = .init();
    defer second_map.deinit(t.allocator);
    var first_prng: std.Random.DefaultPrng = .init(0x5eed);
    var second_prng: std.Random.DefaultPrng = .init(0x5eed);

    for (keys) |path_key| {
        const first = try first_map.get(t.allocator, path_key, first_prng.random());
        const second = try second_map.get(t.allocator, path_key, second_prng.random());
        try t.expectEqual(first, second);
        try expectSameKey(path_key, first_map.lookup(first));
    }
}

test "the three key arms are three addresses even on one host value" {
    // The same node id, and the same eight host bits, in all three subnets.
    // The subnet discriminator is the only thing that differs, so it is the
    // only thing that can keep these apart.
    var script: ScriptedBits = .{ .script = &.{ host_a, host_a, host_a } };
    var map: MappedAddrs = .init();
    defer map.deinit(t.allocator);

    const keys = [_]Key{
        .{ .any_path = try testNodeId(1) },
        .{ .relay = .{
            .relay = try base_addr.RelayUrl.parse("https://a.example./"),
            .node = try testNodeId(1),
        } },
        .{ .custom = try CustomKey.from(.{ .id = 0x2a, .data = &.{ 0xab, 0xcd } }) },
    };
    for (keys) |path_key| {
        const allocated = try map.get(t.allocator, path_key, script.random());
        try t.expectEqual(host_a, hostBitsOf(allocated));
        const socket: base_addr.SocketAddr = .{
            .ip = .{ .v6 = allocated },
            .port = ula.mapped_port,
        };
        // Arm and octets together, so an address that classified into the
        // right subnet with the wrong bytes would still fail here.
        const want: ula.Classification = switch (path_key) {
            .any_path => .{ .any_path = allocated },
            .relay => .{ .relay = allocated },
            .custom => .{ .custom = allocated },
        };
        try t.expectEqual(want, ula.classify(socket));
    }
    // Three draws and no retry: a repeat of the host value in another subnet
    // is a different address, so the reverse index did not refuse it.
    try t.expectEqual(@as(usize, 3), script.drawn);
}

test "a custom key owns its bytes rather than borrowing them" {
    var scratch: [base_addr.max_inline_length]u8 = undefined;
    const parsed = try base_addr.CustomAddr.parse("2a_abab", &scratch);
    const owned = try CustomKey.from(parsed);
    try t.expectEqual(@as(u8, 0x2a), owned.id);
    try t.expectEqual(@as(u8, 2), owned.data_length);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, owned.dataSlice());

    // Scrambling the parse buffer changes nothing, which is the whole reason
    // the key is a copy and not the borrow it came from.
    @memset(&scratch, 0xff);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, owned.dataSlice());
}

test "a custom address too large to own is refused, not truncated" {
    const too_long = [_]u8{0} ** (base_addr.max_inline_length + 1);
    const overlong: CustomAddr = .{ .id = 1, .data = &too_long };
    try t.expectError(error.DataTooLong, CustomKey.from(overlong));
}

test "a custom address too long for the length byte is refused, not a trap" {
    // One past what a `u8` holds, so the refusal comes from the cast rather
    // than from the ceiling. A bare `@intCast` here panics in Debug instead,
    // which is a crash the caller cannot catch and this function can.
    const far_too_long = [_]u8{0} ** (@as(usize, std.math.maxInt(u8)) + 1);
    const overlong: CustomAddr = .{ .id = 1, .data = &far_too_long };
    try t.expectError(error.DataTooLong, CustomKey.from(overlong));
}
