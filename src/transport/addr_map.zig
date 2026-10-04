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
const base_relay_url = @import("../base/relay_url.zig");
const ula = @import("../base/ula.zig");

const NodeId = base_key.NodeId;
const RelayUrl = base_relay_url.RelayUrl;
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
    /// Hash the active key bytes. Unused fixed-buffer tails do not contribute.
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

    /// Compare key contents, ignoring unused bytes in fixed buffers.
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
///
/// Both tables own allocations from the allocator supplied to `get`.
/// Use that same allocator for later mutations and `deinit`.
/// Keys, including custom payloads, are independent copies. Map copies share
/// table storage, so only one copy may mutate or release it. Serialize access.
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
    ///
    /// On error, existing mappings remain unchanged. A failed insertion may
    /// retain table capacity and consume random draws, but records no new key.
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
    const url = try base_relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./");
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
            .relay = try base_relay_url.RelayUrl.parse("https://a.example./"),
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
            .relay = try base_relay_url.RelayUrl.parse("https://a.example./"),
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

/// One key the map was given and the address it answered with.
///
/// Kept together because every assertion about the state a map was in
/// before an operation under test needs both halves, and half a pair is how
/// a map ends up answering a departing path with `null`.
const Entry = struct {
    key: Key,
    addr: Ula,
};

/// Host values, one per entry a filled map holds. Distinct because a repeat
/// inside one subnet is a candidate the reverse index refuses, and a fill
/// built from repeats would spend `max_generate_attempts` on every key after
/// the first. The allocation counts read off such a fill would stop meaning
/// what they say.
const fill_hosts = [_]HostBits{
    .{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .{ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

/// A probe's draw, on a subnet these tests never fill. The first draw lands,
/// so the allocation under test is the first one the key makes.
const first_draw = [_]HostBits{host_a};

/// A probe's draw on the subnet the fill writes into: the host the first
/// fill entry holds, and then one the map does not. The first draw is thrown
/// away by the reverse index, which is the retry loop upstream left
/// unbounded, and the allocation under test is the second draw's.
const colliding_draws = [_]HostBits{ fill_hosts[0], host_a };

/// One key family and the address a single draw allocates for it.
const Probe = struct {
    key: Key,
    allocated: Ula,
};

/// The `any_path` family on its own. It is the one the fill writes into, so
/// this is the only family whose draw can be made to land on an address the
/// map already holds.
fn anyPathProbe() !Probe {
    return .{
        .key = .{ .any_path = try testNodeId(7) },
        .allocated = ula.ulaFor(.any_path, host_a),
    };
}

/// One probe per key family, in tag order. Three families are three
/// different entry sizes in the same two tables, and a table that grew for
/// one of them has to grow for the others.
fn probes() ![3]Probe {
    const relay_url = try base_relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./");
    return .{
        try anyPathProbe(),
        .{
            .key = .{ .relay = .{ .relay = relay_url, .node = try testNodeId(8) } },
            .allocated = ula.ulaFor(.relay, host_a),
        },
        .{
            .key = .{ .custom = try CustomKey.from(.{ .id = 0x2a, .data = &.{ 0xab, 0xcd } }) },
            .allocated = ula.ulaFor(.custom, host_a),
        },
    };
}

/// Whether `table` has to grow before it can take one more entry.
///
/// A table with no capacity has no slots at all, which is the one state in
/// which a free-slot count of zero does not mean full. The rest is std's
/// load limit read off the table rather than restated here, so a change to
/// the growth policy changes what these tests fill and not what they expect.
fn needsRoom(comptime Table: type, table: Table) bool {
    return table.capacity() == 0 or table.available != 0;
}

/// Fill both tables until neither has a slot left, writing every entry into
/// `entries` and returning the part of it that was used.
///
/// A map in this state makes the next `put` in either direction allocate,
/// which is the state an insertion has to survive being refused in. The
/// loop is bounded by the caller's buffer and fails rather than truncating:
/// a sweep over half a filled map says nothing about the other half.
fn fillTables(gpa: std.mem.Allocator, map: *MappedAddrs, entries: []Entry) ![]Entry {
    var script: ScriptedBits = .{ .script = &fill_hosts };
    var filled: usize = 0;
    while (needsRoom(Forward, map.by_key) or needsRoom(Reverse, map.by_addr)) {
        if (filled == entries.len) return error.TestUnexpectedResult;
        // One seed per entry, taken from the size of the host script this
        // loop cannot outrun, so the cast into the length byte is inside it.
        const seed: u8 = @intCast(@min(filled + 1, fill_hosts.len));
        const key: Key = .{ .any_path = try testNodeId(seed) };
        entries[filled] = .{ .key = key, .addr = try map.get(gpa, key, script.random()) };
        filled += 1;
    }
    return entries[0..filled];
}

/// Assert that every entry a map was seeded with is still in it, in both
/// directions.
///
/// Separately, because a rollback that took out the wrong one of the pair
/// leaves a map that still answers `get` while the direction a departing
/// path uses to find the peers that care answers `null`. The reads go
/// through the allocator that has just refused everything, so an answer here
/// is also a statement that reading the old state allocates nothing.
fn expectSeededEntries(gpa: std.mem.Allocator, map: *MappedAddrs, entries: []const Entry) !void {
    var script: ScriptedBits = .{ .script = &first_draw };
    for (entries) |seeded| {
        try t.expectEqual(seeded.addr, try map.get(gpa, seeded.key, script.random()));
        try expectSameKey(seeded.key, map.lookup(seeded.addr));
    }
    // Zero draws for `entries.len` answers: a key the map already holds is
    // answered out of the table rather than allocated.
    try t.expectEqual(@as(usize, 0), script.drawn);
}

/// The seeded entries and the size of both tables, for a pass in which the
/// map held nothing else: a refused insertion changed no count in either
/// direction.
fn expectSeededIntact(gpa: std.mem.Allocator, map: *MappedAddrs, entries: []const Entry) !void {
    try expectSeededEntries(gpa, map, entries);
    try t.expectEqual(entries.len, @as(usize, map.by_key.count()));
    try t.expectEqual(entries.len, @as(usize, map.by_addr.count()));
}

/// Assert that nothing of a refused key is visible from either direction.
///
/// The address is checked as well as the key: the reverse entry is the one
/// an insertion writes first and takes back out last, and a rollback that
/// missed it leaves the map answering `null` for a path it answered a moment
/// ago.
fn expectNothingRecorded(map: *const MappedAddrs, key: Key, candidate: Ula) !void {
    try t.expectEqual(@as(?Ula, null), map.by_key.get(key));
    try t.expectEqual(@as(?Key, null), map.lookup(candidate));
}

test "an allocation refused anywhere in an insertion leaves the old mappings exact" {
    for (try probes()) |case| {
        var open: t.FailingAllocator = .init(t.allocator, .{});
        var open_map: MappedAddrs = .init();
        defer open_map.deinit(open.allocator());
        var open_slots: [fill_hosts.len]Entry = undefined;
        const open_seeded = try fillTables(open.allocator(), &open_map, &open_slots);
        // Everything the fill took, so a refusal can be aimed at one of the
        // insertion's own allocations without counting the fill's.
        const first_refused = open.alloc_index;
        var open_script: ScriptedBits = .{ .script = &first_draw };
        const open_addr = try open_map.get(open.allocator(), case.key, open_script.random());
        try t.expectEqual(case.allocated, open_addr);
        const insertions = open.alloc_index - first_refused;
        // Both tables grow on the way in, so there are at least two
        // allocations to refuse and one of them is the forward index failing
        // after the reverse one was reserved. A count below that would leave
        // the rollback the debt record names untested.
        try t.expect(insertions >= 2);
        try t.expect(open_seeded.len > 0);

        var before_reverse: usize = 0;
        var after_reverse: usize = 0;
        for (0..insertions) |at| {
            var failing: t.FailingAllocator = .init(t.allocator, .{
                .fail_index = first_refused + at,
            });
            const gpa = failing.allocator();
            var map: MappedAddrs = .init();
            defer map.deinit(gpa);
            var slots: [fill_hosts.len]Entry = undefined;
            const seeded = try fillTables(gpa, &map, &slots);
            var script: ScriptedBits = .{ .script = &first_draw };
            try t.expectError(error.OutOfMemory, map.get(gpa, case.key, script.random()));

            // The refusal landed exactly where this pass aimed it, and the
            // two ends of it are named by what had already been allocated:
            // nothing is the reverse index never being reserved, and
            // anything above that is a reverse entry taken back out again.
            try t.expectEqual(first_refused + at, failing.allocations);
            if (failing.allocations == first_refused) {
                before_reverse += 1;
            } else {
                after_reverse += 1;
            }

            try expectNothingRecorded(&map, case.key, case.allocated);
            try expectSeededIntact(gpa, &map, seeded);

            // A refused insertion may keep the capacity it grew into, so the
            // bytes come back when the map is freed rather than when the
            // refusal happened. Nothing else was ever allocated.
            map.deinit(gpa);
            try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        // Both ends were reached: the reverse index never reserved, and a
        // reverse entry that had to be taken back out after the forward one
        // failed.
        try t.expect(before_reverse > 0);
        try t.expect(after_reverse > 0);
    }
}

test "an allocation refused anywhere in the first insertion records nothing" {
    for (try probes()) |case| {
        // Nothing in the map yet, so the whole of `get` is its own
        // allocations and the sweep starts at index zero of them.
        var open: t.FailingAllocator = .init(t.allocator, .{});
        var open_map: MappedAddrs = .init();
        defer open_map.deinit(open.allocator());
        var open_script: ScriptedBits = .{ .script = &first_draw };
        const open_addr = try open_map.get(open.allocator(), case.key, open_script.random());
        try t.expectEqual(case.allocated, open_addr);
        try t.expect(open.alloc_index >= 2);

        var before_reverse: usize = 0;
        var after_reverse: usize = 0;
        for (0..open.alloc_index) |at| {
            var failing: t.FailingAllocator = .init(t.allocator, .{ .fail_index = at });
            const gpa = failing.allocator();
            var empty: MappedAddrs = .init();
            defer empty.deinit(gpa);
            var script: ScriptedBits = .{ .script = &first_draw };
            try t.expectError(error.OutOfMemory, empty.get(gpa, case.key, script.random()));
            try t.expectEqual(@as(usize, at), failing.allocations);
            if (failing.allocations == 0) {
                before_reverse += 1;
            } else {
                after_reverse += 1;
            }
            try expectNothingRecorded(&empty, case.key, case.allocated);
            // An empty map grew or did not and holds nothing in either
            // direction, which is what the counts are for: the refusal
            // changed no state a caller can observe.
            try t.expectEqual(@as(u32, 0), empty.by_key.count());
            try t.expectEqual(@as(u32, 0), empty.by_addr.count());
            empty.deinit(gpa);
            try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        try t.expect(before_reverse > 0);
        try t.expect(after_reverse > 0);

        // One allocation past the last one: nothing is refused, the key is
        // recorded, and the address is the one every refusal above was
        // reaching for. `has_induced_failure` says the insertion asked for
        // nothing beyond what it needed, which is what "to success" means.
        var whole: t.FailingAllocator = .init(t.allocator, .{ .fail_index = open.alloc_index });
        var whole_map: MappedAddrs = .init();
        defer whole_map.deinit(whole.allocator());
        var whole_script: ScriptedBits = .{ .script = &first_draw };
        const whole_addr = try whole_map.get(whole.allocator(), case.key, whole_script.random());
        try t.expectEqual(case.allocated, whole_addr);
        try expectSameKey(case.key, whole_map.lookup(case.allocated));
        try t.expect(!whole.has_induced_failure);
        try t.expectEqual(open.alloc_index, whole.alloc_index);
    }
}

test "a draw that collides is thrown away and the next draw is the one refused" {
    const case = try anyPathProbe();

    var open: t.FailingAllocator = .init(t.allocator, .{});
    var open_map: MappedAddrs = .init();
    defer open_map.deinit(open.allocator());
    var open_slots: [fill_hosts.len]Entry = undefined;
    _ = try fillTables(open.allocator(), &open_map, &open_slots);
    const first_refused = open.alloc_index;
    var open_script: ScriptedBits = .{ .script = &colliding_draws };
    const open_addr = try open_map.get(open.allocator(), case.key, open_script.random());
    try t.expectEqual(case.allocated, open_addr);
    try t.expectEqual(@as(usize, 2), open_script.drawn);
    const insertions = open.alloc_index - first_refused;
    try t.expect(insertions >= 2);

    for (0..insertions) |at| {
        var failing: t.FailingAllocator = .init(t.allocator, .{
            .fail_index = first_refused + at,
        });
        const gpa = failing.allocator();
        var map: MappedAddrs = .init();
        defer map.deinit(gpa);
        var slots: [fill_hosts.len]Entry = undefined;
        const seeded = try fillTables(gpa, &map, &slots);
        var script: ScriptedBits = .{ .script = &colliding_draws };
        try t.expectError(error.OutOfMemory, map.get(gpa, case.key, script.random()));
        // Two draws even though the first one was refused: the loop drew
        // again rather than handing out an address that was taken.
        try t.expectEqual(@as(usize, 2), script.drawn);
        try expectNothingRecorded(&map, case.key, case.allocated);
        // The address the first draw landed on still belongs to the key the
        // fill gave it. A retry that evicted it instead of redrawing would
        // leave a live path unanswerable, and this loop is where it would.
        try expectSameKey(seeded[0].key, map.lookup(ula.ulaFor(.any_path, fill_hosts[0])));
        try expectSeededIntact(gpa, &map, seeded);
        map.deinit(gpa);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "a key refused for want of memory is the key the next call records" {
    for (try probes()) |case| {
        var open: t.FailingAllocator = .init(t.allocator, .{});
        var open_map: MappedAddrs = .init();
        defer open_map.deinit(open.allocator());
        var open_slots: [fill_hosts.len]Entry = undefined;
        _ = try fillTables(open.allocator(), &open_map, &open_slots);
        const first_refused = open.alloc_index;
        var open_script: ScriptedBits = .{ .script = &first_draw };
        const open_addr = try open_map.get(open.allocator(), case.key, open_script.random());
        try t.expectEqual(case.allocated, open_addr);
        const insertions = open.alloc_index - first_refused;
        try t.expect(insertions >= 2);

        for (0..insertions) |at| {
            var failing: t.FailingAllocator = .init(t.allocator, .{
                .fail_index = first_refused + at,
            });
            const gpa = failing.allocator();
            var map: MappedAddrs = .init();
            defer map.deinit(gpa);
            var slots: [fill_hosts.len]Entry = undefined;
            const seeded = try fillTables(gpa, &map, &slots);
            var script: ScriptedBits = .{ .script = &first_draw };
            try t.expectError(error.OutOfMemory, map.get(gpa, case.key, script.random()));
            try expectNothingRecorded(&map, case.key, case.allocated);
            try expectSeededIntact(gpa, &map, seeded);

            // The same call again, on the same map, with memory to spend,
            // drawing the value it drew before. The address a refused
            // insertion was reaching for is the address it records next
            // time: a map that answered differently after a refusal would
            // have handed the peer an address it then could not resolve.
            //
            // The retry allocates through the backing allocator rather than
            // the refusing one, so this pass compares no byte totals of its
            // own. The leak check on the backing allocator is what holds it
            // to account here.
            var retry: ScriptedBits = .{ .script = &first_draw };
            try t.expectEqual(case.allocated, try map.get(t.allocator, case.key, retry.random()));
            try expectSameKey(case.key, map.lookup(case.allocated));
            try expectSeededEntries(t.allocator, &map, seeded);
            try t.expectEqual(seeded.len + 1, @as(usize, map.by_key.count()));
            try t.expectEqual(seeded.len + 1, @as(usize, map.by_addr.count()));
        }
    }
}

test "a key the map already holds answers with every allocation refused" {
    var setup: t.FailingAllocator = .init(t.allocator, .{});
    const gpa = setup.allocator();
    var map: MappedAddrs = .init();
    defer map.deinit(gpa);
    // One key of every family, recorded while the map is empty, so the
    // addresses below are the ones a single draw allocates.
    var held: [3]Entry = undefined;
    for (try probes(), 0..) |case, at| {
        var script: ScriptedBits = .{ .script = &first_draw };
        const addr = try map.get(gpa, case.key, script.random());
        try t.expectEqual(case.allocated, addr);
        held[at] = .{ .key = case.key, .addr = addr };
    }

    // From here on the first allocation is refused and every one after it,
    // and the three keys still answer with the addresses they were given,
    // in both directions. A hit reads the table the key is already in;
    // there is nothing to allocate, which is the only reason these answer
    // at all.
    var blocked: t.FailingAllocator = .init(t.allocator, .{ .fail_index = 0 });
    const blocked_gpa = blocked.allocator();
    var script: ScriptedBits = .{ .script = &first_draw };
    for (held) |known| {
        try t.expectEqual(known.addr, try map.get(blocked_gpa, known.key, script.random()));
        try expectSameKey(known.key, map.lookup(known.addr));
    }
    try t.expectEqual(@as(usize, 0), script.drawn);
    // Nothing was even asked for, which is stronger than nothing succeeding.
    try t.expect(!blocked.has_induced_failure);
}

test "a custom key recorded before a refused insertion still owns its bytes" {
    // The lifetime half of `CustomKey`: an entry the parse buffer pointed
    // into is read back out of the map after the buffer is dead, so a key
    // that borrowed would answer with whatever the next frame wrote there.
    var scratch: [base_addr.max_inline_length]u8 = undefined;
    const borrowed = try base_addr.CustomAddr.parse("2a_abab", &scratch);
    const recorded: Key = .{ .custom = try CustomKey.from(borrowed) };
    const refused_payload: base_addr.CustomAddr = .{ .id = 0x2b, .data = &.{ 0x01, 0x02 } };
    const refused: Key = .{ .custom = try CustomKey.from(refused_payload) };
    const recorded_addr = ula.ulaFor(.custom, host_b);
    const refused_addr = ula.ulaFor(.custom, host_a);

    var open: t.FailingAllocator = .init(t.allocator, .{});
    var open_map: MappedAddrs = .init();
    defer open_map.deinit(open.allocator());
    var open_record: ScriptedBits = .{ .script = &[_]HostBits{host_b} };
    const open_recorded = try open_map.get(open.allocator(), recorded, open_record.random());
    try t.expectEqual(recorded_addr, open_recorded);
    var open_slots: [fill_hosts.len]Entry = undefined;
    _ = try fillTables(open.allocator(), &open_map, &open_slots);
    const first_refused = open.alloc_index;
    var open_script: ScriptedBits = .{ .script = &first_draw };
    const open_refused = try open_map.get(open.allocator(), refused, open_script.random());
    try t.expectEqual(refused_addr, open_refused);
    const insertions = open.alloc_index - first_refused;
    try t.expect(insertions >= 2);

    for (0..insertions) |at| {
        var failing: t.FailingAllocator = .init(t.allocator, .{
            .fail_index = first_refused + at,
        });
        const gpa = failing.allocator();
        var map: MappedAddrs = .init();
        defer map.deinit(gpa);
        var record: ScriptedBits = .{ .script = &[_]HostBits{host_b} };
        try t.expectEqual(recorded_addr, try map.get(gpa, recorded, record.random()));
        var slots: [fill_hosts.len]Entry = undefined;
        const seeded = try fillTables(gpa, &map, &slots);
        // The frame the address was parsed into is gone before the operation
        // under test runs. Anything the map still holds had to be a copy.
        @memset(&scratch, 0xff);

        var script: ScriptedBits = .{ .script = &first_draw };
        try t.expectError(error.OutOfMemory, map.get(gpa, refused, script.random()));

        const found = map.lookup(recorded_addr) orelse return error.TestUnexpectedResult;
        switch (found) {
            .custom => |custom| {
                try t.expectEqual(@as(u8, 0x2a), custom.id);
                try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, custom.dataSlice());
            },
            else => return error.TestUnexpectedResult,
        }
        try expectNothingRecorded(&map, refused, refused_addr);
        // The seeded entries and the custom key recorded above, and neither
        // table grew by the key that was refused.
        try expectSeededEntries(gpa, &map, seeded);
        try t.expectEqual(seeded.len + 1, @as(usize, map.by_key.count()));
        try t.expectEqual(seeded.len + 1, @as(usize, map.by_addr.count()));
        map.deinit(gpa);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
