//! Consumer tests for `dial_source_walk.zig`, with a real QUIC dialer and
//! caller-supplied discovery answers, time and entropy.
//!
//! The merge winner is observed through the destination of its first outgoing
//! datagrams, without forwarding them to a fabricated peer. The other cases
//! distinguish empty answers, unavailable services and retrieval cancellation.
//! Relay routes are not used to identify a winning URL: they share a virtual
//! endpoint address so the connection can later select a physical path.
//!
//! `src/root.zig` and `src/portable_test.zig` register these tests through
//! `std.testing.refAllDecls`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const resolve = @import("resolve.zig");
const addr_map = @import("../transport/addr_map.zig");
const dial = @import("../transport/dial.zig");
const walk = @import("dial_source_walk.zig");

const t = std.testing;
const key = @import("../base/key.zig");
const dns = @import("dns.zig");
const quic_bridge = @import("../transport/quic_bridge.zig");

/// Fixed seeds, so a run draws the same connection ids, the same nonces and
/// the same synthetic host bits every time.
const client_seed: [key.SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [key.SecretKey.seed_length]u8 = @splat(0x53);

/// The one ALPN both ends speak.
const alpn = "ozai";

const at_instant: dial.Instant = 1_000 * std.time.ns_per_s;

/// A seeded generator's engine. `std.Random` is an interface over a pointer to
/// an engine, so the engine outlives every value handed out from it.
const Prng = std.Random.DefaultPrng;

/// The largest datagram a socket read is expected to hold.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too small.
const max_egress = 32;

/// The address this node's socket is bound to, so the address the peer sees
/// the dialled connection come from. A direct one, which is why the receiving
/// end needs no map entry to attribute it.
const local_addr: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 40001 };

/// Two bridges, one dialer and the map they share: the smallest thing a run
/// can be observed against.
///
/// One map for both ends, as `transport/dial.zig`'s own harness does it, so a
/// synthetic address the dialler allocated is one the receiving end can name.
/// The rest is duplicated rather than borrowed because that harness is private
/// to a file this milestone does not change.
const Harness = struct {
    client: *quic_bridge.Bridge,
    server: *quic_bridge.Bridge,
    dialer: *dial.Dialer,
    map: addr_map.MappedAddrs,
    client_secret: key.SecretKey,
    server_secret: key.SecretKey,

    fn init(self: *Harness, engine: *Prng) !void {
        self.* = .{
            .client = undefined,
            .server = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .client_secret = try key.SecretKey.fromSeed(client_seed),
            .server_secret = try key.SecretKey.fromSeed(server_seed),
        };
        errdefer self.client_secret.deinit();
        errdefer self.server_secret.deinit();
        errdefer self.map.deinit(t.allocator);
        // The server pins the client, so a handshake this run opens is
        // verified against a peer that exists rather than against nothing.
        self.client = try quic_bridge.Bridge.create(t.allocator, t.io, .{
            .secret = self.client_secret,
            .expect_peer = null,
            .alpn = alpn,
        }, engine.random());
        errdefer self.client.destroy();
        self.server = try quic_bridge.Bridge.create(t.allocator, t.io, .{
            .secret = self.server_secret,
            .expect_peer = self.client_secret.nodeId(),
            .alpn = alpn,
        }, engine.random());
        errdefer self.server.destroy();
        self.dialer = try dial.Dialer.create(t.allocator, self.client, .{
            .secret = self.client_secret,
            .alpn = alpn,
        });
    }

    /// Take every dialled connection out of the table and free it, then the
    /// dialer, then the bridges.
    ///
    /// `Dialer.destroy` refuses while a connection it opened is still in the
    /// table. The walk below takes every client entry out of it first, so a
    /// refusal is not a path this expects — but that is a claim about a live
    /// table rather than about a constant, and a table that disagreed would
    /// leave the dialer's seed, chain and ALPN freed under a connection still
    /// reading them. `defer` has nowhere to send an error and `deinit` has no
    /// caller that could act, so the refusal is named here: a teardown that
    /// carried on would report success over a dialer freed too early.
    fn deinit(self: *Harness) void {
        // Backwards: `removeConnection` swap-removes from the list being
        // walked, so a forward walk skips an entry and leaves a freed one in
        // the table for `Dialer.destroy` to refuse.
        var index = self.client.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.client.manager.entries.items[index];
            if (!entry.conn.is_server) self.client.manager.removeConnection(entry);
        }
        self.client.sweep();
        self.dialer.destroy() catch |err| switch (err) {
            error.DialedConnectionsLive => std.debug.panic(
                "a dialled connection outlived the dialer that opened it",
                .{},
            ),
        };
        self.client.destroy();
        self.server.destroy();
        self.map.deinit(t.allocator);
        self.client_secret.deinit();
        self.server_secret.deinit();
        // Invalid rather than merely freed. The harness is a test's whole
        // world, and a second teardown over bridges that are already gone
        // would be a use-after-free reported as a mystery rather than as the
        // mistake it is. `secureZero` above has already run, so this erases
        // nothing it was there to erase.
        self.* = undefined;
    }
};

/// A run's request, with the policy this test does not care about: the first
/// address of a sorted list, which is a choice and not a rule.
fn requestAt(harness: *Harness, engine: *Prng) walk.Request {
    return .{
        .node_id = harness.server_secret.nodeId(),
        .local = local_addr,
        .map = &harness.map,
        // The harness outlives the call and the policy reads none of it, so it
        // is the one pointer there is always in hand.
        .select = .{ .ctx = @ptrCast(@alignCast(harness)), .pick = firstAddress },
        .at = at_instant,
        .random = engine.random(),
    };
}

fn firstAddress(_: *anyopaque, endpoint: *const addr.NodeAddr) ?addr.TransportAddr {
    return if (endpoint.addrs.len == 0) null else endpoint.addrs[0];
}

/// The retrieval `discovery/resolve.zig` deliberately does not build, as a
/// value: signed-packet bytes in, a `Packet` out.
///
/// `answers` is NUL-separated because each answer is a whole signed packet,
/// which is `resolve.PacketSource`'s own contract and the reason the two
/// services can share a buffer shape.
const FakeRelay = struct {
    answers: []const u8,
    packets: []const resolve.Packet,
    /// Which answer is being decoded, so a second resolve against one relay
    /// walks the same answer set from its start the way a fresh retrieval
    /// would.
    cursor: usize = 0,
    /// The only bytes this relay knows. Anything else is a malformed packet,
    /// which is how a decode failure is reached.
    good: []const u8 = "signed",

    fn decode(ctx: *anyopaque, packet: []const u8) resolve.DecodeError!resolve.Packet {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, packet, self.good)) return error.MalformedPacket;
        const at = self.cursor;
        self.cursor += 1;
        if (at >= self.packets.len) return error.MalformedPacket;
        return self.packets[at];
    }

    fn source(self: *FakeRelay, cancellation: ?resolve.Cancellation) resolve.PacketSource {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .decode = decode,
            .answers = .init(self.answers),
            .cancellation = cancellation,
        };
    }
};

/// A retrieval handle that only counts, which is the whole of what a test can
/// observe about a cancellation. The count lives outside the service on
/// purpose: a service that counted its own stops would be asserting that it
/// asked itself to stop.
const Counter = struct {
    stops: u32 = 0,

    fn stop(ctx: *anyopaque) void {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.stops += 1;
    }

    fn cancellation(self: *Counter) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stop };
    }
};

/// A service with a counter in front of it, so "was this one asked" is
/// something a test reads rather than something it infers from what came back.
const Counted = struct {
    inner: resolve.AddressLookup,
    asked: u32 = 0,
    vtable: resolve.AddressLookup.VTable = counted_vtable,

    fn init(inner: resolve.AddressLookup) Counted {
        return .{ .inner = inner };
    }

    fn lookup(self: *Counted) resolve.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const counted_vtable: resolve.AddressLookup.VTable = .{
    .publish = resolve.AddressLookup.ignore_publish,
    .resolve = countedResolve,
};

fn countedResolve(
    ctx: *anyopaque,
    // The order is `AddressLookup.VTable.resolve`'s own, and a vtable entry's
    // signature is the interface's to fix: moving the allocator first would
    // change the type every service in the tree implements.
    // ziglint-ignore: Z023
    alloc: std.mem.Allocator,
    node_id: addr.NodeId,
) resolve.ResolveError!?resolve.Stream {
    const self: *Counted = @ptrCast(@alignCast(ctx));
    self.asked += 1;
    return self.inner.resolve(alloc, node_id);
}

/// A service whose work never starts. `resolve.ResolveError` has one arm, and
/// this is how a caller meets it: a real service's `OutOfMemory` arrives
/// exactly this way, with the sources before it already holding streams.
const Unstartable = struct {
    asked: u32 = 0,
    vtable: resolve.AddressLookup.VTable,

    fn init() Unstartable {
        var self: Unstartable = .{ .asked = 0, .vtable = undefined };
        self.vtable = .{
            .publish = resolve.AddressLookup.ignore_publish,
            .resolve = refuseStart,
        };
        return self;
    }

    fn lookup(self: *Unstartable) resolve.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

fn refuseStart(
    ctx: *anyopaque,
    // `AddressLookup.VTable.resolve`'s parameter order, for the reason
    // `countedResolve` above gives. Only the answer is this file's.
    // ziglint-ignore: Z023
    _: std.mem.Allocator,
    _: addr.NodeId,
) resolve.ResolveError!?resolve.Stream {
    const self: *Unstartable = @ptrCast(@alignCast(ctx));
    self.asked += 1;
    return error.OutOfMemory;
}

test "the merge chooses the destination of the dial's outgoing datagrams" {
    var engine: Prng = Prng.init(1);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // Distinct direct destinations make the selected address observable at the
    // send boundary. A relay URL cannot do that: relay routes for one peer
    // deliberately share its virtual endpoint address.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("addr=192.0.2.2:9002\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var service = dns.DnsAddressLookup.init(
        .init("addr=192.0.2.1:9001\x00"),
        null,
    );
    var named_one = Counted.init(service.lookup());
    var named_two = Counted.init(resolver.lookup());
    const sources = [_]resolve.AddressLookup{ named_one.lookup(), named_two.lookup() };

    const outcome = try walk.dialFromSources(
        t.allocator,
        &sources,
        harness.dialer,
        requestAt(&harness, &engine),
    );

    // A walk that stops at the first answer sends to the wrong destination.
    try t.expectEqual(@as(u32, 1), named_one.asked);
    try t.expectEqual(@as(u32, 1), named_two.asked);
    try t.expect(outcome.first_failure == null);

    const dialled = switch (outcome.result) {
        .dialed => |value| value,
        else => return error.ExpectedADial,
    };
    try t.expectEqual(item.Provenance.pkarr, dialled.provenance);

    // The stream the answer came out of is closed before the run returns, so
    // nothing in the result is a slice into an arena that has just been
    // emptied.
    try t.expectEqual(@as(u32, 1), stops.stops);

    const expected: addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 192, 0, 2, 2 } },
        .port = 9002,
    };
    var egress: [max_egress]quic_bridge.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    const sends = try dialled.dial.conn.drain(&egress, &out, at_instant, engine.random());
    try t.expect(sends.len != 0);
    for (sends) |send| {
        try t.expectEqual(expected, send.to);
        try t.expect(send.send.contents.len != 0);
    }
}

test "a service that will not resolve stops the walk where it made its claim" {
    var engine: Prng = Prng.init(2);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // Upstream's publisher implements no `resolve`
    // (`iroh/src/address_lookup/pkarr.rs:357`), so this is a service in
    // ordinary production and not a double invented to make this test pass.
    var publisher = resolve.PkarrPublisher.init();
    defer publisher.deinit();
    var refusing = Counted.init(publisher.lookup());

    // A relay that would have answered with an address, so the refusal is
    // shown to cost an answer rather than to describe a node nobody has.
    var first_stops: Counter = .{};
    var first_relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("addr=192.0.2.9:9999\x00") }},
    };
    var first_resolver = resolve.PkarrResolver.init(
        first_relay.source(first_stops.cancellation()),
    );
    var answering = Counted.init(first_resolver.lookup());

    // The refusal first: the walk ends there, and the service behind it is
    // never asked, so there is no retrieval to cancel and no answer to lose.
    const refused = [_]resolve.AddressLookup{ refusing.lookup(), answering.lookup() };
    const stopped = try walk.dialFromSources(
        t.allocator,
        &refused,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(stopped.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 1), refusing.asked);
    try t.expectEqual(@as(u32, 0), answering.asked);
    try t.expectEqual(@as(u32, 0), first_stops.stops);

    // The same two services the other way round: the walk reads the answering
    // one to the end and *then* stops on the claim, and the retrieval behind
    // the read one is stopped. Two different orders, one answer, and the
    // difference between them is which service was asked.
    const after = [_]resolve.AddressLookup{ answering.lookup(), refusing.lookup() };
    const stopped_after = try walk.dialFromSources(
        t.allocator,
        &after,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(stopped_after.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 1), answering.asked);
    try t.expectEqual(@as(u32, 1), first_stops.stops);

    // And that the stream behind it was *read*, not only closed: the relay
    // behind the answering service gave up its one answer. A walk that named
    // the wrong slot of the open list would close both streams just the same
    // and leave this at zero, so the count is what says the walk drove the
    // stream the first source produced.
    try t.expectEqual(@as(usize, 1), first_relay.cursor);
}

test "an answer with nothing in it does not stop the walk" {
    var engine: Prng = Prng.init(3);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // A node that exists and has nowhere to be sent a packet, from the one
    // service that can say so: an answer set with no records is one item, the
    // node, and no addresses.
    var service = dns.DnsAddressLookup.init(.init(""), null);
    var published_nothing = Counted.init(service.lookup());

    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var relayed = Counted.init(resolver.lookup());
    const sources = [_]resolve.AddressLookup{ published_nothing.lookup(), relayed.lookup() };

    const outcome = try walk.dialFromSources(
        t.allocator,
        &sources,
        harness.dialer,
        requestAt(&harness, &engine),
    );

    // The empty answer did not end the run, and the item it did produce lost
    // the merge to an item with an address, so it never reached the policy.
    try t.expectEqual(@as(u32, 1), published_nothing.asked);
    try t.expectEqual(@as(u32, 1), relayed.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    const dialled = switch (outcome.result) {
        .dialed => |value| value,
        else => return error.ExpectedADial,
    };
    try t.expectEqual(item.Provenance.pkarr, dialled.provenance);
}

test "an empty result, an empty address list and a refused path are told apart" {
    var engine: Prng = Prng.init(4);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // A relay that answered with no packets. It was asked, it ran, and the
    // world had nothing in it: no items at all, which is
    // `item.Resolution.isEmptyResult` and not the absence of a service.
    var quiet: FakeRelay = .{ .answers = "", .packets = &.{} };
    var quiet_resolver = resolve.PkarrResolver.init(quiet.source(null));
    var silent = Counted.init(quiet_resolver.lookup());
    const only_quiet = [_]resolve.AddressLookup{silent.lookup()};
    const nothing = try walk.dialFromSources(
        t.allocator,
        &only_quiet,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(nothing.result == .nothing);
    try t.expectEqual(@as(u32, 1), silent.asked);

    // The same absence of addresses said by the other service, which is a
    // different fact: the node was found and it has no path.
    var service = dns.DnsAddressLookup.init(.init(""), null);
    var nameless = Counted.init(service.lookup());
    const only_nameless = [_]resolve.AddressLookup{nameless.lookup()};
    const no_path = try walk.dialFromSources(
        t.allocator,
        &only_nameless,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(no_path.result == .no_address);

    // And a winner this node's policy will not take, which is a fourth thing
    // again: the network named a path and the caller declined it. The run
    // reports it beside the two above rather than as one of them, and no
    // connection is opened.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var answered = Counted.init(resolver.lookup());
    const only_answered = [_]resolve.AddressLookup{answered.lookup()};
    var declined = requestAt(&harness, &engine);
    declined.select = .{ .ctx = @ptrCast(@alignCast(&harness)), .pick = refuseEvery };
    const refused = try walk.dialFromSources(
        t.allocator,
        &only_answered,
        harness.dialer,
        declined,
    );
    try t.expect(refused.result == .no_address);
    try t.expectEqual(@as(u32, 1), answered.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    try t.expectEqual(@as(usize, 0), harness.client.manager.entries.items.len);
}

fn refuseEvery(_: *anyopaque, _: *const addr.NodeAddr) ?addr.TransportAddr {
    return null;
}

test "a run that gives up mid-walk still stops every retrieval it started" {
    var engine: Prng = Prng.init(5);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // The error path. A service that cannot start leaves the streams of the
    // services before it open, and the error escapes; a run that returned
    // before closing them would have cancelled nothing, and the resolve behind
    // a stream nobody holds any more would keep running.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("addr=192.0.2.9:9999\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var answering = Counted.init(resolver.lookup());
    var unstartable = Unstartable.init();
    const failing = [_]resolve.AddressLookup{ answering.lookup(), unstartable.lookup() };
    try t.expectError(
        error.OutOfMemory,
        walk.dialFromSources(
            t.allocator,
            &failing,
            harness.dialer,
            requestAt(&harness, &engine),
        ),
    );
    try t.expectEqual(@as(u32, 1), answering.asked);
    try t.expectEqual(@as(u32, 1), unstartable.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    // Nothing was dialled, so nothing is in the manager to leak.
    try t.expectEqual(@as(usize, 0), harness.client.manager.entries.items.len);

    // And the path where the walk is cut short by a claim rather than by an
    // error: two sources read to the end, then a service that will not
    // resolve. All three are closed, and the two that produced nothing had a
    // retrieval cancelled as well, because a finished resolve has nothing
    // left to cancel and says so rather than skipping the call.
    var quiet_stops: Counter = .{};
    var quiet: FakeRelay = .{ .answers = "", .packets = &.{} };
    var quiet_resolver = resolve.PkarrResolver.init(quiet.source(quiet_stops.cancellation()));
    var silent = Counted.init(quiet_resolver.lookup());
    var publisher = resolve.PkarrPublisher.init();
    defer publisher.deinit();
    const cut_short = [_]resolve.AddressLookup{
        answering.lookup(),
        silent.lookup(),
        publisher.lookup(),
    };
    const outcome = try walk.dialFromSources(
        t.allocator,
        &cut_short,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(outcome.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 2), answering.asked);
    try t.expectEqual(@as(u32, 1), silent.asked);
    try t.expectEqual(@as(u32, 2), stops.stops);
    try t.expectEqual(@as(u32, 1), quiet_stops.stops);
}
