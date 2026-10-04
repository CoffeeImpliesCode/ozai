//! Upstream's `PkarrResolver`, and the `PacketSource` it reads.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published):
//! `PkarrResolver` at `iroh/src/address_lookup/pkarr.rs:536`. It implements
//! `resolve` and not `publish`, so it takes
//! `resolve.AddressLookup.ignore_publish` for the other method — publishing is
//! `resolve_publish.zig`'s job, and a resolver that also published would make
//! "what this node is reachable at" and "what the network says about that
//! node" the same value.
//!
//! # Where the seam is, and what is not in it
//!
//! Nothing here fetches. A resolver is handed an answer set that something else
//! already retrieved, together with a handle to that retrieval, which is how a
//! caller cancels without this file ever learning what a socket is: that
//! retrieval is `PacketSource`, and `discovery/lookup_io.zig` is the one thing
//! in the tree that builds a real one.
//!
//! # Where the answers stop
//!
//! Decoding a signed packet is `discovery/pkarr.zig`'s, and turning the records
//! that come out of one into an `Item` is `resolve_record.zig`'s. So the only
//! coupling between this file and either is a function pointer and an error set,
//! which is what `PacketSource.decode` and `resolve.Reason` are for.
//!
//! Every stream test for the interface at large lives here rather than beside
//! the interface, because `FakeRelay` is a `PacketSource` and this is the file
//! that reads one. The interface's own contract — one `deinit` per stream, on
//! every path out of a resolve — is exercised through this service because it
//! is the only one in the tree that produces a stream.

const std = @import("std");
const key = @import("../base/key.zig");
const item = @import("item.zig");
const node_addr = @import("../base/node_addr.zig");
const relay_url = @import("../base/relay_url.zig");
const publish = @import("resolve_publish.zig");
const resolve = @import("resolve.zig");
const record = @import("resolve_record.zig");

/// The names the service's own body is written in, spelled once so that a
/// reader can see which of the two siblings each obligation belongs to: the
/// vtable and the error set are the interface's, and the records are the
/// grammar's.
const AddressLookup = resolve.AddressLookup;
const Cancellation = resolve.Cancellation;
const DecodeError = resolve.DecodeError;
const Event = resolve.Event;
const ResolveError = resolve.ResolveError;
const Stream = resolve.Stream;
const failed = resolve.failed;

const parseTxt = record.parseTxt;
const RecordSet = record.RecordSet;

/// One signed pkarr packet, as a resolver needs it.
///
/// A value: `node_id` is fixed-size and `txt` is a position in somebody else's
/// buffer. Nothing here is released, and a `Packet` is valid for as long as the
/// bytes `PacketSource.decode` read it out of — which is why that callback may
/// not decode into scratch it reuses before the pull that asked for it ends.
pub const Packet = struct {
    /// Who signed it, which *is* the node being published: upstream reads the
    /// id out of the packet's own public key (`iroh-dns/src/endpoint_info.rs`,
    /// `from_pkarr_signed_packet`).
    node_id: key.NodeId,
    /// The `_iroh` records, in whatever order the packet listed them. The
    /// `_iroh` name filter is already applied and the character strings of one
    /// record are already concatenated: upstream reads them with
    /// `packet.txt_records(IROH_TXT_NAME)`, and a pkarr packet's records are
    /// DNS records, whose multiple character strings are one value
    /// (`iroh/src/address_lookup/dns.rs:35`: "If a TXT record contains multiple
    /// character strings, they are concatenated first"). The concatenation is a
    /// DNS-layer fact and the same one `discovery/dns.zig` relies on, so neither
    /// service does it.
    ///
    /// Borrowed from the packet bytes, positioned at its first record; a copy is
    /// how two readers share one buffer without stepping on each other.
    txt: RecordSet,
};
/// and a source shared across threads has to be safe to call that way.
pub const PacketSource = struct {
    /// The source's own value, borrowed and reached by `decode`. It has to stay
    /// alive until every stream reading this source is closed.
    ctx: *anyopaque,
    /// Signed-packet bytes to what they say. This function is
    /// `discovery/pkarr.zig`'s and nothing in this file is; a resolver calls it
    /// and turns its answer into either a `Packet` or a `DecodeError`, and that
    /// mapping is the whole of the coupling between the two files.
    ///
    /// Called once per answer, synchronously, inside the `Stream.next` that
    /// walks to it and on that call's thread. `packet` borrows `answers` and is
    /// live for the call only; the returned `Packet.txt` may borrow it, so a
    /// source that decodes out of a scratch buffer cannot hand one back that
    /// outlives the pull. Nothing here reenters the stream being pulled, and
    /// `error.MalformedPacket` and `error.BadSignature` lose that one answer
    /// rather than the stream.
    decode: *const fn (ctx: *anyopaque, packet: []const u8) DecodeError!Packet,
    /// The answers, already retrieved, concatenated and NUL-separated. The
    /// first NUL ends one packet and the second starts the next, which is why
    /// each answer is a whole signed packet and a packet may hold several
    /// `_iroh` records of its own.
    ///
    /// Borrowed, and read from the position this value holds: a resolver copies
    /// it per resolve so two streams cannot tread on each other's place in the
    /// buffer, but both copies point at the same bytes, which therefore have to
    /// stay valid and unchanged until the last of those streams is closed.
    answers: RecordSet,
    /// How to stop the retrieval. Null when there was none — an answer set read
    /// out of a file has nothing to cancel — and a stream with a null one still
    /// runs and still frees; it simply tells nobody to stop. Non-null is fired
    /// exactly once per stream, from `Stream.deinit`, so the handle it points at
    /// has to outlive every stream started here.
    cancellation: ?Cancellation,
};
/// `PkarrResolver`: the service that only resolves.
///
/// Upstream's `PkarrResolver` implements `resolve` and not `publish`
/// (`iroh/src/address_lookup/pkarr.rs:536`), so it takes
/// `AddressLookup.ignore_publish`. Publishing is somebody else's job, and a
/// resolver that also published would make "what this node is reachable at" and
/// "what the network says about that node" the same value.
///
/// Copying the service copies the borrowed source and the vtable, so a copy is
/// a second handle onto one answer set and not a second retrieval.
pub const PkarrResolver = struct {
    /// The answers and the handle to the retrieval behind them, both borrowed.
    /// Every stream started against this resolver reads them, so they have to
    /// outlive all of those streams.
    source: PacketSource,
    /// Borrowed by every `AddressLookup` handed out of `lookup`.
    vtable: AddressLookup.VTable = resolver_vtable,

    /// A resolver over one already-retrieved answer set.
    pub fn init(source: PacketSource) PkarrResolver {
        return .{ .source = source };
    }

    /// A handle onto this resolver. Borrowed, so the resolver has to outlive
    /// every stream started through the handle.
    pub fn lookup(self: *PkarrResolver) AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};
const resolver_vtable: AddressLookup.VTable = .{
    .publish = AddressLookup.ignore_publish,
    .resolve = resolverResolve,
};
const PkarrState = struct {
    parent: *const PkarrResolver,
    /// The arena every item this stream produces lives in. See `parseTxt` on
    /// why a resolver needs one: an item owns a `NodeAddr` *and* the bytes
    /// behind any custom address in it, and a `NodeAddr` has nowhere to keep
    /// the second. One arena for the whole stream means `destroy` is one call
    /// and no item can outlive it by accident.
    arena: std.heap.ArenaAllocator,
    /// `arena.allocator()`, taken after the state reached its final address:
    /// the allocator hands back the arena's own address, and that address must
    /// not move while the allocator is in use.
    alloc: std.mem.Allocator,
    /// The node the caller asked about, held because a packet is only an answer
    /// if it was signed by it. See `Reason.UnexpectedSigner`.
    node_id: key.NodeId,
    /// The service's answer set, by value: two resolves against one service
    /// each get their own position in the buffer.
    answers: RecordSet,
    /// The item being handed over. It walks forward one at a time, so a caller
    /// that abandons the stream leaves the rest of the answers undecoded — which
    /// is what "cancel the work" has to mean for a resolver whose work is the
    /// decode.
    cursor: usize,
    /// Every item this stream has produced, in packet order. `finish` hands the
    /// whole slice back, so it has to outlive the last pull, and the pull that
    /// produces an item is the pull that appends it.
    items: std.ArrayList(item.Item),
};
fn resolverResolve(
    ctx: *anyopaque,
    // `AddressLookup.VTable.resolve`'s parameter order: a vtable entry takes
    // its context first and the allocator second, and the type every service
    // in the tree implements is fixed on `AddressLookup`.
    // ziglint-ignore: Z023
    alloc: std.mem.Allocator,
    node_id: key.NodeId,
) ResolveError!?Stream {
    const self: *PkarrResolver = @ptrCast(@alignCast(ctx));
    // Ownership leaves this function with the `Stream` it returns: the vtable
    // above names `pkarrDestroy`, which calls `alloc.destroy` on this pointer,
    // and the `errdefer` below covers the paths that fail before that. The
    // engine does not follow a pointer handed back to a caller.
    // zwanzig-disable-next-line: store-violations-engine
    const state = try alloc.create(PkarrState);
    errdefer alloc.destroy(state);
    state.* = .{
        .parent = self,
        .arena = .init(alloc),
        .alloc = undefined,
        .node_id = node_id,
        .answers = self.source.answers,
        .cursor = 0,
        .items = .empty,
    };
    state.alloc = state.arena.allocator();
    return .{
        .state = @ptrCast(@alignCast(state)),
        .vtable = &pkarr_stream_vtable,
        .alloc = alloc,
        .status = .live,
    };
}
const pkarr_stream_vtable: Stream.VTable = .{
    .next = pkarrNext,
    .finish = pkarrFinish,
    .cancel = pkarrCancel,
    .destroy = pkarrDestroy,
};
/// One pull: hand over the item already decoded, or decode the next answer.
///
/// Decoding and delivering are interleaved rather than separated on purpose.
/// Doing every decode up front would make `finish` simpler and would mean a
/// caller that abandons the stream had already paid for all of it, which is the
/// opposite of what a cancellation is for.
fn pkarrNext(state: *anyopaque) ?Event {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    if (self.cursor < self.items.items.len) {
        const value = self.items.items[self.cursor];
        self.cursor += 1;
        return .{ .item = value };
    }
    const bytes = self.answers.next() orelse return null;
    const packet = self.parent.source.decode(self.parent.source.ctx, bytes) catch |reason| {
        return failed(.pkarr, reason);
    };
    if (self.node_id.order(packet.node_id) != .eq) {
        return failed(.pkarr, error.UnexpectedSigner);
    }
    const value = parseTxt(self.alloc, packet.node_id, packet.txt, .pkarr) catch |reason| {
        return failed(.pkarr, reason);
    };
    self.items.append(self.alloc, value) catch {
        // The item is built and owned by nothing, so its address list is freed
        // here: `destroy` walks `items` and this one is not in it.
        value.endpoint.deinit(self.alloc);
        return failed(.pkarr, error.OutOfMemory);
    };
    // The item just appended is the one being handed over, so the cursor moves
    // with it. Without this the next pull would find `cursor < items.len` and
    // hand the same item over a second time.
    self.cursor += 1;
    return .{ .item = value };
}
fn pkarrFinish(state: *anyopaque) item.Resolution {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    return .{ .resolved = self.items.items };
}
fn pkarrCancel(state: *anyopaque) void {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    if (self.parent.source.cancellation) |cancellation| cancellation.fire();
}
// `Stream.VTable.destroy`'s parameter order, for the reason `resolverResolve`
// above gives: the state being released, then the allocator the stream was
// started with.
// ziglint-ignore: Z023
fn pkarrDestroy(state: *anyopaque, alloc: std.mem.Allocator) void {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    // The arena owns every item, their address lists and the bytes behind any
    // custom address, so there is nothing to walk and nothing to free
    // individually — and therefore no way for one of those to be missed.
    self.arena.deinit();
    alloc.destroy(self);
}

const t = std.testing;
/// A node id from a fixed seed. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so a corpus draws from seeds.
fn corpusId(seed: u8) !key.NodeId {
    var bytes: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&bytes, seed);
    return (try key.SecretKey.fromSeed(bytes)).nodeId();
}
/// The three record strings and the node id of upstream's own
/// `test_from_txt_lookup`, copied from `iroh-dns/src/endpoint_info.rs` at
/// 187f59e80afdae6bd9866002b33d3365c00b06d8. Captured bytes and not invented:
/// all three strings and the 64-character id are that test's own literals.
const upstream_records = "addr=192.168.96.145:60165\x00" ++
    "addr=213.208.157.87:60165\x00" ++
    "relay=https://euw1-1.relay.iroh.network./\x00";
const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";
/// A stand-in for `discovery/pkarr.zig`: signed bytes to a `Packet`, in answer
/// order, and a counter standing in for the retrieval. Those are exactly the
/// two seams `PacketSource` names, so a resolver wired to this exercises the
/// same interface a real one does, and the counter is what makes a cancellation
/// observable rather than merely asserted.
const FakeRelay = struct {
    /// NUL-separated, because each answer is a whole signed packet and a
    /// packet may hold several `_iroh` records of its own.
    answers: []const u8,
    packets: []const Packet,
    /// Which answer is being decoded, so a second call gets the next packet the
    /// way a real source reading a fresh answer set does.
    cursor: usize = 0,
    /// Fired once per `Stream.deinit`. This is the assertion invariant 13 is
    /// really about, and it lives outside the resolver on purpose.
    cancels: u32 = 0,
    /// The only bytes this fake accepts. Anything else is a malformed packet,
    /// which is how a resolver's decode-failure path gets exercised.
    good: []const u8 = "signed",

    fn decode(ctx: *anyopaque, packet: []const u8) DecodeError!Packet {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, packet, self.good)) return error.MalformedPacket;
        const at = self.cursor;
        self.cursor += 1;
        if (at >= self.packets.len) return error.MalformedPacket;
        return self.packets[at];
    }

    fn stop(ctx: *anyopaque) void {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        self.cancels += 1;
    }

    fn source(self: *FakeRelay) PacketSource {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .decode = decode,
            .answers = .init(self.answers),
            .cancellation = .{ .ctx = @ptrCast(@alignCast(self)), .stop = stop },
        };
    }
};
test "a publish nobody wanted still released what it was handed" {
    // The other end of the transfer. Every resolver in the tree takes
    // `ignore_publish`, so this is the shape a caller publishes into when the
    // service it chose does not publish: nothing was published, and nothing is
    // left over for the caller to release either, because the address list
    // arrived with the allocator that built it. `t.allocator` names the leak at
    // the end of the test, so a `publish` that dropped the value on the floor
    // fails here without needing an assertion of its own.
    const id = try corpusId(3);
    var relay: FakeRelay = .{ .answers = "", .packets = &.{} };
    var resolver = PkarrResolver.init(relay.source());

    resolver.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try node_addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try relay_url.RelayUrl.parse("https://relay.example./"),
        ),
        .last_updated = null,
    });
    // The publication changed nothing about the service: it resolves as it did,
    // which is the whole of what publishing into a resolver means.
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() == null);
    try t.expect(stream.finish().isEmptyResult());
    stream.deinit();
}
test "cannot resolve and resolved to nothing are different answers" {
    const id = try corpusId(1);

    // A service that will not answer at all. There is no `Resolution` in hand
    // afterwards, and the absence is the whole point: there is no value a caller
    // could mistake for an empty one.
    var publisher = publish.PkarrPublisher.init();
    defer publisher.deinit();
    try t.expect((try publisher.lookup().resolve(t.allocator, id)) == null);

    // A service that was asked, ran, and had nothing to say. The answer set is
    // empty because the relay answered with no packets, which is a real state of
    // the world: a node that has published nothing.
    var relay: FakeRelay = .{
        .answers = "",
        .packets = &.{},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();
    try t.expect(stream.next() == null);

    const nothing = stream.finish();
    try t.expectEqual(@as(?usize, 0), nothing.itemCount());
    try t.expect(nothing.isEmptyResult());
    // `Resolution.cannot_resolve` as a value and not as an enum member: a
    // tagged union has no member to name on the type.
    const cannot: item.Resolution = .cannot_resolve;
    try t.expectEqual(@as(?usize, null), cannot.itemCount());
    try t.expect(!cannot.isEmptyResult());
}
test "dropping a stream stops the work behind it" {
    const id = try corpusId(3);
    var relay: FakeRelay = .{
        .answers = "signed\x00signed\x00",
        .packets = &.{
            .{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") },
            .{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") },
        },
    };
    var resolver = PkarrResolver.init(relay.source());

    // Abandoned part-drained, with a second answer still waiting: the case a
    // future-driven stream gets wrong, because nothing in the caller's control
    // has to happen for the work behind it to keep going.
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    // Nothing has been told to stop yet, and saying so is the half of the
    // assertion that makes the other half mean anything.
    try t.expectEqual(@as(u32, 0), relay.cancels);
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}
test "a drained stream is cancelled exactly once too" {
    const id = try corpusId(3);
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
    // A finished service has nothing left to stop, so a `cancel` that is a
    // no-op now is what makes "on every path" true rather than aspirational.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
    // Idempotent, because a second `deinit` is a caller mistake that must not
    // also be a double free.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}
test "a resolver with no retrieval in flight still runs and still frees" {
    // `cancellation` is null when the answers were not fetched here. Upstream's
    // pkarr and DNS lookups are both in-flight fetches, so null is a
    // stored-answer-set shape rather than the production one, and it has to
    // work because that is how a cache is read back.
    const id = try corpusId(4);
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") }},
    };
    var resolver = PkarrResolver.init(.{
        .ctx = @ptrCast(@alignCast(&relay)),
        .decode = FakeRelay.decode,
        .answers = .init("signed\x00"),
        .cancellation = null,
    });
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
    stream.deinit();
    // Nothing was told to stop, because there was nothing to stop. The counter
    // belongs to the fake and the fake's handle is null, so this is the
    // complement of the cancellation tests rather than a repeat of them.
    try t.expectEqual(@as(u32, 0), relay.cancels);
}
test "a packet signed for another node is reported, not returned" {
    // Upstream takes the id from the packet and hands it on
    // (`from_pkarr_signed_packet`), so a relay answering a query for one node
    // with another's record is obeyed. ozai reports it instead.
    const id = try corpusId(7);
    const other = try corpusId(8);
    var relay: FakeRelay = .{
        .answers = "signed\x00signed\x00",
        .packets = &.{
            .{ .node_id = other, .txt = .init("relay=https://elsewhere.example./\x00") },
            .{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") },
        },
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(error.UnexpectedSigner, first.failed.reason);
    try t.expectEqual(item.Provenance.pkarr, first.failed.provenance);
    // The failure did not end the stream, so the packet that *was* signed for
    // this node still arrives behind it.
    const second = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
}
test "a packet that will not decode fails one answer and not the stream" {
    const id = try corpusId(7);
    var relay: FakeRelay = .{
        .answers = "garbage\x00signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(error.MalformedPacket, first.failed.reason);
    const second = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
}
test "resolver output is what merge and order are for" {
    // Two services and three items, none of which a test built for the purpose
    // of being ordered: two come out of the pkarr resolver's stream and one out
    // of upstream's captured records. The total order is exercised through what
    // the services produced.
    const dns_id = try key.NodeId.parseHex(upstream_id);
    const pkarr_id = try corpusId(9);
    const records = "relay=https://use1-1.relay.iroh.network./\x00addr=192.0.2.9:9999\x00";
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = pkarr_id, .txt = .init(records) }},
    };
    var resolver = PkarrResolver.init(relay.source());

    var pulled: [1]item.Item = undefined;
    {
        var stream = (try resolver.lookup().resolve(t.allocator, pkarr_id)) orelse
            return error.TestUnexpectedResult;
        defer stream.deinit();
        var count: usize = 0;
        var failed_count: usize = 0;
        while (stream.next()) |event| switch (event) {
            .item => |value| {
                pulled[count] = value;
                count += 1;
            },
            .failed => failed_count += 1,
        };
        try t.expectEqual(@as(usize, 0), failed_count);
        try t.expectEqual(@as(usize, 1), count);
        try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());

        // Everything below reads items the stream owns, so all of it happens
        // before `deinit` hands the heap back. That ordering is `Stream`'s
        // contract, and a test that got it wrong would read freed memory and
        // pass or fail at random.
        const same_by_dns = try parseTxt(t.allocator, pkarr_id, .init(records), .dns);
        defer same_by_dns.endpoint.deinit(t.allocator);
        const other = try parseTxt(t.allocator, dns_id, .init(upstream_records), .dns);
        defer other.endpoint.deinit(t.allocator);

        const found = [_]item.Item{ pulled[0], same_by_dns, other };
        const merged = try item.merge(t.allocator, &found);
        defer t.allocator.free(merged);
        // Three services' answers, three distinct facts, and the two that agree
        // on one endpoint are *not* the same item: provenance is a tiebreak and
        // not a dedup key, because two services reporting one address is
        // agreement rather than a conflict.
        try t.expectEqual(@as(usize, 3), merged.len);
        try t.expect(merged[0].eql(item.winner(&found).?));
        var at: usize = 1;
        while (at < merged.len) : (at += 1) {
            try t.expectEqual(std.math.Order.gt, merged[at - 1].order(merged[at]));
        }
        // And the pair that differs in nothing at all but which service said it
        // has an order, and it is the one `Provenance.rank` names rather than
        // the one the answers happened to arrive in.
        try t.expectEqual(std.math.Order.lt, same_by_dns.order(pulled[0]));
        try t.expectEqual(std.math.Order.gt, pulled[0].order(same_by_dns));
    }
}
/// One resolve over three answers, drained to the end and released: the shape
/// every boundary of the resolver's lifetime is measured against.
fn drainThree(alloc: std.mem.Allocator, node_id: key.NodeId) !void {
    const packets = [_]Packet{
        .{ .node_id = node_id, .txt = .init("addr=1_a1b2c3\x00") },
        .{ .node_id = node_id, .txt = .init("addr=2_deadbeef\x00relay=https://relay.example./\x00") },
        .{ .node_id = node_id, .txt = .init("addr=127.0.0.1:1234\x00") },
    };
    var relay: FakeRelay = .{ .answers = "signed\x00signed\x00signed\x00", .packets = &packets };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(alloc, node_id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();
    var items: usize = 0;
    while (stream.next()) |event| switch (event) {
        .item => items += 1,
        .failed => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 3), items);
    try t.expectEqual(@as(?usize, 3), stream.finish().itemCount());
    try t.expectEqual(@as(u32, 1), relay.cancels);
}
// and then the arena and the item list behind it as the answers are turned
// into items. One boundary is the construction and the rest are the drain, so
// a sweep that only walked the first would say nothing about a stream that has
// to answer for anybody.
test "a resolve, a drain and a release, refused at every allocation in turn" {
    const id = try corpusId(25);
    const boundaries = try boundariesOf(drainThree, .{id});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        const packets = [_]Packet{
            .{ .node_id = id, .txt = .init("addr=1_a1b2c3\x00") },
            .{ .node_id = id, .txt = .init("addr=2_deadbeef\x00relay=https://relay.example./\x00") },
            .{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") },
        };
        var relay: FakeRelay = .{ .answers = "signed\x00signed\x00signed\x00", .packets = &packets };
        var resolver = PkarrResolver.init(relay.source());
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        const started = resolver.lookup().resolve(alloc, id);
        if (started) |maybe| {
            var stream = maybe orelse return error.TestUnexpectedResult;
            defer stream.deinit();
            var items: usize = 0;
            var failures: usize = 0;
            while (stream.next()) |event| switch (event) {
                .item => items += 1,
                .failed => |why| {
                    failures += 1;
                    // A failed answer is lost and the stream is not, which is
                    // what makes the count below exact rather than a bound.
                    try t.expectEqual(error.OutOfMemory, why.reason);
                    try t.expectEqual(item.Provenance.pkarr, why.provenance);
                },
            };
            // Every answer was still walked, and exactly one of them was lost —
            // the one whose building allocation the sweep refused.
            try t.expectEqual(@as(usize, 3), items + failures);
            try t.expect(if (refused != 0) failures >= 1 else failures == 0);
            // `finish` counts the items that survived, so a lost answer is one
            // the caller never sees and not one it sees twice.
            try t.expectEqual(@as(?usize, items), stream.finish().itemCount());
            stream.deinit();
            // A drained stream is still cancelled, and once.
            try t.expectEqual(@as(u32, 1), relay.cancels);
        } else |reason| {
            // The first allocation a resolve makes is the state block, and
            // refusing it starts nothing: no stream exists to cancel and
            // nothing was allocated to release.
            try t.expectEqual(error.OutOfMemory, reason);
            try t.expectEqual(@as(usize, 0), refused);
            try t.expectEqual(@as(u32, 0), relay.cancels);
        }
        try t.expect(failing.has_induced_failure);

        // The retry a caller gets by asking again rather than abandoning: the
        // refusal was one event, the service is undamaged, and this time all
        // three answers arrive and the arena goes back to the allocator whole.
        failing.fail_index = std.math.maxInt(usize);
        var again: FakeRelay = .{ .answers = "signed\x00signed\x00signed\x00", .packets = &packets };
        var second = PkarrResolver.init(again.source());
        var retried = (try second.lookup().resolve(alloc, id)) orelse
            return error.TestUnexpectedResult;
        while (retried.next()) |event| switch (event) {
            .item => {},
            .failed => return error.TestUnexpectedResult,
        };
        try t.expectEqual(@as(?usize, 3), retried.finish().itemCount());
        retried.deinit();
        try t.expectEqual(@as(u32, 1), again.cancels);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
// The boundary the drain above walks past: a caller that stops reading part
// way. Abandonment has to hold on the path where one answer was refused and
// the arena holds a delivered item and a lost one at the same time, so this
// finds the second answer's first allocation by running the same drain once
// with nothing refused and watching how far the first pull got.
test "a stream abandoned after a refused answer is still stopped exactly once" {
    const id = try corpusId(26);
    const packets = [_]Packet{
        .{ .node_id = id, .txt = .init("addr=1_a1b2c3\x00") },
        .{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00bad_record\x00") },
        .{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") },
    };

    var relay: FakeRelay = .{ .answers = "signed\x00signed\x00signed\x00", .packets = &packets };
    var resolver = PkarrResolver.init(relay.source());
    var failing = t.FailingAllocator.init(t.allocator, .{});
    const alloc = failing.allocator();
    var stream = (try resolver.lookup().resolve(alloc, id)) orelse
        return error.TestUnexpectedResult;

    // The first answer arrives whole, and the second is the one refused.
    switch (stream.next() orelse return error.TestUnexpectedResult) {
        .item => |delivered| try t.expectEqual(id, delivered.endpoint.node_id),
        .failed => return error.TestUnexpectedResult,
    }
    switch (stream.next() orelse return error.TestUnexpectedResult) {
        .item => return error.TestUnexpectedResult,
        .failed => |why| try t.expectEqual(error.MalformedRecord, why.reason),
    }

    // Abandoned here: the third answer is never read, which is the whole of
    // what a cancellation buys, and nothing has been told to stop yet.
    try t.expectEqual(@as(u32, 0), relay.cancels);
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
    // The arena and the state went with it, so the allocator is empty again
    // after a stream that delivered one item and lost another.
    try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    // And a second `deinit` is a caller mistake that costs nothing.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}

/// How many allocations `run` makes, whether it finishes or stops on an error
/// that is not the allocator's — which is the whole point of the paths that
/// end in `MalformedRecord`.
///
/// The error the probe saw is deliberately dropped: the count is what this is
/// for, and every sweep that uses it re-runs each boundary and asserts the
/// error it gets there, so nothing is asserted twice and nothing is skipped.
///
/// `resize_fail_index` is pinned at zero rather than left at its default. A
/// growth the backing allocator can satisfy in place goes through `resize`
/// instead of `alloc`, consumes no allocation index, and is therefore a
/// boundary no `fail_index` can reach: the sweep would step over it and the
/// case would look complete while a growth went untested. Refusing every
/// resize routes each growth through `alloc`, so what comes back is the count
/// of allocating boundaries rather than the count of the ones this allocator
/// happens to make visible.
fn boundariesOf(comptime run: anytype, args: anytype) !usize {
    var probe = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    // The error is the measurement, not a surprise: the probe refuses its first
    // request, so a run that returns is the case this counts. Which error it
    // stopped with is the boundary's identity, and every sweep re-runs each
    // boundary and asserts the error it gets there — so the payload is bound
    // and dropped here by name rather than swallowed by `catch {}`.
    _ = @call(.auto, run, .{probe.allocator()} ++ args) catch |probe_error| {
        std.mem.doNotOptimizeAway(&probe_error);
    };
    return probe.alloc_index;
}
