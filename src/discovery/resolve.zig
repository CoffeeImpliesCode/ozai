//! The address-lookup interface, the pull-based stream `resolve` hands back,
//! and the two pkarr services.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published): the
//! `AddressLookup` trait at `iroh/src/address_lookup.rs:335` with its two
//! default bodies at `:343` and `:349`, `PkarrPublisher` and `PkarrResolver` at
//! `iroh/src/address_lookup/pkarr.rs:357` and `:536`, and the `key=value` record
//! grammar at `iroh-dns/src/attrs.rs` and `iroh-dns/src/endpoint_info.rs`.
//!
//! Three things differ from upstream and each is one rule applied rather than
//! three decisions made.
//!
//! * The trait is a vtable, as `docs/ARCHITECTURE.md` records for
//!   `ProtocolHandler`. A vtable has no default method bodies, so upstream's two
//!   defaults are two function pointers any vtable may take:
//!   `AddressLookup.ignore_publish` and `AddressLookup.refuse_resolve`. The
//!   second is where "cannot resolve at all" comes from, and `PkarrPublisher`
//!   takes it — upstream's publisher implements no `resolve`, so asking one to
//!   resolve is answered with `None` and not with an empty stream.
//! * The stream is pulled. See `Stream`.
//! * Nothing here opens a socket. A service is handed the bytes an answer
//!   consists of, and a handle to the retrieval they came from, and the
//!   retrieval is the transport's business and is injected at construction.
//!   mDNS and the Mainline DHT are external crates upstream and are not in that
//!   tree; in ozai they are two more `VTable` values and nothing else, and
//!   nothing here would change to add either.
//!
//! One thing is deliberately absent: `AddressLookupServices`, upstream's fan-in
//! over many services (`iroh/src/address_lookup.rs:565`). M5 asks for three
//! implementations of one interface, and the merge that would sit on top of it
//! is `discovery/item.zig`'s `merge` and `order`, which are already total.
//!
//! # Where each half lives
//!
//! Three modules under `src/discovery/`, with the boundaries between the
//! questions rather than between the declarations. Every public name this file
//! has ever had is still reachable through it, so a caller that names this file
//! gets exactly what it got before:
//!
//! * `lookup.zig` — what a service *is*: `Published`, `ResolveError`,
//!   `AddressLookup`, `Event`, `Failure`, `DecodeError`, `Reason`,
//!   `Cancellation`, `Stream`.
//! * `txt.zig` — how bytes become an `Item`: `ParseError`, `iroh_txt_name`,
//!   `Attribute`, `RecordSet`, `parseTxt`, `writeSocketAddr`, `EncodeError`,
//!   `max_record_length`, `maxTxtStringsLength`.
//! * `pkarr_services.zig` — the two concrete services: `Packet`,
//!   `PacketSource`, `PkarrPublisher`, `PkarrResolver`. It is not
//!   `discovery/pkarr.zig`, which is the signed-packet codec underneath it.
//!
//! The dependencies run one way. `pkarr_services.zig` imports both of the
//! others, and `lookup.zig` names `txt.zig` for `ParseError` alone, so `txt.zig`
//! imports neither and the grammar stays the bottom of the stack.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const lookup = @import("lookup.zig");
const txt = @import("txt.zig");
const pkarr_services = @import("pkarr_services.zig");

/// What a service is asked to publish. See `discovery/lookup.zig`.
pub const Published = lookup.Published;

/// Why `resolve` could not start. See `discovery/lookup.zig`.
pub const ResolveError = lookup.ResolveError;

/// Two methods, upstream's method set, as a vtable. See `discovery/lookup.zig`.
pub const AddressLookup = lookup.AddressLookup;

/// One pull's worth of answer. See `discovery/lookup.zig`.
pub const Event = lookup.Event;

/// One answer that was not an item. See `discovery/lookup.zig`.
pub const Failure = lookup.Failure;

/// Why injected packet bytes are not a signed packet. See `discovery/lookup.zig`.
pub const DecodeError = lookup.DecodeError;

/// Everything one answer can fail with. See `discovery/lookup.zig`.
pub const Reason = lookup.Reason;

/// The producer's own stop handle. See `discovery/lookup.zig`.
pub const Cancellation = lookup.Cancellation;

/// A resolve in progress, pulled by whoever asked for it. See `discovery/lookup.zig`.
pub const Stream = lookup.Stream;

/// Why a set of records is not an `Item`. See `discovery/txt.zig`.
pub const ParseError = txt.ParseError;

/// The record name both services write under. See `discovery/txt.zig`.
pub const iroh_txt_name = txt.iroh_txt_name;

/// The three `iroh` TXT attributes. See `discovery/txt.zig`.
pub const Attribute = txt.Attribute;

/// A set of `key=value` records in one borrowed buffer. See `discovery/txt.zig`.
pub const RecordSet = txt.RecordSet;

/// Turn a set of records into the one `Item` they describe. See `discovery/txt.zig`.
pub const parseTxt = txt.parseTxt;

/// `addr.SocketAddr` to the text an `addr=` record carries. See `discovery/txt.zig`.
pub const writeSocketAddr = txt.writeSocketAddr;

/// Why a publisher could not write its records. See `discovery/txt.zig`.
pub const EncodeError = txt.EncodeError;

/// Longest single `key=value` record. See `discovery/txt.zig`.
pub const max_record_length = txt.max_record_length;

/// Buffer size for this many addresses, separators included. See `discovery/txt.zig`.
pub const maxTxtStringsLength = txt.maxTxtStringsLength;

/// One signed pkarr packet, as a resolver needs it. See `discovery/pkarr_services.zig`.
pub const Packet = pkarr_services.Packet;

/// What a pkarr resolver reads. See `discovery/pkarr_services.zig`.
pub const PacketSource = pkarr_services.PacketSource;

/// The service that only publishes. See `discovery/pkarr_services.zig`.
pub const PkarrPublisher = pkarr_services.PkarrPublisher;

/// The service that only resolves. See `discovery/pkarr_services.zig`.
pub const PkarrResolver = pkarr_services.PkarrResolver;

const t = std.testing;
const key = @import("../base/key.zig");

/// A node id from a fixed seed. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so a corpus draws from seeds.
fn corpusId(seed: u8) !addr.NodeId {
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

test "a publisher cannot resolve, which is not a failure" {
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();
    // Upstream's publisher implements `publish` and no `resolve`
    // (`iroh/src/address_lookup/pkarr.rs:357`), so a resolve is the trait
    // default's `None`: the service will not answer, as against a service that
    // answered and had nothing. No work was started, so there is nothing to
    // cancel either, and no error to log.
    try t.expect((try publisher.lookup().resolve(t.allocator, try corpusId(1))) == null);
}

test "a publisher that has published nothing writes nothing" {
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();
    // `published` is null and `writeTxtStrings` says so rather than handing
    // back an empty record set, which a reader would take for a node that has
    // published nothing. One slot, two answers, and the second one is not
    // "there is nothing here yet".
    try t.expect(publisher.published() == null);
    var buffer: [maxTxtStringsLength(1)]u8 = undefined;
    try t.expectError(error.NothingPublished, publisher.writeTxtStrings(&buffer));
}

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
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://relay.example./"),
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

test "a publisher releases the slot it replaces with the allocator that made it" {
    // Two publications, two allocators, and the second replaces the first. A
    // publisher holds no allocator of its own, so this is only correct because
    // each `Published` carries the one its list came from: releasing the first
    // slot with the second's would hand an arena's bytes to a testing allocator
    // that never allocated them, and the run would stop inside `free` rather
    // than at an assertion here.
    const id = try corpusId(4);
    // Declared before the publisher, so `deinit` empties the slot while the
    // arena is still there. That order is the obligation `Published` states for
    // a caller, and a test that got it wrong would free into a dead arena.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();

    publisher.lookup().publish(.{
        .alloc = arena.allocator(),
        .endpoint = try addr.NodeAddr.withRelay(
            arena.allocator(),
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 1,
    });
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://two.example./"),
        ),
        .last_updated = 2,
    });

    // The slot is the second publication and the first is gone: an address the
    // endpoint has since stopped using is stale, not a second opinion.
    const stored = publisher.published() orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(?u64, 2), stored.last_updated);
    try t.expectEqual(@as(usize, 1), stored.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://two.example./"),
        stored.endpoint.addrs[0].relay,
    );

    // A third publication replaces that one, and `deinit` releases this one on
    // the way out — the release a replaced slot never gets to make.
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://three.example./"),
        ),
        .last_updated = 3,
    });
}

test "cannot resolve and resolved to nothing are different answers" {
    const id = try corpusId(1);

    // A service that will not answer at all. There is no `Resolution` in hand
    // afterwards, and the absence is the whole point: there is no value a caller
    // could mistake for an empty one.
    var publisher = PkarrPublisher.init();
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

test "the attribute set is upstream's three, spelled upstream's way" {
    // `IrohAttr` in `iroh-dns/src/attrs.rs`: three arms, `kebab-case`, and
    // "The resource record uses the lower-case names".
    try t.expectEqual(@as(usize, 3), Attribute.all.len);
    // `all` is what `parse` iterates. An arm missing from it would be
    // unreadable and unwritable, so the list is held to the enum here.
    try t.expectEqual(Attribute.all.len, @typeInfo(Attribute).@"enum".field_names.len);
    try t.expectEqualStrings("relay", Attribute.relay.text());
    try t.expectEqualStrings("addr", Attribute.addr.text());
    try t.expectEqualStrings("user-data", Attribute.user_data.text());
    // Every arm round trips through its own spelling, which is the only thing
    // `parse` has to get right: a spelling that did not would make a record
    // some other client wrote unreadable here.
    inline for (Attribute.all) |attribute| {
        try t.expectEqual(attribute, Attribute.parse(attribute.text()).?);
    }
    // The match is exact. `strum`'s generated `FromStr` is exact too, so a
    // case-folded record is a failed record and not a read one — and
    // `userdata` is not `user-data`, which is the mistake worth pinning.
    try t.expect(Attribute.parse("RELAY") == null);
    try t.expect(Attribute.parse("userdata") == null);
    try t.expect(Attribute.parse("") == null);
}

test "upstream's own records parse to the endpoint upstream says" {
    const id = try key.NodeId.parseHex(upstream_id);
    const value = try parseTxt(t.allocator, id, .init(upstream_records), .dns);
    defer value.endpoint.deinit(t.allocator);

    // Upstream's expected `EndpointInfo` from the same test: one relay URL and
    // two sockets, no user data. `NodeAddr` is sorted, and the sorted order is
    // relay, then IPv4 by address, which is the order the test lists them in.
    try t.expectEqual(@as(usize, 3), value.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://euw1-1.relay.iroh.network./"),
        value.endpoint.addrs[0].relay,
    );
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 192, 168, 96, 145 } }, .port = 60165 },
        value.endpoint.addrs[1].ip,
    );
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 213, 208, 157, 87 } }, .port = 60165 },
        value.endpoint.addrs[2].ip,
    );
    // Neither upstream service supplies a timestamp, so ties use address values.
    try t.expectEqual(@as(?u64, null), value.last_updated);
    try t.expectEqual(item.Provenance.dns, value.provenance);
}

test "a value ends at the second equals sign, as upstream's split does" {
    // `iroh-dns/src/attrs.rs`, `from_strings`: `let mut parts = s.split('=')`
    // and then the first two pieces, so the value of `a=b=c` is `b` and `c` is
    // gone. The records below are built to exercise that rule; they are not
    // captured ones, and nothing here claims they are.
    const value = try parseTxt(
        t.allocator,
        try corpusId(5),
        .init("addr=127.0.0.1:1234=9\x00user-data=a=b\x00"),
        .pkarr,
    );
    defer value.endpoint.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 },
        value.endpoint.addrs[0].ip,
    );
}

test "an unknown key fails the whole record set" {
    // `ParseError::AttrFromString` upstream: `T::from_str(key).map_err(..)`
    // returns `Err`, so one key that is not one of the three takes the good
    // records with it. That is what makes a typo in a publisher visible instead
    // of silent.
    const id = try corpusId(5);
    try t.expectError(error.MalformedRecord, parseTxt(
        t.allocator,
        id,
        .init("relay=https://relay.example./\x00hostname=x\x00"),
        .dns,
    ));
    // A record with no `=` is `ParseError::UnexpectedFormat`, and an empty key
    // is the same arm of it.
    try t.expectError(error.MalformedRecord, parseTxt(
        t.allocator,
        id,
        .init("relay=https://relay.example./\x00nonsense\x00"),
        .dns,
    ));
}

test "a value that will not parse is dropped and the rest is kept" {
    // `filter_map(|s| Url::parse(s).ok())` upstream: a relay URL that is not a
    // URL is a dropped record, not a failed lookup. Same for an address of no
    // known shape.
    const value = try parseTxt(
        t.allocator,
        try corpusId(5),
        .init("relay=not a url\x00addr=999.1.1.1:1\x00relay=https://relay.example./\x00"),
        .dns,
    );
    defer value.endpoint.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://relay.example./"),
        value.endpoint.addrs[0].relay,
    );
}

test "a custom payload is released however the record fails" {
    // Three allocations stand between this record and the item: the payload
    // copy, the tracker that records it, and the growth of the address list.
    // The middle one is the one that used to be missed — the copy went into the
    // address list first and was recorded afterwards, so a failure in the
    // recording handed back an item holding a buffer no path owned. Each probe
    // fails one of the two later allocations by index, and `t.allocator` names
    // the leak at the end of the test, so both are green only when the copy is
    // released on each of those paths.
    const id = try corpusId(6);
    const records: RecordSet = .init("addr=1_a1b2c3\x00");

    var recording = t.FailingAllocator.init(t.allocator, .{ .fail_index = 1 });
    try t.expectError(error.OutOfMemory, parseTxt(recording.allocator(), id, records, .pkarr));

    var growing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 2 });
    try t.expectError(error.OutOfMemory, parseTxt(growing.allocator(), id, records, .pkarr));

    // The success path still owns what the contract says it does: the payload is
    // the caller's to release, because `NodeAddr.deinit` frees the address list
    // and nothing else. Reading it here is the other half of that sentence — an
    // item that copied the bytes out and then lost track of them would fail on
    // the leak check above and never reach this.
    const value = try parseTxt(t.allocator, id, records, .pkarr);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    for (value.endpoint.addrs) |one| {
        if (one == .custom) t.allocator.free(one.custom.data);
    }
    value.endpoint.deinit(t.allocator);
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

test "published records read back as the address that was published" {
    const id = try corpusId(7);
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();

    // Three families, so the loop that writes one record per address is walked
    // in all three, and the v6 and custom arms are the ones whose text form is
    // not this project's own display form.
    var endpoint = addr.NodeAddr.init(id);
    for ([_]addr.TransportAddr{
        .{ .relay = try addr.RelayUrl.parse("https://relay.example./") },
        .{ .ip = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 } },
        .{ .ip = .{ .ip = .{ .v6 = .{
            0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 0,
            0,    0,    0,    0,    0,    0,    0, 1,
        } }, .port = 12345 } },
        .{ .custom = .{ .id = 1, .data = &.{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } } },
    }) |value| {
        if (try endpoint.insert(t.allocator, value)) |grown| endpoint = grown;
    }
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = endpoint,
        .last_updated = 7,
    });

    var buffer: [maxTxtStringsLength(4)]u8 = undefined;
    const records = try publisher.writeTxtStrings(&buffer);

    // The custom address is upstream's `txt_attr_roundtrip_with_custom_addr`
    // `bt_addr`, whose text form `iroh-base/src/endpoint_addr.rs` writes as
    // `write!(f, "{:x}_{}", self.id, HEXLOWER.encode(self.data.as_bytes()))`.
    try t.expect(std.mem.indexOf(u8, records, "addr=1_a1b2c3d4e5f6\x00") != null);
    // The relay text is `url::Url`'s `Display`: scheme, host, no port for the
    // default, and a `/` path. That is the shape invariant 4 pins, so the two
    // rules agree and a published relay is readable by any other client.
    try t.expect(std.mem.indexOf(u8, records, "relay=https://relay.example./\x00") != null);
    // The reader's copy of the custom address data has to outlive the item, so
    // the read side gets the arena `parseTxt` asks for. The published side
    // borrows, because the data here is a string literal in the test.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const read = try parseTxt(arena.allocator(), id, .init(records), .pkarr);
    defer read.endpoint.deinit(arena.allocator());
    const stored = publisher.published() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(stored.endpoint.node_id, read.endpoint.node_id);
    try t.expectEqual(stored.endpoint.addrs.len, read.endpoint.addrs.len);
    for (stored.endpoint.addrs, read.endpoint.addrs) |left, right| {
        // `order` and not `==`: a `TransportAddr` holds a slice, and the two
        // were built from two different buffers.
        try t.expectEqual(std.math.Order.eq, left.order(right));
    }
    // The wire record carries no timestamp, so the reader cannot recover the
    // publisher's stamp. Resolver items therefore tie in the address value order.
    try t.expectEqual(@as(?u64, null), read.last_updated);
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
