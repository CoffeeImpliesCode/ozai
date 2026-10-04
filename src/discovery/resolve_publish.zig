//! Upstream's `PkarrPublisher`: the service that only publishes.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published):
//! `PkarrPublisher` at `iroh/src/address_lookup/pkarr.rs:357`. It implements
//! `publish` and not `resolve`, so it takes
//! `resolve.AddressLookup.refuse_resolve` and a resolve asked of it comes back
//! `None`. That is the production case for the distinction invariant 13 is
//! about, and not only a trait default nobody uses.
//!
//! One slot, so the last publication is readable, and `deinit` for the one that
//! is still in it. The slot holds the whole `resolve.Published`, allocator
//! included, so a value this publisher did not build is released with the
//! allocator that did build it — see `Published`.
//!
//! `writeTxtStrings` is the publishing half's output format, and it is written
//! by `resolve_record.zig`'s grammar and bounded by it: `max_record_length` is
//! the width of the scratch buffer this file allocates per address, so the two
//! cannot drift apart without this loop walking off its own scratch.

const std = @import("std");
const item = @import("item.zig");
const key = @import("../base/key.zig");
const node_addr = @import("../base/node_addr.zig");
const relay_url = @import("../base/relay_url.zig");
const transport_addr = @import("../base/transport_addr.zig");
const record = @import("resolve_record.zig");
const resolve = @import("resolve.zig");

/// The interface's names, spelled once: a publisher holds a `Published`, hands
/// one over the vtable, and gives the one it replaces back with
/// `releaseTransfer` — the allocator that slot arrived with is the whole of it.
const AddressLookup = resolve.AddressLookup;
const Published = resolve.Published;
const releaseTransfer = resolve.releaseTransfer;

const EncodeError = record.EncodeError;
const max_record_length = record.max_record_length;
const maxTxtStringsLength = record.maxTxtStringsLength;
const parseTxt = record.parseTxt;
const writeSocketAddr = record.writeSocketAddr;

/// `PkarrPublisher`: the service that only publishes.
///
/// Upstream's `PkarrPublisher` implements `publish` and not `resolve`
/// (`iroh/src/address_lookup/pkarr.rs:357`), so it takes
/// `AddressLookup.refuse_resolve` and a resolve asked of it comes back `None`.
/// That is the production case for the distinction invariant 13 is about, and
/// not only a trait default nobody uses.
///
/// One slot, so the last publication is readable, and `deinit` for the one that
/// is still in it. The slot holds the whole `Published`, allocator included, so
/// a value this publisher did not build is released with the allocator that did
/// build it — see `Published`.
pub const PkarrPublisher = struct {
    /// The last data handed to `publish`, owned whole so the caller is free the
    /// moment `publish` returns. Upstream's is `self.watchable.set(Some(info))`
    /// (`iroh/src/address_lookup/pkarr.rs`, `update_endpoint_data`): the same
    /// take-ownership swap, into the same one slot, read by a background task
    /// that republishes on a timer.
    ///
    /// Null is the empty state: nothing published, and `published` says so
    /// rather than answering with an item that has no address.
    stored: ?Published,
    /// Borrowed by every `AddressLookup` handed out of `lookup`.
    vtable: AddressLookup.VTable = publisher_vtable,

    /// A publisher with nothing in its slot.
    pub fn init() PkarrPublisher {
        return .{ .stored = null };
    }

    // The slot is given back and then nulled, and null is the terminal state:
    // `published` answers null, a second `deinit` frees nothing, and the next
    // `publish` starts a fresh slot. Z030 recognises a fixed list of terminal
    // field names and `stored` is not on it, so the `= null` it cannot see is
    // here to be read.
    // ziglint-ignore: Z030
    /// Releases the slot, with the allocator that slot arrived with, and leaves
    /// the publisher empty. Not a vtable entry, because the vtable is a
    /// borrowed view: see `AddressLookup`. A second call frees nothing, and a
    /// `Published` published afterwards is released by the next `publish` or by
    /// this call.
    pub fn deinit(self: *PkarrPublisher) void {
        if (self.stored) |data| releaseTransfer(data);
        self.stored = null;
    }

    /// A handle onto this publisher. Borrowed, so the publisher has to outlive
    /// every handle taken of it and every publish made through one.
    pub fn lookup(self: *PkarrPublisher) AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }

    /// What was published last, or null when `publish` has not been called.
    ///
    /// Borrows the publisher's own storage, so the address list is dead after
    /// the next `publish` and after `deinit` — invariant 6's reason. The
    /// provenance is `.pkarr` and the stamp is the one the caller published,
    /// because a publisher is only ever a pkarr one.
    pub fn published(self: *const PkarrPublisher) ?item.Item {
        const data = self.stored orelse return null;
        return item.Item.init(data.endpoint, .pkarr, data.last_updated);
    }

    /// The records a signed packet for the published data would carry, as a
    /// `RecordSet` written into caller storage. Records are NUL-separated
    /// because that is what a DNS record set is; whoever builds the packet puts
    /// each one in a character string of its own and does not send the
    /// separators.
    ///
    /// The order is upstream's — every `relay=`, then every `addr=`, then
    /// `user-data=` — because a `BTreeMap` over `IrohAttr` iterates in
    /// declaration order however the packet listed them (`iroh-dns/src/attrs.rs`,
    /// `to_txt_strings`). It falls out of one loop here because
    /// `TransportAddr`'s declaration order is the same three families and
    /// `NodeAddr` is sorted by `TransportAddr.order`, so the sorted list is
    /// already grouped. `user-data=` is never written, because there is no user
    /// data to write: see `Attribute.user_data`.
    ///
    /// The order *within* the relays and the addresses is not upstream's.
    /// Upstream's `EndpointData` is insertion-ordered and says so — "The
    /// address order is preserved, so it can encode priority for address lookup
    /// services, should they not fit into e.g. a single DNS packet otherwise".
    /// Invariant 2 makes an address list a set, so ozai cannot encode a
    /// publication priority. That is a divergence, not an oversight.
    ///
    /// The relay URL text is upstream's: `url::Url`'s `Display` is scheme, host,
    /// a non-default port and a `/` path, which is exactly the canonical form
    /// invariant 4 pins.
    pub fn writeTxtStrings(self: *const PkarrPublisher, out: []u8) EncodeError![]const u8 {
        const stored = self.stored orelse return error.NothingPublished;
        var writer = std.Io.Writer.fixed(out);
        for (stored.endpoint.addrs) |value| {
            // One record at a time, into a scratch buffer, and copied out with
            // its separator. The separator goes *between* records, and a `for`
            // body is the only place that knows where one record ends; writing
            // it here also means `max_record_length` is a bound this loop
            // actually relies on rather than one it hopes for.
            var scratch: [max_record_length]u8 = undefined;
            var line = std.Io.Writer.fixed(&scratch);
            switch (value) {
                .relay => |url| {
                    line.writeAll("relay=") catch return error.BufferTooSmall;
                    url.format(&line) catch return error.BufferTooSmall;
                },
                .ip => |socket| {
                    line.writeAll("addr=") catch return error.BufferTooSmall;
                    writeSocketAddr(socket, &line) catch return error.BufferTooSmall;
                },
                .custom => |custom| {
                    line.writeAll("addr=") catch return error.BufferTooSmall;
                    custom.format(&line) catch return error.BufferTooSmall;
                },
            }
            writer.writeAll(line.buffered()) catch return error.BufferTooSmall;
            writer.writeAll("\x00") catch return error.BufferTooSmall;
        }
        return writer.buffered();
    }
};
const publisher_vtable: AddressLookup.VTable = .{
    .publish = publisherPublish,
    .resolve = AddressLookup.refuse_resolve,
};
fn publisherPublish(ctx: *anyopaque, data: Published) void {
    const self: *PkarrPublisher = @ptrCast(@alignCast(ctx));
    // The slot is replaced, not appended to, which is upstream's
    // `watchable.set`: a publisher's job is to say what this node is reachable
    // at *now*, and an address the endpoint has since stopped using is not a
    // second opinion, it is stale.
    // Released with the allocator that slot arrived with, not with one of this
    // publisher's: whoever published last built that list, and a publisher has
    // no allocator of its own to release it with.
    if (self.stored) |previous| releaseTransfer(previous);
    self.stored = data;
}

const t = std.testing;
/// A node id from a fixed seed. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so a corpus draws from seeds.
fn corpusId(seed: u8) !key.NodeId {
    var bytes: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&bytes, seed);
    return (try key.SecretKey.fromSeed(bytes)).nodeId();
}
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
        .endpoint = try node_addr.NodeAddr.withRelay(
            arena.allocator(),
            id,
            try relay_url.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 1,
    });
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try node_addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try relay_url.RelayUrl.parse("https://two.example./"),
        ),
        .last_updated = 2,
    });

    // The slot is the second publication and the first is gone: an address the
    // endpoint has since stopped using is stale, not a second opinion.
    const stored = publisher.published() orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(?u64, 2), stored.last_updated);
    try t.expectEqual(@as(usize, 1), stored.endpoint.addrs.len);
    try t.expectEqual(
        try relay_url.RelayUrl.parse("https://two.example./"),
        stored.endpoint.addrs[0].relay,
    );

    // A third publication replaces that one, and `deinit` releases this one on
    // the way out — the release a replaced slot never gets to make.
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try node_addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try relay_url.RelayUrl.parse("https://three.example./"),
        ),
        .last_updated = 3,
    });
}
test "published records read back as the address that was published" {
    const id = try corpusId(7);
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();

    // Three families, so the loop that writes one record per address is walked
    // in all three, and the v6 and custom arms are the ones whose text form is
    // not this project's own display form.
    var endpoint = node_addr.NodeAddr.init(id);
    for ([_]transport_addr.TransportAddr{
        .{ .relay = try relay_url.RelayUrl.parse("https://relay.example./") },
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
// `PkarrPublisher` is the one service here with no allocation of its own: it
// takes a value built by somebody else and hands it back with the allocator
// that built it. So a probe across two publications and a `deinit` must see
// exactly the two address lists this test built and no more — an allocation
// inside `publish` would be the publisher building an address list it was
// handed whole, and counting is how that would be caught.
test "the publisher allocates nothing of its own across two publications" {
    const id = try corpusId(24);
    var publisher = PkarrPublisher.init();
    var failing = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    const alloc = failing.allocator();

    publisher.lookup().publish(.{
        .alloc = alloc,
        .endpoint = try node_addr.NodeAddr.withRelay(
            alloc,
            id,
            try relay_url.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 1,
    });
    publisher.lookup().publish(.{
        .alloc = alloc,
        .endpoint = try node_addr.NodeAddr.withRelay(
            alloc,
            id,
            try relay_url.RelayUrl.parse("https://two.example./"),
        ),
        .last_updated = 2,
    });

    // The replaced slot was released as the second publication arrived, so the
    // publisher holds one list and the caller has handed over both.
    try t.expectEqual(@as(usize, 2), failing.allocations);
    try t.expectEqual(@as(usize, 1), failing.deallocations);
    const stored = publisher.published() orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(?u64, 2), stored.last_updated);
    try t.expectEqual(
        try relay_url.RelayUrl.parse("https://two.example./"),
        stored.endpoint.addrs[0].relay,
    );

    // `deinit` releases the slot that is still in it, with the allocator that
    // slot arrived with, and the whole lifecycle is two allocations and two
    // releases with nothing in between that the publisher itself did.
    publisher.deinit();
    try t.expect(publisher.published() == null);
    try t.expectEqual(@as(usize, 2), failing.deallocations);
    try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    // And a second `deinit` frees nothing.
    publisher.deinit();
    try t.expectEqual(@as(usize, 2), failing.deallocations);
}
