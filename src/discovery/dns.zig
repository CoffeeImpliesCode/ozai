//! DNS TXT discovery: `_iroh.<z32>.<origin>`.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published):
//! `DnsAddressLookup` at `iroh/src/address_lookup/dns.rs`, the query name at
//! `iroh-dns/src/dns.rs:1062`, the record name and the label parser at
//! `iroh-dns/src/attrs.rs`, and the origins at `iroh-dns/src/dns.rs:36` and
//! `:38`. The record grammar itself is not here: `discovery/resolve.zig` owns
//! it, because a pkarr packet's records and a DNS answer's records are the same
//! `key=value` strings and upstream reads both with the same function.
//!
//! What is different from upstream is one thing. Upstream's `resolve` awaits
//! `DnsResolver::lookup_endpoint_by_id_staggered`, which opens a socket, and
//! retries on a 6-second budget. Here the answer is injected: the transport
//! runs the query and hands back the records it got, and this module is the
//! name it queried under, the parser, and the stream. That is the whole
//! difference between a resolver and a resolver's test.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const resolve = @import("resolve.zig");
const item = @import("item.zig");
const transport_addr = @import("../base/transport_addr.zig");

/// The origin n0 operates for production. `iroh-dns/src/dns.rs:36`.
///
/// The trailing dot is part of it, and not a convention: upstream builds the
/// query name as `format!("_iroh.{}.{}", endpoint_id.to_z32(), origin)`, so an
/// origin without one produces a name the host resolver may complete with a
/// local search domain.
pub const prod_origin = "dns.iroh.link.";

/// The origin n0 operates for testing. `iroh-dns/src/dns.rs:38`.
pub const staging_origin = "staging-dns.iroh.link.";

/// Why a DNS name is not an `_iroh` record name.
///
/// Upstream's `ParseError` in `iroh-dns/src/attrs.rs` has one arm per failure
/// and the key decoder's own error chained underneath two of them. A caller of
/// a *name* has one thing to do about all three — do not use the name — so the
/// base32 and key errors collapse into one arm here. The two name-shape arms
/// stay apart because they say different things: one is a name, the other is
/// not a name at all.
pub const NameError = error{
    /// Fewer than two labels. Upstream `ParseError::NumLabels`.
    TooFewLabels,
    /// The first label is not `_iroh`. Upstream `ParseError::NotAnIrohRecord`.
    NotAnIrohRecord,
    /// The second label is not a node id. Upstream chains
    /// `ParseError::DecodingError` over `KeyParsingError`; ozai reports one
    /// arm for the whole chain.
    BadNodeId,
};

/// Buffer size `queryName` needs for an origin of this length.
pub fn queryNameLength(origin: []const u8) usize {
    return resolve.iroh_txt_name.len + 1 + key.NodeId.z32_length + 1 + origin.len;
}

/// The name to query for a node: `_iroh.<z32>.<origin>`.
///
/// Upstream's is `format!("_iroh.{}.{}", endpoint_id.to_z32(), origin)`
/// (`iroh-dns/src/dns.rs:1062`), character for character. The z32 label is 52
/// characters where hex would be 64, which is why a node id is never written as
/// hex on a name: RFC 1035 caps a label at 63 and hex would not fit.
///
/// The name is written into caller storage and the result borrows it, for
/// invariant 6's reason: a name handed back out of a dead frame is a name the
/// query sends from freed memory.
pub fn queryName(out: []u8, node_id: key.NodeId, origin: []const u8) []const u8 {
    std.debug.assert(out.len >= queryNameLength(origin));
    const label = node_id.toZ32();
    var at: usize = 0;
    @memcpy(out[at..][0..resolve.iroh_txt_name.len], resolve.iroh_txt_name);
    at += resolve.iroh_txt_name.len + 1;
    out[at - 1] = '.';
    @memcpy(out[at..][0..label.len], &label);
    at += label.len;
    out[at] = '.';
    at += 1;
    @memcpy(out[at..][0..origin.len], origin);
    return out[0 .. at + origin.len];
}

/// The node a record name is about.
///
/// Upstream's `endpoint_id_from_txt_name` (`iroh-dns/src/attrs.rs`): at least
/// two labels, the first must be `_iroh`, the second is the z32 node id, and
/// every label after that is ignored — which is what lets the same code read a
/// bare `_iroh.<z32>` and a fully qualified `_iroh.<z32>.dns.iroh.link.`.
pub fn endpointIdFromName(name: []const u8) NameError!key.NodeId {
    // Upstream counts the labels before it looks at any of them
    // (`name.split(".").count() < 2`), so a name with no dot is `NumLabels`
    // however it is spelled, and not `NotAnIrohRecord`.
    const first_dot = std.mem.indexOfScalar(u8, name, '.') orelse return error.TooFewLabels;
    if (!std.mem.eql(u8, name[0..first_dot], resolve.iroh_txt_name)) {
        return error.NotAnIrohRecord;
    }
    const rest = name[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
    return key.NodeId.parseZ32(rest[0..second_dot]) catch error.BadNodeId;
}

/// `DnsAddressLookup`: a resolver over one injected TXT answer.
///
/// Upstream implements `resolve` and not `publish` (`iroh/src/address_lookup/dns.rs`),
/// so this takes `resolve.AddressLookup.ignore_publish` for the other method. A
/// DNS record is written by whoever runs the authoritative server for an origin,
/// and a resolver that could also write one would make "what the network says
/// about this node" and "what this node says about itself" the same value.
///
/// The origin is the caller's, not this type's: the name `_iroh.<z32>.<origin>`
/// is built with `queryName` and asked for by `lookup_io.Retrieval`, and by the
/// time an answer exists the name has done its work. Nothing here reads a name,
/// so nothing here keeps an origin — upstream holds an `Arc<String>` and takes
/// a `&str` per call to build a query this service never builds.
pub const DnsAddressLookup = struct {
    /// The TXT records the query returned, already fetched and already one
    /// string per record.
    ///
    /// The joining of a record's character strings is upstream's, and it is
    /// done by the DNS layer and not by either service: `TxtRecordData`'s
    /// `Display` "will parse each character string with
    /// `String::from_utf8_lossy` and then concatenate all strings without a
    /// separator" (`iroh-dns/src/dns.rs`, `TxtRecordData`). One detail of that
    /// sentence ozai does not reproduce: the lossiness. A value here is bytes,
    /// and a byte sequence that is not UTF-8 reaches the parser as it is rather
    /// than as U+FFFD, which for a hex id, a URL or an address means it fails
    /// to parse either way.
    answers: resolve.RecordSet,
    /// How to stop the query. Null when there was none — a lookup against a
    /// cached answer has nothing to cancel, and saying so is different from
    /// having a cancellation that nobody fired. Non-null is fired once per
    /// stream, from `Stream.deinit`, so the handle it points at has to outlive
    /// every stream started here.
    cancellation: ?resolve.Cancellation,
    /// Borrowed by every `resolve.AddressLookup` handed out of `lookup`.
    vtable: resolve.AddressLookup.VTable = dns_vtable,

    /// A resolver over one already-fetched answer set. The records are borrowed,
    /// so they have to stay valid and unchanged until every stream started
    /// against this service is closed; two streams each read their own copy of
    /// the set, and so walk one buffer from its start twice.
    pub fn init(
        answers: resolve.RecordSet,
        cancellation: ?resolve.Cancellation,
    ) DnsAddressLookup {
        return .{
            .answers = answers,
            .cancellation = cancellation,
        };
    }

    /// A handle onto this service. Borrowed, so the service has to outlive every
    /// stream started through the handle.
    pub fn lookup(self: *DnsAddressLookup) resolve.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const dns_vtable: resolve.AddressLookup.VTable = .{
    .publish = resolve.AddressLookup.ignore_publish,
    .resolve = dnsResolve,
};

const DnsState = struct {
    parent: *const DnsAddressLookup,
    /// The arena the item this stream produces lives in. See
    /// `resolve.parseTxt` on why a resolver needs one: an item owns a
    /// `NodeAddr` *and* the bytes behind any custom address in it, and a
    /// `NodeAddr` has nowhere to keep the second. One arena for the whole
    /// stream means `destroy` is one call and the item cannot outlive it.
    arena: std.heap.ArenaAllocator,
    /// `arena.allocator()`, taken after the state reached its final address:
    /// the allocator hands back the arena's own address, and that address must
    /// not move while the allocator is in use.
    alloc: std.mem.Allocator,
    /// The node that was asked about. Upstream hands the *name* it built to
    /// `EndpointInfo::from_txt_lookup`, which reads the id back out of the
    /// second label, so upstream's node id and this one are the same value by
    /// construction; keeping it here states that, and `endpointIdFromName` is
    /// the function that checks the two ends of it agree.
    node_id: key.NodeId,
    /// The service's answer set, by value: two resolves against one service
    /// each get their own position in the buffer.
    answers: resolve.RecordSet,
    /// Which of the two things a one-query lookup can do has already happened.
    /// There is no third: upstream's DNS resolve is a single `once_future`
    /// (`iroh/src/address_lookup/dns.rs`, `resolve`), so the stream is at most
    /// one item or one failure and then ends.
    stage: Stage,
    /// The item, kept until `finish` hands the slice back. A one-slot array and
    /// a flag rather than a `?item.Item`, because a nullable field would leave
    /// the struct partly undefined in the two stages that hold nothing.
    slot: [1]item.Item,
    has_item: bool,

    const Stage = enum { pending, delivered, end };
};

fn dnsResolve(
    ctx: *anyopaque,
    // `resolve.AddressLookup.VTable.resolve`'s parameter order: a vtable entry
    // takes its context first and the allocator second, and the type every
    // service in the tree implements is fixed there rather than here.
    // ziglint-ignore: Z023
    alloc: std.mem.Allocator,
    node_id: key.NodeId,
) resolve.ResolveError!?resolve.Stream {
    const self: *DnsAddressLookup = @ptrCast(@alignCast(ctx));
    // Ownership leaves this function with the `Stream` it returns: the vtable
    // below names `dnsDestroy`, which calls `alloc.destroy` on this pointer,
    // and the `errdefer` after it covers the paths that fail before that. The
    // engine does not follow a pointer handed back to a caller.
    // zwanzig-disable-next-line: store-violations-engine
    const state = try alloc.create(DnsState);
    errdefer alloc.destroy(state);
    state.* = .{
        .parent = self,
        .arena = .init(alloc),
        .alloc = undefined,
        .node_id = node_id,
        .answers = self.answers,
        .stage = .pending,
        .slot = undefined,
        .has_item = false,
    };
    state.alloc = state.arena.allocator();
    // Upstream returns `Some` unconditionally here
    // (`iroh/src/address_lookup/dns.rs`, `resolve`), and so does this: a DNS
    // service always has a name to ask, and a name that does not resolve is a
    // failed query rather than a service that will not answer. The `None` that
    // means "cannot resolve at all" belongs to the publisher.
    return .{
        .state = @ptrCast(@alignCast(state)),
        .vtable = &dns_stream_vtable,
        .alloc = alloc,
        .status = .live,
    };
}

const dns_stream_vtable: resolve.Stream.VTable = .{
    .next = dnsNext,
    .finish = dnsFinish,
    .cancel = dnsCancel,
    .destroy = dnsDestroy,
};

fn dnsNext(state: *anyopaque) ?resolve.Event {
    const self: *DnsState = @ptrCast(@alignCast(state));
    if (self.stage != .pending) return null;
    const value = resolve.parseTxt(self.alloc, self.node_id, self.answers, .dns) catch |reason| {
        self.stage = .end;
        return .{ .failed = .{ .provenance = .dns, .reason = reason } };
    };
    self.slot[0] = value;
    self.has_item = true;
    self.stage = .delivered;
    return .{ .item = value };
}

fn dnsFinish(state: *anyopaque) item.Resolution {
    const self: *DnsState = @ptrCast(@alignCast(state));
    return .{ .resolved = if (self.has_item) self.slot[0..1] else &.{} };
}

fn dnsCancel(state: *anyopaque) void {
    const self: *DnsState = @ptrCast(@alignCast(state));
    if (self.parent.cancellation) |cancellation| cancellation.fire();
}

// `resolve.Stream.VTable.destroy`'s parameter order, for the reason
// `dnsResolve` above gives: the state it is releasing, then the allocator the
// stream was started with. A vtable entry is handed its arguments in the
// order its type declares.
// ziglint-ignore: Z023
fn dnsDestroy(state: *anyopaque, alloc: std.mem.Allocator) void {
    const self: *DnsState = @ptrCast(@alignCast(state));
    // The arena owns the item, its address list and the bytes behind any custom
    // address, so there is nothing to walk and nothing to free individually.
    self.arena.deinit();
    alloc.destroy(self);
}

const t = std.testing;

/// The name and the node of upstream's own `test_from_txt_lookup`, copied from
/// `iroh-dns/src/endpoint_info.rs` at 187f59e80afdae6bd9866002b33d3365c00b06d8.
/// Both are that test's literals: the name it looks up and the `EndpointId` it
/// expects the answer to be about.
const upstream_name =
    "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.";
const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";

test "the query name is the one upstream builds" {
    const id = try key.NodeId.parseHex(upstream_id);
    var buffer: [queryNameLength(prod_origin)]u8 = undefined;
    // Upstream's test looks up this exact name for this exact node, so writing
    // the name here and comparing it to that string is a check against captured
    // bytes rather than against this module's own arithmetic.
    try t.expectEqualStrings(upstream_name, queryName(&buffer, id, prod_origin));
    try t.expectEqual(
        @as(usize, upstream_name.len),
        queryNameLength(prod_origin),
    );
    // The origin is appended whole, trailing dot and all, because the trailing
    // dot is what stops a host resolver appending a local search domain.
    var staged: [queryNameLength(staging_origin)]u8 = undefined;
    try t.expectEqualStrings(
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.staging-dns.iroh.link.",
        queryName(&staged, id, staging_origin),
    );
}

test "a record name reads back the node it was built for" {
    const id = try key.NodeId.parseHex(upstream_id);
    var buffer: [queryNameLength(prod_origin)]u8 = undefined;
    // The two directions of the same round trip, and upstream's own is the same
    // one: it builds the name and then hands that name to
    // `EndpointInfo::from_txt_lookup`, which reads the id back out
    // (`iroh-dns/src/dns.rs:1062` then `iroh-dns/src/attrs.rs`). The check
    // here is that both ends exist and agree, so a change to either that broke
    // the pair would be visible.
    try t.expectEqual(id, try endpointIdFromName(upstream_name));
    try t.expectEqual(id, try endpointIdFromName(queryName(&buffer, id, prod_origin)));
    // Labels after the second are ignored, which is what lets a bare
    // `_iroh.<z32>` and a fully qualified name both work.
    try t.expectEqual(
        id,
        try endpointIdFromName("_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy"),
    );
}

test "a name that is not an iroh record name is refused" {
    // Upstream checks the label count before it looks at any label
    // (`name.split(".").count() < 2`), so a dotless name is `NumLabels` however
    // it is spelled.
    try t.expectError(error.TooFewLabels, endpointIdFromName("_iroh"));
    try t.expectError(error.TooFewLabels, endpointIdFromName(""));
    // A first label that is not `_iroh` is `NotAnIrohRecord`, and it is a
    // different failure from the one above on purpose: this is a name, that is
    // not a name.
    try t.expectError(error.NotAnIrohRecord, endpointIdFromName("_irohx.abc"));
    try t.expectError(error.NotAnIrohRecord, endpointIdFromName("dns.iroh.link."));
    // A second label that is not a node id. Upstream chains
    // `ParseError::DecodingError` over `KeyParsingError`; ozai reports one arm
    // for the whole chain, and the two reasons a label can fail to be a node
    // id both land there: the wrong length and a character outside the
    // alphabet.
    try t.expectError(error.BadNodeId, endpointIdFromName("_iroh.short"));
    try t.expectError(error.BadNodeId, endpointIdFromName("_iroh.!bn!r!"));
}

test "a TXT lookup yields one item, tagged as the dns service" {
    const id = try key.NodeId.parseHex(upstream_id);
    // The three records of upstream's `test_from_txt_lookup`, concatenated into
    // the one-string-per-record shape a TXT answer arrives in.
    const records = "addr=192.168.96.145:60165\x00" ++
        "addr=213.208.157.87:60165\x00" ++
        "relay=https://euw1-1.relay.iroh.network./\x00";
    var service = DnsAddressLookup.init(.init(records), null);

    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    // Upstream's resolve is one `once_future`, so the stream has exactly one
    // pull that produces something and one that ends it.
    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(item.Provenance.dns, first.item.provenance);
    try t.expectEqual(id, first.item.endpoint.node_id);
    try t.expectEqual(@as(usize, 3), first.item.endpoint.addrs.len);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
}

test "a TXT answer that is not records fails the lookup, not the stream" {
    const id = try key.NodeId.parseHex(upstream_id);
    var service = DnsAddressLookup.init(
        .init("relay=https://relay.example./\x00hostname=x\x00"),
        null,
    );
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(error.MalformedRecord, first.failed.reason);
    try t.expectEqual(item.Provenance.dns, first.failed.provenance);
    try t.expect(stream.next() == null);
    // A failed query is a query that ran: it is `resolved` to nothing, which
    // is not the same as never having been asked.
    try t.expectEqual(@as(?usize, 0), stream.finish().itemCount());
}

test "dropping a DNS stream stops the query behind it" {
    const id = try key.NodeId.parseHex(upstream_id);
    var cancels: u32 = 0;
    const Counter = struct {
        fn stop(ctx: *anyopaque) void {
            const count: *u32 = @ptrCast(@alignCast(ctx));
            count.* += 1;
        }
    };
    var service = DnsAddressLookup.init(
        .init("relay=https://relay.example./\x00"),
        .{ .ctx = @ptrCast(@alignCast(&cancels)), .stop = Counter.stop },
    );

    // Never pulled. The item was sitting there ready to be read and the caller
    // walked away, which is the case a stream that only cancels on `next` would
    // get wrong.
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(u32, 0), cancels);
    stream.deinit();
    try t.expectEqual(@as(u32, 1), cancels);
}

test "an empty answer is a node that published nothing" {
    // Upstream's `lookup_txt` errors on a name that does not exist and yields
    // an empty iterator on a name that does, so an answer set with no records is
    // reachable and is a fact about the world rather than a failure to go
    // looking. The item carries the node and no addresses, which is upstream's
    // `EndpointInfo::from_txt_lookup` over an empty `lookup`.
    const id = try key.NodeId.parseHex(upstream_id);
    var service = DnsAddressLookup.init(.init(""), null);
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 0), first.item.endpoint.addrs.len);
    try t.expectEqual(id, first.item.endpoint.node_id);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
}

/// The answer set the ownership checks below run against.
///
/// A relay, two socket addresses and one custom transport address: the last
/// is the only record kind whose payload is not the address itself, so it is
/// the one that has to be copied out of the answer and owned by the stream
/// that produced the item.
const sweep_records =
    "relay=https://euw1-1.relay.iroh.network./\x00" ++
    "addr=192.168.96.145:60165\x00" ++
    "addr=213.208.157.87:60165\x00" ++
    "addr=2a_abab\x00";

/// How many addresses one item over `sweep_records` carries.
const sweep_addresses = 4;

/// The ceiling on a resolve sweep, so that one cannot run forever. A resolve
/// allocates the stream state, the arena behind it and inside that arena the
/// address list and the copied custom payload, so a handful of allocations;
/// sixty-four is well past it.
const allocation_ceiling = 64;

/// What one stream over one answer set must produce: an item carrying this
/// many addresses, or a failure carrying exactly that reason.
const Outcome = union(enum) {
    item: usize,
    refused: resolve.Reason,
};

/// One resolve at a fixed allocation index, and every byte it took and gave
/// back.
///
/// Both outcomes are measured. Whether the resolve produced an item or ran out
/// of memory, the stream state and everything its arena holds came back, so
/// the balance is checked before the result is raised rather than after it: a
/// failing allocation is one of the outcomes this sweep is for, and it must
/// leave as little behind as a successful one does.
fn resolveAtIndex(
    fail_index: usize,
    records: []const u8,
    expect: Outcome,
) !?anyerror {
    var failing = t.FailingAllocator.init(t.allocator, .{
        .fail_index = fail_index,
        .resize_fail_index = fail_index,
    });
    const outcome = oneStream(failing.allocator(), records, expect);
    try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    if (outcome) |_| {
        return null;
    } else |err| {
        return @as(?anyerror, err);
    }
}

/// One resolve over one answer set, and what it produced.
///
/// The stream is released on every path out of here, which is what lets the
/// caller check a balance afterwards rather than trust a `defer` it did not
/// write.
fn oneStream(alloc: std.mem.Allocator, records: []const u8, expect: Outcome) !void {
    const id = try key.NodeId.parseHex(upstream_id);
    var service = DnsAddressLookup.init(.init(records), null);
    var stream = (try service.lookup().resolve(alloc, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    switch (expect) {
        .item => |wanted| {
            const first = stream.next() orelse return error.TestUnexpectedResult;
            switch (first) {
                // Nothing partial survives a failure: this answer is gone and
                // the stream carries on, so a pull that came back this way is
                // the refusal and not a half-built endpoint.
                .failed => |failure| return failure.reason,
                .item => |value| try expectAddresses(value, wanted),
            }
        },
        .refused => |reason| {
            const first = stream.next() orelse return error.TestUnexpectedResult;
            switch (first) {
                .item => return error.ItemWhereARefusalWasNamed,
                .failed => |failure| {
                    try t.expectEqual(item.Provenance.dns, failure.provenance);
                    // An allocator with nothing left refuses too, and this
                    // function does not tell the two apart: below the count
                    // what came back is the allocation, and at or past it what
                    // came back is the answer set. The caller knows which,
                    // because it is the caller that chose the index.
                    if (reason != failure.reason) return failure.reason;
                },
            }
        },
    }
    // Upstream's DNS resolve is one `once_future`, so there is no second pull
    // and `finish` is the whole of what the lookup came to.
    try t.expect(stream.next() == null);
    const resolution = stream.finish();
    const wanted: ?usize = if (std.meta.activeTag(expect) == .item) 1 else 0;
    try t.expectEqual(wanted, resolution.itemCount());
}

/// The addresses one item carries, in the order invariant 2 holds a `NodeAddr`
/// to: relay, then sockets by address, then custom transports. The answer
/// listed the two sockets the other way round on purpose, so a list that was
/// not sorted by the one that owns it would show up here.
fn expectAddresses(value: item.Item, wanted: usize) !void {
    try t.expectEqual(item.Provenance.dns, value.provenance);
    const addrs = value.endpoint.addrs;
    try t.expectEqual(wanted, addrs.len);
    if (wanted != sweep_addresses) return;
    try t.expectEqual(transport_addr.TransportAddr.relay, std.meta.activeTag(addrs[0]));
    try t.expectEqual(transport_addr.TransportAddr.ip, std.meta.activeTag(addrs[1]));
    try t.expectEqual(transport_addr.TransportAddr.ip, std.meta.activeTag(addrs[2]));
    try t.expectEqual(transport_addr.TransportAddr.custom, std.meta.activeTag(addrs[3]));
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 192, 168, 96, 145 } }, .port = 60165 },
        addrs[1].ip,
    );
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 213, 208, 157, 87 } }, .port = 60165 },
        addrs[2].ip,
    );
    try t.expectEqual(@as(u64, 0x2a), addrs[3].custom.id);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, addrs[3].custom.data);
    // And the payload is a copy the stream owns rather than a window into the
    // answer set the service borrows: `parseTxt` copies it because a
    // `NodeAddr` has nowhere to keep the bytes a custom address points at.
    try t.expect(
        @intFromPtr(addrs[3].custom.data.ptr) != @intFromPtr(sweep_records.ptr),
    );
}

/// Every allocation index over an answer set this resolver refuses on its own
/// terms, and what must come out of each one.
///
/// The point is that a refusal is a refusal at every index: an answer set that
/// is not records never publishes an item, whether the run got far enough to
/// find that out or ran out of memory first.
fn resolveRefusalSweep(records: []const u8, reason: resolve.Reason) !void {
    const named: anyerror = reason;
    var index: usize = 0;
    while (index < allocation_ceiling) : (index += 1) {
        // A null outcome is the refusal coming out as it was asked for, so
        // there is nothing left to say about this index.
        const outcome = try resolveAtIndex(index, records, .{ .refused = reason });
        if (outcome == null) continue;
        // Publishing an item is the one defect this sweep is for: the answer
        // set is not records, so there was nothing there to publish.
        if (outcome.? == error.ItemWhereARefusalWasNamed) {
            return error.RefusedAnswerSetPublishedAnItem;
        }
        // Below the count the run could not finish because an allocation
        // failed, and at or past it the answer set itself is what was refused.
        try t.expect(outcome.? == named or outcome.? == error.OutOfMemory);
    }
}

test "every allocation index of a DNS resolve hands back what it took" {
    // The success path first, and the count is discovered rather than written
    // down: a sweep bounded by a number in this test stops covering the
    // resolver the first time it allocates one thing more than it used to.
    var index: usize = 0;
    while (index < allocation_ceiling) : (index += 1) {
        const refusal = try resolveAtIndex(
            index,
            sweep_records,
            .{ .item = sweep_addresses },
        );
        if (refusal == null) break;
        try t.expect(refusal.? == error.OutOfMemory);
    } else return error.MoreAllocationsThanTheCeilingAllows;
    try t.expect(index > 0);

    // And every index below it, where the failure lands somewhere in the
    // stream state, the arena behind it, the address list inside that arena or
    // the custom payload copied beside it.
    for (0..index) |failing| {
        const refusal = try resolveAtIndex(
            failing,
            sweep_records,
            .{ .item = sweep_addresses },
        );
        if (refusal == null) return error.ResolveSucceededBelowItsOwnAllocationCount;
        try t.expect(refusal.? == error.OutOfMemory);
    }

    // A record that is not a record at all is a different refusal, and it
    // happens before the arena takes anything, so it is a different set of
    // indices entirely.
    try resolveRefusalSweep("hostname=x\x00", error.MalformedRecord);
}

test "two streams over one answer set each own their own item" {
    const id = try key.NodeId.parseHex(upstream_id);
    var service = DnsAddressLookup.init(.init(sweep_records), null);

    var first = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    var second = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;

    // Both are live at once, so both items are readable at once: each resolve
    // walked the borrowed record set from its own position and built its item
    // in its own arena, and neither is a second handle onto the other.
    const left = switch (first.next() orelse return error.TestUnexpectedResult) {
        .item => |value| value,
        .failed => |failure| return failure.reason,
    };
    const right = switch (second.next() orelse return error.TestUnexpectedResult) {
        .item => |value| value,
        .failed => |failure| return failure.reason,
    };
    try expectAddresses(left, sweep_addresses);
    try expectAddresses(right, sweep_addresses);
    try t.expect(
        @intFromPtr(left.endpoint.addrs.ptr) != @intFromPtr(right.endpoint.addrs.ptr),
    );
    try t.expect(
        @intFromPtr(left.endpoint.addrs[3].custom.data.ptr) !=
            @intFromPtr(right.endpoint.addrs[3].custom.data.ptr),
    );

    // And releasing one leaves the other's item standing, which is the whole
    // of what owning the item separately means: `Stream.deinit` frees one
    // arena and nothing that belongs to the other.
    first.deinit();
    try t.expectEqual(@as(usize, sweep_addresses), right.endpoint.addrs.len);
    try t.expectEqualSlices(u8, &[_]u8{ 0xab, 0xab }, right.endpoint.addrs[3].custom.data);
    second.deinit();
}

test "a DNS answer that is not records fails the lookup at every allocation index" {
    // `discovery/resolve.zig`'s `parseTxt` fails a DNS answer two ways: a
    // record that is not a `key=value` under one of the three iroh attributes,
    // and an allocator with nothing left. They are separate reasons because a
    // caller reads them differently — the first is a publisher to fix and the
    // second is this lookup's own fault — and a sweep is what holds the first
    // one in place while the second one is being provoked.
    try resolveRefusalSweep("hostname=x\x00", error.MalformedRecord);
    try resolveRefusalSweep(
        "relay=https://relay.example./\x00hostname=x\x00",
        error.MalformedRecord,
    );

    // And a record whose value does not parse is not a refusal at all: it is
    // dropped and the records behind it are kept, which is the one place the
    // answer's own bytes decide the shape of the item.
    const id = try key.NodeId.parseHex(upstream_id);
    var service = DnsAddressLookup.init(
        .init("addr=not-an-address\x00relay=https://relay.example./\x00"),
        null,
    );
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();
    const value = switch (stream.next() orelse return error.TestUnexpectedResult) {
        .item => |item_value| item_value,
        .failed => |failure| return failure.reason,
    };
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    try t.expectEqual(
        transport_addr.TransportAddr.relay,
        std.meta.activeTag(value.endpoint.addrs[0]),
    );
}
