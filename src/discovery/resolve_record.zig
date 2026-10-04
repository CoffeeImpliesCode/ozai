//! The `key=value` record grammar both services read and both write.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published): the
//! record grammar at `iroh-dns/src/attrs.rs` and `iroh-dns/src/endpoint_info.rs`
//! — `IrohAttr`, `from_txt_lookup`, `from_pkarr_signed_packet`, `to_txt_strings`
//! and `TxtAttrs::from_strings`.
//!
//! It is its own file and not part of `resolve.zig` because upstream reads a
//! DNS answer's records and a pkarr packet's records with the *same* function,
//! and one of the two services lives two layers above the other. What this file
//! is, then, is the thing `discovery/dns.zig` and `resolve_pkarr.zig` both name
//! when they turn bytes into an `item.Item` or back, and it is the whole of
//! `ParseError`.
//!
//! The three pieces are a value (`RecordSet`, with a position in it so two
//! resolves over one buffer cannot tread on each other), a reader (`parseTxt`,
//! and the only place in the tree that reads a record), and a writer's two
//! bounds (`max_record_length` and `maxTxtStringsLength`, which
//! `resolve_publish.zig`'s `writeTxtStrings` relies on rather than hopes for).
//! `writeSocketAddr` is here rather than beside them because it is the same
//! grammar read backwards: `std`'s `IpAddress` text, both ways.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const item = @import("item.zig");
const node_addr = @import("../base/node_addr.zig");
const relay_url = @import("../base/relay_url.zig");
const transport_addr = @import("../base/transport_addr.zig");

/// Why a set of records is not an `Item`.
///
/// `DecodeError`, plus the one way a *record* can be wrong and the one way this
/// code can run out of memory. A value that is well formed but unusable — a
/// relay URL that will not parse, an address of no known shape — is not in here:
/// upstream drops those and `parseTxt` drops them, because a resolver that
/// failed instead would lose the good records behind the bad one.
pub const ParseError = error{
    /// A record that is not `key=value`, or whose key is not one of the three
    /// `iroh` attributes. Upstream fails the whole lookup on either
    /// (`ParseError::UnexpectedFormat`, `ParseError::AttrFromString`, both in
    /// `iroh-dns/src/attrs.rs`).
    MalformedRecord,
    OutOfMemory,
};
/// The record name both services write under: `_iroh`.
///
/// `iroh-dns/src/attrs.rs`, `pub const IROH_TXT_NAME: &str = "_iroh";`. It is
/// here and not in `discovery/dns.zig` because it is the one thing a pkarr
/// packet and a DNS query have in common, and a publisher needs it too:
/// upstream's `TxtAttrs::to_pkarr_signed_packet` hands `IROH_TXT_NAME` to
/// `pkarr::SignedPacket::from_txt_strings`, same file.
pub const iroh_txt_name = "_iroh";
/// `UserData` with `#[strum(serialize_all = "kebab-case")]`, derives `Ord`, and
/// collects into a `BTreeMap`, so records come back out grouped in declaration
/// order however the packet or the answer listed them. The spellings are
/// upstream's: lower case, and `user-data` with a hyphen — "The resource record
/// uses the lower-case names", and `strum`'s generated match is exact.
pub const Attribute = enum {
    /// `relay=<url>`: the home relay.
    relay,
    /// `addr=<addr>`: an IP socket, or a custom transport address.
    addr,
    /// `user-data=<text>`.
    ///
    /// Read and discarded. Upstream keeps it on `EndpointData`; `item.Item` has
    /// nowhere to put it. Discarding is what keeps a real published record
    /// readable: refusing `user-data=` would fail every endpoint that publishes
    /// one, and an endpoint that cannot be found is worse than one whose note
    /// is lost.
    user_data,

    /// Every arm, for iteration. A test holds this against the enum, so an arm
    /// cannot be added without a spelling.
    pub const all = [_]Attribute{ .relay, .addr, .user_data };

    /// The attribute whose record key is `key_text`, or null when the key is not
    /// one of the three. The match is exact — `strum`'s generated `FromStr` is
    /// too — so a case-folded or hyphen-less key is an unknown key rather than
    /// a spelling of one of these.
    pub fn parse(key_text: []const u8) ?Attribute {
        inline for (all) |attribute| {
            if (std.mem.eql(u8, key_text, attribute.text())) return attribute;
        }
        return null;
    }

    /// The key this attribute is written under in a `key=value` record. A slice
    /// of a string literal, so it is valid for the life of the program.
    pub fn text(self: Attribute) []const u8 {
        return switch (self) {
            .relay => "relay",
            .addr => "addr",
            .user_data => "user-data",
        };
    }
};
/// because a DNS answer and a pkarr packet are different iterators over one
/// shape. A NUL-separated buffer is that shape with no allocation and no length
/// prefix, and it is the shape DNS already has: a TXT record's character strings
/// are NUL-free by construction, so a block of them is exactly this. A
/// publisher's output and a resolver's input are then the same value, which is
/// what makes a round trip a test rather than a conversion.
///
/// A `RecordSet` is a value with a position in it, so it is copied into whatever
/// reads it and never shared: two resolves against one service each get their
/// own, and neither can tread on the other's place in the buffer.
pub const RecordSet = struct {
    /// The NUL-separated records, borrowed from whoever holds the answer. A
    /// `RecordSet` owns none of them and has no `deinit`: the buffer has to
    /// outlive every read made through any copy of this set.
    bytes: []const u8,
    /// How far this copy has read, zero for a set nothing has read from. It is
    /// per-copy state rather than a property of the buffer, which is what lets
    /// two sets read one buffer from its start at the same time.
    at: usize = 0,

    /// A set over `bytes`, positioned at its first record.
    pub fn init(bytes: []const u8) RecordSet {
        return .{ .bytes = bytes };
    }

    /// The next record, or null at the end. A trailing NUL is not a record: the
    /// block is a list and not a counted sequence, so it may end with one or
    /// without.
    pub fn next(self: *RecordSet) ?[]const u8 {
        if (self.at >= self.bytes.len) return null;
        const end = std.mem.indexOfScalar(u8, self.bytes[self.at..], 0) orelse {
            const record = self.bytes[self.at..];
            self.at = self.bytes.len;
            return record;
        };
        const record = self.bytes[self.at..][0..end];
        self.at += end + 1;
        return record;
    }
};
/// `iroh/src/address_lookup/pkarr.rs:546`). A timestamp would be something the
/// publisher knew and the reader did not, and inventing one on the reading side
/// would put a value into the order that no two services could ever agree on.
///
/// # What the result owns, and what a caller has to release
///
/// Everything the result owns comes from `alloc`: the address list, and the
/// bytes behind every `addr=<custom>` value. The second one is not optional.
/// `addr.CustomAddr.data` borrows — `CustomAddr.parse` needs storage for the
/// inline data and `NodeAddr.insert` copies the slice header, not the bytes it
/// points at — so the bytes are copied out here, and that copy has to outlive
/// the item.
///
/// So `alloc` has to outlive the item, and `NodeAddr.deinit` releases the
/// address list and nothing else, because a `NodeAddr` has no field for the
/// payloads. On the success path the item owns both: a caller that holds it in
/// an arena gets both back from one `arena.deinit`, which is what both
/// resolvers below do, and a caller that does not has to walk `addrs` and free
/// each custom address's `data` itself. This is invariant 6 read from the
/// other end: the value never carries a slice into storage it does not own, and
/// where it cannot own it, the owner is named.
///
/// On either error nothing survives: the address list and every payload copied
/// before the failing record are released before the error leaves, and no
/// record after it is read. There is no partial item to clean up, and `alloc` is
/// back to what it was on entry.
///
/// Upstream's three rules, all three load-bearing:
///
/// * `s.split('=')` and take the first two pieces, so a value runs from the
///   first `=` to the *second* and everything after the second is dropped. A
///   relay URL carrying a query does not survive it. That is upstream's
///   behaviour and not something to fix here, because a fix would make ozai's
///   reader disagree with every other one.
/// * A record that does not split, or a key that is not one of the three, fails
///   the whole lookup. Upstream returns `Err` and the resolve yields an error
///   rather than a partial answer.
/// * A value that does not parse is dropped and the rest of the set is kept, by
///   `filter_map` in `endpoint_info_from_attrs`. Upstream loses a bad address
///   and keeps the good ones, and a reader that failed instead would hand back
///   nothing at all, which is the one outcome a caller cannot act on.
pub fn parseTxt(
    alloc: std.mem.Allocator,
    node_id: key.NodeId,
    records: RecordSet,
    provenance: item.Provenance,
) ParseError!item.Item {
    var set = records;
    var endpoint = node_addr.NodeAddr.init(node_id);
    // `NodeAddr.deinit` frees the outer list and nothing else, and an empty
    // list costs nothing to free, so this is unconditional.
    errdefer endpoint.deinit(alloc);
    // Every custom address data buffer copied out so far, so the error path can
    // hand them all back. `NodeAddr.deinit` frees the address list and nothing
    // else, so a buffer that only an earlier record allocated has no owner left
    // to free it once the item is discarded. On the success path the list is
    // dropped without freeing, because by then the buffers belong to the item.
    var owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (owned.items) |bytes| alloc.free(bytes);
        owned.deinit(alloc);
    }
    while (set.next()) |record| {
        const separator = std.mem.indexOfScalar(u8, record, '=') orelse
            return error.MalformedRecord;
        const key_text = record[0..separator];
        const after = record[separator + 1 ..];
        const value_end = std.mem.indexOfScalar(u8, after, '=') orelse after.len;
        const attribute = Attribute.parse(key_text) orelse return error.MalformedRecord;
        const value = after[0..value_end];
        switch (attribute) {
            .relay => {
                const url = relay_url.RelayUrl.parse(value) catch continue;
                // A duplicate is not a failure: `insert` reports one by
                // returning null and upstream dedups too, in
                // `EndpointData::new`. Only the error is an error.
                endpoint = (try endpoint.insert(alloc, .{ .relay = url })) orelse endpoint;
            },
            .addr => {
                // Upstream tries `SocketAddr::from_str` and then
                // `CustomAddr::from_str`, dropping the record if neither takes
                // it. The socket parse is `std`'s, because a socket address on
                // a wire is Rust's `SocketAddr` text and nothing else — see
                // `writeSocketAddr` for the other direction.
                if (std.Io.net.IpAddress.parseLiteral(value)) |literal| {
                    const grown = try endpoint.insert(alloc, .{ .ip = socketOf(literal) });
                    endpoint = grown orelse endpoint;
                } else |_| {
                    var storage: [addr.max_inline_length]u8 = undefined;
                    const custom = addr.CustomAddr.parse(value, &storage) catch continue;
                    // `CustomAddr.data` borrows `storage`, which dies at the end
                    // of this block, and `NodeAddr.insert` copies the slice
                    // header rather than the bytes it points at. So the bytes
                    // are copied out here, from `alloc`, and that copy has to
                    // outlive the item — which is the rule `parseTxt` states
                    // about its allocator.
                    const data = try alloc.dupe(u8, custom.data);
                    // Recorded before the address is inserted, and not after,
                    // because recording it can fail and the insert is what makes
                    // the item refer to the copy. Appending first means every
                    // later path out of here frees the copy through `owned`,
                    // where the error path walks it; the other order handed back
                    // an item holding a buffer that nothing owned as soon as
                    // this append failed. The one path the tracker cannot cover
                    // is this one, and it frees the copy itself.
                    owned.append(alloc, data) catch {
                        alloc.free(data);
                        return error.OutOfMemory;
                    };
                    const grown = endpoint.insert(alloc, .{
                        .custom = .{ .id = custom.id, .data = data },
                    }) catch return error.OutOfMemory;
                    if (grown) |next| {
                        endpoint = next;
                    } else {
                        // Already present, so nothing refers to the copy. It is
                        // the last thing `owned` recorded, so freeing it is
                        // taking back that one entry; the list itself is given
                        // up whole below whether or not this arm ran.
                        alloc.free(owned.items[owned.items.len - 1]);
                        owned.items.len -= 1;
                    }
                }
            },
            .user_data => {},
        }
    }
    owned.deinit(alloc);
    return item.Item.init(endpoint, provenance, null);
}
/// `std.Io.net.IpAddress` to `addr.SocketAddr`.
fn socketOf(literal: std.Io.net.IpAddress) addr.SocketAddr {
    return switch (literal) {
        .ip4 => |address| .{ .ip = .{ .v4 = address.bytes }, .port = address.port },
        .ip6 => |address| .{ .ip = .{ .v6 = address.bytes }, .port = address.port },
    };
}
/// `addr.SocketAddr` to the text an `addr=` record carries.
///
/// `std`'s, and not `addr.SocketAddr.format`, and the reason is worth writing
/// down because the two differ: `base/addr.zig` renders an IPv6 address as bare
/// lower-case hex, which is this project's own canonical display form for logs
/// and tickets, and it is *not* what a peer or a DNS record carries. Upstream
/// writes `addr.to_string()` on a `std::net::SocketAddr` and reads it with
/// `SocketAddr::from_str` (`iroh-dns/src/endpoint_info.rs`), and `std`'s
/// `IpAddress` parser and formatter are the same text on both sides of that
/// pair — brackets, `::` compression, `::ffff:` for a mapped address and all.
pub fn writeSocketAddr(socket: addr.SocketAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const literal: std.Io.net.IpAddress = switch (socket.ip) {
        .v4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = socket.port } },
        .v6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = socket.port } },
    };
    return literal.format(writer);
}
/// Why a publisher could not write its records.
pub const EncodeError = error{
    /// `out` is smaller than `maxTxtStringsLength` for the address list. The
    /// only way a fixed writer fails is a full buffer, so a write failure and a
    /// buffer the caller sized too small are one event.
    BufferTooSmall,
    /// `publish` has not been called, so there is nothing to write.
    NothingPublished,
};
/// Longest single `key=value` record, being the relay arm: `relay=`, the
/// longest scheme `https://`, a 253-byte host, a five-digit port, and the
/// trailing `/` invariant 4 requires. The other two arms are far shorter —
/// `addr=` with either 21 bytes of IPv4 or 39 of IPv6, or 77 bytes of custom id
/// and data — and the relay arm is the one that has to be right.
pub const max_record_length = 6 + 8 + relay_url.RelayUrl.max_host_length + 1 + 5 + 1;
/// separators included. The encoding has no fixed length, because the address
/// list has none, so the caller sizes the buffer and owns it.
pub fn maxTxtStringsLength(addrs: usize) usize {
    return addrs * (max_record_length + 1);
}

const t = std.testing;const t = std.testing;
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
test "the attribute set is upstream's three, spelled upstream's way" {
    // `IrohAttr` in `iroh-dns/src/attrs.rs`: three arms, `kebab-case`, and
    // "The resource record uses the lower-case names".
    try t.expectEqual(@as(usize, 3), Attribute.all.len);
    // `all` is what `parse` iterates. An arm missing from it would be
    // unreadable and unwritable, so the list is held to the enum here.
    try t.expectEqual(Attribute.all.len, @typeInfo(Attribute).@"enum".fields.len);
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
        try relay_url.RelayUrl.parse("https://euw1-1.relay.iroh.network./"),
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
        try relay_url.RelayUrl.parse("https://relay.example./"),
        value.endpoint.addrs[0].relay,
    );
}
/// Release a parsed item the way `parseTxt` says a caller releases it: the
/// address list with `NodeAddr.deinit`, and the payload behind every custom
/// address by hand, because `deinit` frees the list and nothing else.
fn releaseParsed(alloc: std.mem.Allocator, value: item.Item) void {
    for (value.endpoint.addrs) |one| {
        if (one == .custom) alloc.free(one.custom.data);
    }
    value.endpoint.deinit(alloc);
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
/// One parse of `set` that keeps what it built and gives all of it back. The
/// sweeps use it as the probe so a boundary is only ever counted against a run
/// that releases everything, and so a successful run can compare its live
/// bytes against the same shape.
fn parseAndRelease(
    alloc: std.mem.Allocator,
    node_id: key.NodeId,
    set: RecordSet,
) ParseError!void {
    const value = try parseTxt(alloc, node_id, set, .pkarr);
    releaseParsed(alloc, value);
}
// The whole of one custom record's ownership, a boundary at a time. Three
// allocations stand between the record and the item: the payload copy, the
// tracker that records it, and the growth of the address list it is inserted
// into. The middle one is the one that used to be missed — the copy went into
// the address list first and was recorded afterwards, so a failure in the
// recording handed back an item holding a buffer no path owned — and the
// count below is what stops a fourth boundary from being added silently.
test "a custom payload is released however the record fails" {
    const id = try corpusId(6);
    const records: RecordSet = .init("addr=1_a1b2c3\x00");

    try t.expectEqual(@as(usize, 3), try boundariesOf(parseAndRelease, .{ id, records }));

    for (0..3) |refused| {
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        // `parseTxt` promises that nothing survives either error: the address
        // list and every payload copied before the failing record are released
        // before the error leaves. `t.allocator` would name the leak at the end
        // of the test; the byte equality is the stronger claim, because it
        // says the allocator is back to what it was on entry at every boundary
        // rather than only at the end.
        try t.expectError(error.OutOfMemory, parseAndRelease(failing.allocator(), id, records));
        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    // The retry the contract promises, and the half of the ownership sentence
    // the byte count above cannot reach: the payload is the caller's to
    // release, because `NodeAddr.deinit` frees the address list and nothing
    // else. Reading it back here is the other half — an item that copied the
    // bytes out and then lost track of them would fail on the leak check above
    // and never reach this line.
    var working = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    const alloc = working.allocator();
    const value = try parseTxt(alloc, id, records, .pkarr);
    defer releaseParsed(alloc, value);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    switch (value.endpoint.addrs[0]) {
        .custom => |custom| {
            try t.expectEqual(@as(u64, 1), custom.id);
            try t.expectEqualSlices(u8, &.{ 0xa1, 0xb2, 0xc3 }, custom.data);
        },
        else => return error.TestUnexpectedResult,
    }
}
// Three good records, then a value that will not parse — dropped, with the
// rest kept, upstream's `filter_map` — and then a key that is not one of the
// three, which fails the whole lookup and takes the good records with it.
test "a malformed tail releases the records that came before it" {
    const id = try corpusId(22);
    const records: RecordSet = .init(
        "relay=https://relay.example./\x00" ++
            "addr=1_a1b2c3\x00" ++
            "relay=not a url\x00" ++
            "hostname=x\x00",
    );

    // Two address-list growths, one payload copy, and the tracker that owns it.
    // The dropped relay allocates nothing and the tail allocates nothing, so
    // four is every boundary this record set has.
    try t.expectEqual(@as(usize, 4), try boundariesOf(parseAndRelease, .{ id, records }));

    for (0..4) |refused| {
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        try t.expectError(error.OutOfMemory, parseAndRelease(failing.allocator(), id, records));
        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    // The tail itself, with nothing refused. `MalformedRecord` is not an
    // allocation, so the same promise has to hold on this path and the sweep
    // above is not what proves it: the address list and the payload copy are
    // both released before the error leaves, and there is no partial item.
    var whole = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    try t.expectError(error.MalformedRecord, parseAndRelease(whole.allocator(), id, records));
    try t.expect(!whole.has_induced_failure);
    try t.expectEqual(whole.allocated_bytes, whole.freed_bytes);
}
// The same record twice. `NodeAddr.insert` reports the second one as already
// present and returns null *without allocating*, so the payload copy made for
// it is unreferenced the moment its record has been read — and only `parseTxt`
// is in a position to know that, which is why the release is this loop's job
// rather than the address list's.
test "a duplicate custom payload leaves one copy behind and not two" {
    const id = try corpusId(23);
    const records: RecordSet = .init(
        "addr=1_a1b2c3\x00" ++
            "addr=1_a1b2c3\x00" ++
            "addr=127.0.0.1:1234\x00",
    );

    // First copy, the tracker that owns it, the list it goes into, the second
    // copy, and the growth that adds the socket address. The duplicate's own
    // insert allocates nothing, which is the whole reason there are five
    // boundaries here and not six.
    try t.expectEqual(@as(usize, 5), try boundariesOf(parseAndRelease, .{ id, records }));

    for (0..5) |refused| {
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        try t.expectError(error.OutOfMemory, parseAndRelease(failing.allocator(), id, records));
        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    var working = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    const alloc = working.allocator();
    const value = try parseTxt(alloc, id, records, .pkarr);
    defer releaseParsed(alloc, value);

    // Two addresses, one payload. The byte count is what says the second copy
    // went back: an item that kept it would hold one extra copy per duplicate
    // record, which a count of addresses cannot see and which only surfaces as
    // a leak at the end of the test.
    try t.expectEqual(@as(usize, 2), value.endpoint.addrs.len);
    try t.expectEqual(
        2 * @sizeOf(transport_addr.TransportAddr) + 3,
        working.allocated_bytes - working.freed_bytes,
    );
    // `TransportAddr` orders relay, then ip, then custom, so the payload is on
    // the second of the two.
    switch (value.endpoint.addrs[1]) {
        .custom => |custom| try t.expectEqualSlices(u8, &.{ 0xa1, 0xb2, 0xc3 }, custom.data),
        else => return error.TestUnexpectedResult,
    }
}
// One record set that grows the address list five times and copies two
// payloads along the way. This is the case the single-record sweep cannot
// reach: a refusal in the middle leaves an address list, a tracker and one
// payload behind it, and all three have to come back.
test "every boundary of a growing multi-record set releases what came before it" {
    const id = try corpusId(29);
    const records: RecordSet = .init(
        "relay=https://a.example./\x00" ++
            "relay=https://b.example./\x00" ++
            "addr=1_a1b2c3\x00" ++
            "addr=2_deadbeef\x00" ++
            "addr=127.0.0.1:1234\x00" ++
            "addr=192.0.2.9:443\x00",
    );

    // Six address-list growths — one per address that is kept — plus the first
    // payload copy, the tracker that owns it, and the second payload copy. The
    // second `owned` append fits the tracker's capacity the first one bought,
    // so it is not a boundary.
    try t.expectEqual(@as(usize, 9), try boundariesOf(parseAndRelease, .{ id, records }));

    for (0..9) |refused| {
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        try t.expectError(error.OutOfMemory, parseAndRelease(failing.allocator(), id, records));
        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    var working = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    const alloc = working.allocator();
    const value = try parseTxt(alloc, id, records, .pkarr);
    defer releaseParsed(alloc, value);

    try t.expectEqual(@as(usize, 6), value.endpoint.addrs.len);
    // Six addresses and both payloads: nothing was dropped and nothing was
    // copied twice.
    try t.expectEqual(
        6 * @sizeOf(transport_addr.TransportAddr) + 7,
        working.allocated_bytes - working.freed_bytes,
    );
    // Relay, then ip, then custom, so the two payloads are last and in id
    // order.
    switch (value.endpoint.addrs[4]) {
        .custom => |custom| try t.expectEqualSlices(u8, &.{ 0xa1, 0xb2, 0xc3 }, custom.data),
        else => return error.TestUnexpectedResult,
    }
    switch (value.endpoint.addrs[5]) {
        .custom => |custom| try t.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, custom.data),
        else => return error.TestUnexpectedResult,
    }
}
