//! The `_iroh` `key=value` record grammar: how the bytes of a TXT answer become
//! one `Item`, and how an endpoint's addresses become the records that answer
//! for it.
//!
//! Captured from n0-computer/iroh, `iroh-dns/src/attrs.rs` and
//! `iroh-dns/src/endpoint_info.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30: `IROH_TXT_NAME` and the three `IrohAttr`
//! spellings in the first, `from_txt_lookup` and `from_pkarr_signed_packet` at
//! its bottom, and `SocketAddr::from_str` followed by `CustomAddr::from_str` in
//! the second.
//!
//! This is the only place in the tree that reads a record. A DNS answer and a
//! pkarr packet are two iterators over one shape — upstream says so in one
//! signature — and a NUL-separated buffer is that shape with no allocation and
//! no length prefix. A publisher's output and a resolver's input are then the
//! same value, which is what makes a round trip a test rather than a conversion,
//! and it is why the reading side and the writing side are one file:
//! `parseTxt` and `max_record_length` describe the same record from its two ends,
//! and a bound the encoder does not consult is a bound that is wrong.
//!
//! # Why this is the bottom of the stack
//!
//! `ParseError` is here rather than with the rest of the failure vocabulary
//! because `discovery/lookup.zig`'s `Reason` is a union over the arms this module
//! produces and the arms a packet decoder produces, and a union names the homes
//! of its members. Nothing here imports `discovery/lookup.zig`: the one name
//! that crosses is `ParseError`, and it crosses as a type the other file names
//! rather than as a value either of them computes.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");

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

/// The three `iroh` TXT attributes.
///
/// Upstream's `IrohAttr` (`iroh-dns/src/attrs.rs`) declares `Relay`, `Addr`,
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

/// A set of `key=value` records, in one borrowed buffer, separated by NUL.
///
/// Upstream takes `impl Iterator<Item = impl Display>`
/// (`iroh-dns/src/attrs.rs`, `from_txt_lookup` and `from_pkarr_signed_packet`),
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

/// Turn a set of records into the one `Item` they describe.
///
/// The node id arrives as an argument because upstream takes it from two
/// different places — a DNS name's second label for TXT, the packet's public key
/// for pkarr — and both call the same `TxtAttrs::from_strings` at the bottom of
/// `iroh-dns/src/attrs.rs`. This is that bottom, and it is the only place in the
/// tree that reads a record.
///
/// `last_updated` is null because it is null upstream: `AddressLookupItem::new`
/// is called with `None` by both services (`iroh/src/address_lookup/dns.rs`,
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
    node_id: addr.NodeId,
    records: RecordSet,
    provenance: item.Provenance,
) ParseError!item.Item {
    var set = records;
    var endpoint = addr.NodeAddr.init(node_id);
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
        var storage: [addr.max_inline_length]u8 = undefined;
        var candidate = (try parseTxtRecord(record, &storage)) orelse continue;
        if (candidate == .custom) {
            // Track the copy before insertion can make the endpoint refer to it.
            const data = try alloc.dupe(u8, candidate.custom.data);
            owned.append(alloc, data) catch {
                alloc.free(data);
                return error.OutOfMemory;
            };
            candidate.custom.data = data;
        }
        if (try endpoint.insert(alloc, candidate)) |grown| {
            endpoint = grown;
        } else if (candidate == .custom) {
            // A duplicate does not own the new copy; undo this record's allocation.
            std.debug.assert(owned.items.len > 0);
            alloc.free(owned.pop().?);
        }
    }
    owned.deinit(alloc);
    return item.Item.init(endpoint, provenance, null);
}

fn parseTxtRecord(
    record: []const u8,
    storage: *[addr.max_inline_length]u8,
) ParseError!?addr.TransportAddr {
    const separator = std.mem.indexOfScalar(u8, record, '=') orelse
        return error.MalformedRecord;
    const key_text = record[0..separator];
    const after = record[separator + 1 ..];
    const value_end = std.mem.indexOfScalar(u8, after, '=') orelse after.len;
    const attribute = Attribute.parse(key_text) orelse return error.MalformedRecord;
    const value = after[0..value_end];
    return switch (attribute) {
        .relay => .{ .relay = addr.RelayUrl.parse(value) catch return null },
        .addr => parseTxtAddress(value, storage),
        .user_data => null,
    };
}

fn parseTxtAddress(
    value: []const u8,
    storage: *[addr.max_inline_length]u8,
) ?addr.TransportAddr {
    // Upstream tries the socket form before the custom form and drops invalid values.
    if (std.Io.net.IpAddress.parseLiteral(value)) |literal| {
        return .{ .ip = socketOf(literal) };
    } else |_| {
        return .{ .custom = addr.CustomAddr.parse(value, storage) catch return null };
    }
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
pub const max_record_length = 6 + 8 + addr.RelayUrl.max_host_length + 1 + 5 + 1;

/// Buffer size `PkarrPublisher.writeTxtStrings` needs for this many addresses,
/// separators included. The encoding has no fixed length, because the address
/// list has none, so the caller sizes the buffer and owns it.
pub fn maxTxtStringsLength(addrs: usize) usize {
    return addrs * (max_record_length + 1);
}

test "TXT fail-N preserves unique custom payloads and rolls back malformed records" {
    // Exercise the actual consumer with duplicates and later insertion failures.
    const t = std.testing;
    var secret = try @import("../base/key.zig").SecretKey.fromSeed(@splat(0x51));
    defer secret.deinit();
    const node_id = secret.nodeId();
    const records =
        "addr=1_a1b2c3\x00addr=1_a1b2c3\x00addr=2_01020304\x00" ++
        "addr=127.0.0.1:1234\x00relay=https://relay.example./\x00";
    var reached_success = false;
    for (0..64) |fail_index| {
        var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = fail_index });
        const alloc = failing.allocator();
        const value = parseTxt(alloc, node_id, .init(records), .dns) catch |err| {
            try t.expectEqual(error.OutOfMemory, err);
            try t.expect(failing.has_induced_failure);
            try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        try t.expectEqual(@as(usize, 4), value.endpoint.addrs.len);
        var custom_count: usize = 0;
        for (value.endpoint.addrs) |candidate| {
            if (candidate == .custom) {
                custom_count += 1;
                switch (candidate.custom.id) {
                    1 => try t.expectEqualSlices(u8, &.{ 0xa1, 0xb2, 0xc3 }, candidate.custom.data),
                    2 => try t.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, candidate.custom.data),
                    else => return error.TestUnexpectedResult,
                }
                alloc.free(candidate.custom.data);
            }
        }
        try t.expectEqual(@as(usize, 2), custom_count);
        value.endpoint.deinit(alloc);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        reached_success = true;
        break;
    }
    try t.expect(reached_success);
    var rollback = t.FailingAllocator.init(t.allocator, .{});
    try t.expectError(error.MalformedRecord, parseTxt(
        rollback.allocator(),
        node_id,
        .init(records ++ "unknown=value\x00"),
        .dns,
    ));
    try t.expectEqual(rollback.allocated_bytes, rollback.freed_bytes);
}
