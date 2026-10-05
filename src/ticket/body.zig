//! The postcard fields every ticket body is made of: a node id, a relay URL,
//! a socket address and a transport address.
//!
//! A port of `iroh-tickets` 1.0.0, `src/endpoint.rs` and `src/lib.rs`, at
//! commit `cec7f1e119003980f238819e0f320ccb0ceaa691`, fetched 2026-09-30.
//! Upstream declares these once, beside the `Ticket` trait both ticket kinds
//! implement, and writes them the same way in either kind; that is why they
//! are a module of their own and not part of the endpoint ticket.
//! `blob_ticket.zig` reaches them through `endpoint_ticket.zig`, which
//! re-exports this file unchanged.
//!
//! # The order is the wire
//!
//! postcard has no notion of a relay URL, so a relay goes on the wire as the
//! text a human would write, trailing slash and all — invariant 4 — and a
//! different spelling is a different relay to a peer. `canonicalizeAddrs`
//! exists for the same reason: upstream's `BTreeSet` collapses duplicates and
//! imposes its order on whatever order the bytes arrived in, and a list that
//! is neither sorted nor unique breaks invariant 2.
//!
//! # Ownership
//!
//! Nothing here allocates. A custom payload read off the wire is a borrow of
//! the reader's input, so a value this file returns is only meaningful while
//! those bytes are alive; `EndpointTicket.decodeBytes` copies the payload
//! after the list is canonical, and `Decoded` says who owns the copy.
//!
//! The dependency runs one way: this file names `text.zig`'s error set, and
//! nothing in `text.zig` names anything here.
const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");
const ticket_text = @import("text.zig");

const NodeId = key.NodeId;
const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;
const TransportAddr = addr.TransportAddr;
const BodyError = ticket_text.BodyError;

// -- The fields both kinds share ---------------------------------------------

/// The longest text `RelayUrl.format` can produce: the longest scheme, an RFC
/// 1035 host at its limit, the longest port, and the trailing slash
/// invariant 4 requires.
pub const relay_url_text_max = "https://".len + addr.RelayUrl.max_host_length + ":65535".len + 1;

pub const WireVariant = enum(u32) { variant1 = 0 };

pub const TransportTag = enum(u32) { relay = 0, ip = 1, custom = 2 };

/// postcard's `SocketAddr`: an externally tagged family, the address, the
/// port. `std::net::SocketAddr` serialises the two fields of a struct and
/// postcard writes a struct as its fields, so the family byte is the only
/// tag there is.
const IpFamily = enum(u32) { v4 = 0, v6 = 1 };

/// A node id, inline: 32 raw bytes and no length prefix.
///
/// `PublicKey::serialize` sends `self.0.as_bytes().serialize(…)` when the
/// serializer is not human readable, and postcard is not, and a `[u8; 32]`
/// is a tuple of 32 `u8`s. The `00` in front of the 32 bytes in upstream's own
/// vector is the ticket variant, not a length.
pub fn writeNodeId(writer: *postcard.Writer, id: NodeId) postcard.Error!void {
    try writer.writeArray(key.NodeId.byte_length, &id.toBytes());
}

/// 32 raw bytes as a `NodeId`. The bytes are checked, so a well-formed
/// encoding of a non-point is `error.NotANodeId` rather than a value.
pub fn readNodeId(reader: *postcard.Reader) (postcard.Error || BodyError)!NodeId {
    const bytes = try reader.readArray(key.NodeId.byte_length);
    return NodeId.fromBytes(bytes) catch error.NotANodeId;
}

/// A relay URL, as its canonical text: a length prefix and the bytes.
///
/// Invariant 4 is why this is a rendering and not a structured value. The URL
/// goes on the wire as the text a human would write, trailing slash and all,
/// and a different spelling is a different relay to a peer.
pub fn writeRelayUrl(writer: *postcard.Writer, url: RelayUrl) postcard.Error!void {
    var scratch: [relay_url_text_max]u8 = undefined;
    var out = std.Io.Writer.fixed(&scratch);
    // Unreachable for any `RelayUrl.parse` accepted: every term of
    // `relay_url_text_max` is a field bound and `format` writes one of each.
    url.format(&out) catch return error.BufferFull;
    try writer.writeBytes(scratch[0..out.end]);
}

/// A relay URL from its length-prefixed text. The text is validated UTF-8 by
/// `readStr` and then by `RelayUrl.parse`, so both a malformed encoding and a
/// URL this build will not accept are refused — the latter as
/// `error.BadRelayUrl`.
pub fn readRelayUrl(reader: *postcard.Reader) (postcard.Error || BodyError)!RelayUrl {
    const text = try reader.readStr();
    return RelayUrl.parse(text) catch error.BadRelayUrl;
}

/// A socket address: the family as a `varint(u32)`, then the address bytes and
/// the port. An exhaustive family enum, so a family byte this build has no arm
/// for is `error.UnknownVariant`.
pub fn writeSocketAddr(writer: *postcard.Writer, value: SocketAddr) postcard.Error!void {
    switch (value.ip) {
        .v4 => |octets| {
            try writer.writeVariant(IpFamily.v4);
            try writer.writeArray(octets.len, &octets);
        },
        .v6 => |octets| {
            try writer.writeVariant(IpFamily.v6);
            try writer.writeArray(octets.len, &octets);
        },
    }
    try writer.writeU16(value.port);
}

/// A socket address read back. The value owns its bytes and borrows nothing;
/// the reader is left on the first byte after the port.
pub fn readSocketAddr(reader: *postcard.Reader) postcard.Error!SocketAddr {
    const family = try reader.readVariant(IpFamily);
    return .{
        .ip = switch (family) {
            .v4 => .{ .v4 = try reader.readArray(4) },
            .v6 => .{ .v6 = try reader.readArray(16) },
        },
        .port = try reader.readU16(),
    };
}

pub fn writeTransportAddr(writer: *postcard.Writer, one: TransportAddr) postcard.Error!void {
    switch (one) {
        .relay => |url| {
            try writer.writeVariant(TransportTag.relay);
            try writeRelayUrl(writer, url);
        },
        .ip => |socket| {
            try writer.writeVariant(TransportTag.ip);
            try writeSocketAddr(writer, socket);
        },
        .custom => |custom| {
            try writer.writeVariant(TransportTag.custom);
            try writer.writeU64(custom.id);
            try writer.writeBytes(custom.data);
        },
    }
}

/// One address off the wire, with a custom payload still borrowing the
/// reader's input. `decodeBytes` copies the payload after the list is
/// canonical, so a value this returns is only meaningful while `bytes`
/// is alive.
pub fn readTransportAddr(reader: *postcard.Reader) (postcard.Error || BodyError)!TransportAddr {
    return switch (try reader.readVariant(TransportTag)) {
        .relay => .{ .relay = try readRelayUrl(reader) },
        .ip => .{ .ip = try readSocketAddr(reader) },
        .custom => try readCustomAddr(reader),
    };
}

fn readCustomAddr(reader: *postcard.Reader) (postcard.Error || BodyError)!TransportAddr {
    const id = try reader.readU64();
    const data = try reader.readBytes();
    if (data.len > addr.max_inline_length) return error.CustomAddrTooLong;
    return .{ .custom = .{ .id = id, .data = data } };
}

pub fn maxTransportAddrLength(one: TransportAddr) usize {
    return switch (one) {
        .relay => 1 + postcard.varintMax(u64) * 2 + relay_url_text_max,
        .ip => 1 + 1 + 16 + postcard.varintMax(u16),
        .custom => |custom| 1 + postcard.varintMax(u64) * 2 + custom.data.len,
    };
}

/// Sort an address list into `TransportAddr.order` and drop duplicates.
/// Returns the surviving prefix, which is shorter than the input exactly when
/// the input held a duplicate.
///
/// postcard reads a `BTreeSet` by inserting, so upstream's own decoder
/// collapses duplicates and imposes the set's order on whatever order the
/// bytes arrived in. Appending would do neither, and a `NodeAddr` whose list
/// is neither sorted nor unique breaks invariant 2 — which is what makes a
/// ticket an identifier rather than a fresh value on every send, and what
/// makes the bytes a function of the value rather than of the encoding.
///
/// Every ticket upstream writes is already in this order, so in practice this
/// is one comparison pass; the sort is what makes the guarantee hold for a
/// peer that sends the same address twice, or out of order.
///
/// Nothing is allocated and nothing is freed: a duplicate is dropped as a
/// value, so a caller whose list holds *owned* custom payloads must free the
/// dropped one itself, and a caller whose payloads are borrows must not. Both
/// decoders here sidestep the question by collapsing duplicates while the
/// payloads still borrow the frame; see `EndpointTicket.decodeBytes`.
pub fn canonicalizeAddrs(addrs: []TransportAddr) []TransportAddr {
    var out = addrs;
    std.mem.sort(TransportAddr, out, {}, lessTransportAddr);
    var kept: usize = 0;
    // Writes land at or behind the read cursor, so nothing is overwritten
    // before it is read.
    for (out) |one| {
        if (kept != 0 and out[kept - 1].order(one) == .eq) continue;
        out[kept] = one;
        kept += 1;
    }
    out.len = kept;
    return out;
}

fn lessTransportAddr(_: void, a: TransportAddr, b: TransportAddr) bool {
    return a.order(b) == .lt;
}
