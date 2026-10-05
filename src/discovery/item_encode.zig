//! The canonical bytes one discovery record is written as.
//!
//! Split out of `discovery/item.zig` along the line between what a record *is*
//! and what a record *looks like in bytes*, because those two change for
//! different reasons: the record gains a field when a service starts reporting
//! one, and this layout has to be re-derived when `addr.TransportAddr` gains an
//! arm. `discovery/item_record.zig` owns the record; this module owns the
//! spelling, and depends on nothing but `base/addr.zig` so that neither can
//! drag the other along.
//!
//! # A key, never a wire format
//!
//! The doc of `Item.canonicalBytes` is the authority on what these bytes are
//! for: two records share bytes exactly when they name the same endpoint, and
//! the bytes are a map key or a log key. They are never sent to a peer. This
//! is deliberately not `CustomAddr.writeBinary`'s little-endian wire spelling
//! — the `.custom` arm says so in as many words, and a reader who confuses one
//! for the other finds out.
//!
//! Nor is this encoding's byte order `TransportAddr.order`'s, and `discovery/
//! item.zig`'s module doc gives the second divergence whole: an order that
//! moved when a ticket encoding moved would reorder zones for a reason nobody
//! could see. The two disagree on purpose, and `discovery/item_merge.zig`'s
//! "the tiebreak is the address value order, not the encoded record" test is
//! the pair that reads them apart.
//!
//! # Nothing below pins itself
//!
//! Every tag, field width and byte order here is the one `discovery/item.zig`
//! wrote before this split, and it is preserved verbatim. No test in the tree
//! compares a record against a literal byte string, so the layout is pinned by
//! the module docs and by the properties `discovery/item_record.zig` and
//! `discovery/item_merge.zig` check — a key that is injective on the endpoint,
//! and a sort order that is not this one. A test that named the bytes would be
//! the missing regression guard, and that is a gap rather than a fact this
//! module can assert about itself.

const std = @import("std");
const addr = @import("../base/addr.zig");

/// Tag byte per `TransportAddr` arm, in the union's declaration order, so the
/// first byte of a record names its variant in the rank order
/// `TransportAddr.order` gives the three. It is a name and not a sort
/// position: nothing here compares records against one another.
const tag_relay = 0;
const tag_ip = 1;
const tag_custom = 2;

/// Longest record `encodeAddr` writes: the relay arm, being tag, scheme,
/// port, host length and a maximal host. A new `TransportAddr` arm that
/// encodes longer has to raise this; the switch in `encodeAddr` is exhaustive,
/// so such an arm cannot be added without the compiler pointing at it.
pub const max_encoded_addr_length = 1 + 1 + 2 + 1 + addr.RelayUrl.max_host_length;

/// Why an item cannot be written in its canonical encoding: the caller's buffer
/// was too small for it, or one of its addresses is one no record can hold.
///
/// Only `canonicalBytes` returns this. `Item.order` compares address values
/// and never goes through the encoder, which is why an address no record can
/// hold still has a total order and why this error set is not in `order`'s.
pub const EncodeError = error{
    /// `out` cannot hold the whole encoding. Size it with `maxEncodedLength`.
    BufferTooSmall,
    /// A `CustomAddr` in the address carries more data than a `CustomAddr`
    /// holds inline. `CustomAddr.parse` cannot produce one; an `Item` built by
    /// hand can, and a resolver never does.
    CustomAddrTooLong,
};

/// One address, canonically encoded and self-delimiting, so the records of
/// two different addresses can be walked in step without either list's shape
/// being known in advance. Nothing compares them; see `canonicalBytes`.
pub fn encodeAddr(
    value: addr.TransportAddr,
    out: *[max_encoded_addr_length]u8,
) EncodeError![]const u8 {
    return switch (value) {
        .relay => |url| record: {
            out[0] = tag_relay;
            out[1] = @intFromEnum(url.scheme);
            std.mem.writeInt(u16, out[2..4], url.port, .big);
            const host = url.hostSlice();
            // `hostSlice` is `host[0..host_length]`, so the slice is that `u8`
            // field widened: the record takes the field, and needs no cast.
            out[4] = url.host_length;
            @memcpy(out[5..][0..host.len], host);
            break :record out[0 .. 5 + host.len];
        },
        .ip => |socket| record: {
            out[0] = tag_ip;
            out[1] = switch (socket.ip) {
                .v4 => 0,
                .v6 => 1,
            };
            // One field for both families, so a v4 record and a v6 record are
            // the same shape. The v4 case zero-fills, which loses nothing: a
            // v4 address is four bytes and the other twelve are the padding.
            @memset(out[2..18], 0);
            switch (socket.ip) {
                .v4 => |bytes| @memcpy(out[2..6], &bytes),
                .v6 => |bytes| @memcpy(out[2..18], &bytes),
            }
            std.mem.writeInt(u16, out[18..20], socket.port, .big);
            break :record out[0..20];
        },
        // Big-endian id, unlike the little-endian `CustomAddr.writeBinary`
        // writes for the wire. This record is a local key and is never sent,
        // so the two spellings are free to differ — and they do, which is how
        // a reader who confuses one for the other finds out.
        .custom => |custom| record: {
            // Narrow once, where the bound is proved: the cast admits only a
            // length the record's length byte holds, and the comparison is
            // this arm's own ceiling. One error answers both, because a
            // payload the record cannot spell is one it cannot hold either.
            const data_length = std.math.cast(u8, custom.data.len) orelse
                return error.CustomAddrTooLong;
            if (data_length > addr.max_inline_length) return error.CustomAddrTooLong;
            out[0] = tag_custom;
            std.mem.writeInt(u64, out[1..9], custom.id, .big);
            out[9] = data_length;
            @memcpy(out[10..][0..data_length], custom.data);
            break :record out[0 .. 10 + @as(usize, data_length)];
        },
    };
}
