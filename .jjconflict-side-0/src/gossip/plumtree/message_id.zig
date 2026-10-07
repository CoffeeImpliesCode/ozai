//! What a `MessageId` is, and the one way to compute a wrong one.
//!
//! `MessageId` is the content's BLAKE3 hash with no domain separation, and
//! `domainSeparatedId` exists so the test that a domain-separated id is
//! rejected can use a real digest rather than a strawman. The vectors that pin
//! both live in `blake3_vectors.zig`.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const limits = @import("limits.zig");

const id_length = limits.id_length;

/// What a `MessageId` is: the content's BLAKE3 hash, with no domain
/// separation. See the module doc for why that is not an oversight.
pub const MessageId = struct {
    bytes: [id_length]u8,

    /// `blake3(content)`. Upstream `MessageId::from_content`, `plumtree.rs:35-37`.
    pub fn fromContent(content: []const u8) MessageId {
        var id: MessageId = undefined;
        std.crypto.hash.Blake3.hash(content, &id.bytes, .{});
        return id;
    }

    /// The id these 32 bytes are, for a caller that decoded them rather than
    /// hashing a payload. No validation happens here and none is possible: any
    /// 32 bytes are a well-formed id, and whether they name a real message is
    /// answered by `Gossip.validate` on the payload that arrives with it.
    pub fn fromBytes(bytes: [id_length]u8) MessageId {
        return .{ .bytes = bytes };
    }

    /// A copy of the digest, for a caller storing it or writing it out. By
    /// value: the digest is 32 bytes and a borrow of a temporary would outlive
    /// the call.
    pub fn toBytes(self: MessageId) [id_length]u8 {
        return self.bytes;
    }

    /// Whether two ids are the same message. Total over the whole digest, so
    /// this is `==` on the struct spelled out; it is here because a caller
    /// reaching for the id through a union arm cannot use `==` without naming
    /// the payload beside it.
    pub fn eql(a: MessageId, b: MessageId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Digest order, ascending, which is what every id-sorted structure in this
    /// module orders by. Arbitrary but total and stable, so two nodes that
    /// disagree about nothing still agree about it.
    pub fn order(a: MessageId, b: MessageId) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }
};

/// A `MessageId` computed the way it must *not* be.
///
/// `blake3::derive_key` is the natural-looking "do it properly" choice and it
/// is wrong here: a peer that derived the id under a context string computes a
/// different value from every other peer for the same content, and the
/// mismatch is indistinguishable from a spoof. It exists so the rejection test
/// can use a real domain-separated digest rather than a made-up one.
pub fn domainSeparatedId(context: []const u8, content: []const u8) MessageId {
    var hasher = std.crypto.hash.Blake3.initKdf(context, .{});
    hasher.update(content);
    var id: MessageId = undefined;
    hasher.final(&id.bytes);
    return id;
}
