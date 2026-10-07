//! The name of a swarm.
//!
//! `TopicId` is 32 opaque bytes an application chose, and there is no privacy
//! story to tell: nothing derives it, nothing scopes it, nothing encrypts under
//! it. The module doc says where that belongs instead.
//!
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const bounds = @import("bounds.zig");

const topic_id_length = bounds.topic_id_length;

/// The swarm a set of messages travels over.
///
/// There is no derivation, no scope, no public/private distinction and no
/// encryption, here or upstream. See the module doc: privacy goes above this,
/// and a scheme invented here would protect nothing.
pub const TopicId = struct {
    bytes: [topic_id_length]u8,

    pub fn fromBytes(bytes: [topic_id_length]u8) TopicId {
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: TopicId) [topic_id_length]u8 {
        return self.bytes;
    }

    pub fn eql(a: TopicId, b: TopicId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Lexicographic, so two implementations agree on which of two topics is
    /// "first" without agreeing on anything else.
    pub fn order(a: TopicId, b: TopicId) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    /// The first five bytes as hex, which is upstream `TopicId::fmt_short` and
    /// the only reason that function exists: a log line about a topic should
    /// not be 64 characters long.
    pub fn shortHex(self: TopicId) [10]u8 {
        const prefix = std.fmt.bytesToHex(self.bytes[0..5], .lower);
        return prefix[0..10].*;
    }
};
