//! What this node knows about a peer, and the bounded tables it keeps it in.
//!
//! `PeerData` is contact bytes, held inline and copied in; `PeerInfo` is a peer
//! with whatever was offered for it; `PeerInfos` is the bounded list a `Shuffle`
//! carries; `PeerDataMap` is the table itself. Everything here is bounded,
//! because "no allocator" costs a bound and the bound is checked at the copy.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const key = @import("../../base/key.zig");
const bounds = @import("bounds.zig");
const node_id = @import("node_id.zig");

const sameNode = node_id.sameNode;

const NodeId = key.NodeId;
const Error = bounds.Error;
const max_known_peers = bounds.max_known_peers;
const max_shuffle_nodes = bounds.max_shuffle_nodes;
const peer_data_max = bounds.peer_data_max;

/// Opaque contact bytes, as upstream `PeerData(Bytes)`.
///
/// Stored inline in the state, bounded, and copied out on the way in. What
/// travels in a *message* is a `[]const u8` slice of one of these, which is
/// the same borrow-by-handle upstream gets from cloning a `Bytes`: valid until
/// the next `handle` on the same state.
pub const PeerData = struct {
    /// Zeroed, and only `len` bytes of it mean anything.
    bytes: [peer_data_max]u8 = [_]u8{0} ** peer_data_max,
    /// `u16` rather than `u8` because `peer_data_max` is 256 and a length of
    /// 255 is a legal value, not the largest one.
    len: u16 = 0,

    pub fn fromBytes(bytes: []const u8) Error!PeerData {
        // Narrow once, where the bound is proved: the cast admits only a
        // length `len` is able to spell, and the comparison is the array's own
        // ceiling. One error answers both, because a length this record
        // cannot spell is a length it cannot own.
        const len: u16 = std.math.cast(u16, bytes.len) orelse
            return error.PeerDataTooLong;
        if (len > peer_data_max) return error.PeerDataTooLong;
        var data: PeerData = .{};
        @memcpy(data.bytes[0..len], bytes);
        data.len = len;
        return data;
    }

    pub fn slice(self: *const PeerData) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn isEmpty(self: *const PeerData) bool {
        return self.len == 0;
    }

    pub fn eql(a: *const PeerData, b: *const PeerData) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }
};

/// A peer and whatever contact data was offered for it. Upstream `PeerInfo`.
pub const PeerInfo = struct {
    id: NodeId,
    /// Borrowed from the state's `peer_data` table or from a message.
    data: ?[]const u8,
};

/// A bounded list of `PeerInfo`.
pub const PeerInfos = struct {
    count: u8,
    items: [max_shuffle_nodes]PeerInfo,

    pub fn init(items: []const PeerInfo) Error!PeerInfos {
        if (items.len > max_shuffle_nodes) return error.ShuffleNodeListTooLong;
        var list: PeerInfos = undefined;
        list.count = @intCast(items.len);
        @memcpy(list.items[0..items.len], items);
        return list;
    }

    pub fn slice(self: *const PeerInfos) []const PeerInfo {
        return self.items[0..self.count];
    }
};

/// A table of peers' contact data. Upstream `HashMap<PI, PeerData>`.
pub const PeerDataMap = struct {
    const Entry = struct { peer: NodeId, data: PeerData };

    entries: [max_known_peers]Entry = undefined,
    len: usize = 0,

    pub fn count(self: *const PeerDataMap) usize {
        return self.len;
    }

    /// Forget every peer's contact data. The `PeerData` values in the slots
    /// past `len` are copies this table took, and `get` reads only the live
    /// prefix, so forgetting the entry is what stops this state from offering
    /// that data again.
    pub fn clear(self: *PeerDataMap) void {
        self.len = 0;
    }

    pub fn get(self: *const PeerDataMap, peer: NodeId) ?*const PeerData {
        for (self.entries[0..self.len]) |*entry| {
            if (sameNode(entry.peer, peer)) return &entry.data;
        }
        return null;
    }

    /// Copies before writing, because the slice handed in is often a borrow of
    /// the entry being replaced.
    ///
    /// The bound is proved here, at the copy, because nothing above this line
    /// proves it: the slice is a peer's claim about itself, carried in a
    /// message, and a message is not obliged to be short. Refusing is the only
    /// honest answer, and it is also what leaves every `PeerData` in the table
    /// one `fromBytes` would have built, so `get`'s `slice` is in bounds by
    /// construction rather than by hope.
    pub fn put(self: *PeerDataMap, peer: NodeId, data: []const u8) Error!void {
        const len: u16 = std.math.cast(u16, data.len) orelse
            return error.PeerDataTooLong;
        if (len > peer_data_max) return error.PeerDataTooLong;
        var copy: PeerData = .{};
        @memcpy(copy.bytes[0..len], data);
        copy.len = len;
        for (self.entries[0..self.len]) |*entry| {
            if (sameNode(entry.peer, peer)) {
                entry.data = copy;
                return;
            }
        }
        if (self.len == max_known_peers) return error.PeerDataFull;
        self.entries[self.len] = .{ .peer = peer, .data = copy };
        self.len += 1;
    }
};
