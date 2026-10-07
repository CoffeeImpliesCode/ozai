//! The iTree's eager and lazy peer sets.
//!
//! Upstream's are `BTreeSet`s, so they iterate in sorted order and a fan-out
//! reaches peers in sorted order. That order is observable: two implementations
//! that fan out in insertion order send the same bytes to the same peers in a
//! different order, and under load that is the difference between a peer being
//! reached by the first retransmission and the last.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");
const limits = @import("limits.zig");
const node_id = @import("node_id.zig");

const NodeId = key.NodeId;
const Error = limits.Error;

/// Upstream's eager and lazy peer sets are `BTreeSet`s, so they iterate in
/// sorted order and a fan-out reaches peers in sorted order. This is one
/// sorted array: the sets hold at most `max_peers` members, and a linear
/// insert beats a tree at that size.
///
/// The order is observable. Two implementations that fan out in insertion
/// order rather than sorted order send the same bytes to the same peers in a
/// different order, and under load that is the difference between a peer being
/// reached by the first retransmission and the last.
pub fn PeerSet(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        items: [capacity]NodeId = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn at(self: *const Self, index: usize) NodeId {
            return self.items[index];
        }

        pub fn slice(self: *const Self) []const NodeId {
            return self.items[0..self.len];
        }

        /// Forget every peer. The slots past `len` keep whatever they held and
        /// are never read again; `len` is what every reader consults.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn contains(self: *const Self, peer: NodeId) bool {
            for (self.slice()) |item| {
                if (node_id.sameNode(item, peer)) return true;
            }
            return false;
        }

        /// Insert in sorted position, leaving an existing member where it is.
        pub fn insert(self: *Self, peer: NodeId) Error!void {
            var slot = self.len;
            for (self.slice(), 0..) |item, index| {
                if (node_id.sameNode(item, peer)) return;
                if (item.order(peer) == .gt) {
                    slot = index;
                    break;
                }
            }
            if (self.len == capacity) return error.PeerSetFull;
            @memmove(
                self.items[slot + 1 .. self.len + 1],
                self.items[slot..self.len],
            );
            self.items[slot] = peer;
            self.len += 1;
        }

        pub fn remove(self: *Self, peer: NodeId) bool {
            for (self.slice(), 0..) |item, index| {
                if (!node_id.sameNode(item, peer)) continue;
                self.removeAt(index);
                self.len -= 1;
                return true;
            }
            return false;
        }

        fn removeAt(self: *Self, index: usize) void {
            @memmove(
                self.items[index .. self.len - 1],
                self.items[index + 1 .. self.len],
            );
        }
    };
}
