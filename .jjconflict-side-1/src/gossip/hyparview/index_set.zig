//! Upstream's `IndexSet`: a set whose iteration order is *insertion* order.
//!
//! That order is observable: `onJoin` sends a `ForwardJoin` to
//! `active_view.iter_without(peer)` in it, so a node with the same set of
//! neighbours in a different insertion order sends the same bytes in a
//! different order. It is kept because it is upstream's, and the sets here are
//! small enough that the difference is a copy rather than a tree.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");
const bounds = @import("bounds.zig");
const entropy = @import("rng.zig");
const node_id = @import("node_id.zig");

const NodeId = key.NodeId;
const Rng = entropy.Rng;
const Error = bounds.Error;
const sameNode = node_id.sameNode;
const containsNode = node_id.containsNode;

/// Upstream's `IndexSet`: a set whose iteration order is *insertion* order.
///
/// That order is observable: `onJoin` sends a `ForwardJoin` to
/// `active_view.iter_without(peer)` in it, so a node with the same set of
/// neighbours in a different insertion order sends the same bytes in a
/// different order. It is kept because it is upstream's, and the sets here are
/// small enough that the difference is a copy rather than a tree.
pub fn IndexSet(comptime capacity: usize) type {
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

        /// Forget every peer. Slots past `len` keep their ids and are never
        /// read again.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn contains(self: *const Self, peer: NodeId) bool {
            for (self.slice()) |item| {
                if (sameNode(item, peer)) return true;
            }
            return false;
        }

        /// `true` when the peer was not already a member, which is what
        /// upstream's `IndexSet::insert` returns and what `sendNeighbor` uses
        /// to send exactly one `Neighbor` per request.
        pub fn insert(self: *Self, peer: NodeId) Error!bool {
            if (self.contains(peer)) return false;
            if (self.len == capacity) return error.ActiveViewFull;
            self.items[self.len] = peer;
            self.len += 1;
            return true;
        }

        pub fn remove(self: *Self, peer: NodeId) bool {
            const index = self.indexOf(peer) orelse return false;
            _ = self.removeAt(index);
            return true;
        }

        pub fn indexOf(self: *const Self, peer: NodeId) ?usize {
            for (self.slice(), 0..) |item, index| {
                if (sameNode(item, peer)) return index;
            }
            return null;
        }

        pub fn removeAt(self: *Self, index: usize) NodeId {
            const removed = self.items[index];
            @memmove(
                self.items[index .. self.len - 1],
                self.items[index + 1 .. self.len],
            );
            self.len -= 1;
            return removed;
        }

        /// Upstream `pick_random`.
        pub fn pickRandom(self: *const Self, rng: *Rng) ?NodeId {
            if (self.len == 0) return null;
            return self.items[rng.below(self.len)];
        }

        /// Upstream `pick_random_index`.
        pub fn pickRandomIndex(self: *const Self, rng: *Rng) ?usize {
            if (self.len == 0) return null;
            return rng.below(self.len);
        }

        /// Upstream `pick_random_without`: uniform over the members that are
        /// not in `without`.
        pub fn pickRandomWithout(self: *const Self, without: []const NodeId, rng: *Rng) ?NodeId {
            var candidates: [capacity]NodeId = undefined;
            var found: usize = 0;
            for (self.slice()) |item| {
                if (containsNode(without, item)) continue;
                candidates[found] = item;
                found += 1;
            }
            if (found == 0) return null;
            return candidates[rng.below(found)];
        }

        /// Upstream `shuffled_without_and_capped`: a random `len` members,
        /// excluding `without`.
        pub fn shuffledWithoutAndCapped(
            self: *const Self,
            without: []const NodeId,
            len: usize,
            rng: *Rng,
            out: []NodeId,
        ) usize {
            var scratch: [capacity]NodeId = undefined;
            var found: usize = 0;
            for (self.slice()) |item| {
                if (containsNode(without, item)) continue;
                scratch[found] = item;
                found += 1;
            }
            rng.shuffle(scratch[0..found]);
            const take = @min(len, @min(found, out.len));
            @memcpy(out[0..take], scratch[0..take]);
            return take;
        }
    };
}
