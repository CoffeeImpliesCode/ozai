//! The "have I seen this message" table.
//!
//! Upstream `TimeBoundCache<MessageId, ()>`: ids with an expiry, checked
//! against `now` only when a sweep runs. A re-insert overwrites in place, which
//! is upstream's "the entry was re-added with a later time" case. Evicting is
//! not a failure — a forgotten id costs one duplicate delivery, which the
//! receiving end also tolerates.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const limits = @import("limits.zig");
const message_id = @import("message_id.zig");

const MessageId = message_id.MessageId;
const Nanos = limits.Nanos;

/// Upstream `TimeBoundCache<MessageId, ()>`: ids with an expiry, checked
/// against `now` only when a sweep runs. A re-insert overwrites in place,
/// which is upstream's "the entry was re-added with a later time" case.
pub fn IdCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct { id: MessageId, expires_at: Nanos };

        entries: [capacity]Entry = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Forget every id, cached or not. Expiry is a sweep, not a
        /// destructor: dropping the topic drops the table outright rather than
        /// waiting for entries to age out.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn contains(self: *const Self, id: MessageId) bool {
            for (self.entries[0..self.len]) |entry| {
                if (entry.id.eql(id)) return true;
            }
            return false;
        }

        pub fn put(self: *Self, id: MessageId, expires_at: Nanos) void {
            for (self.entries[0..self.len]) |*entry| {
                if (!entry.id.eql(id)) continue;
                entry.expires_at = expires_at;
                return;
            }
            const at = self.evictSlot();
            self.entries[at] = .{ .id = id, .expires_at = expires_at };
        }

        /// Remove everything that has expired at or before `now`.
        pub fn expireUntil(self: *Self, now: Nanos) void {
            var kept: usize = 0;
            for (self.entries[0..self.len]) |entry| {
                if (entry.expires_at > now) {
                    self.entries[kept] = entry;
                    kept += 1;
                }
            }
            self.len = kept;
        }

        /// The slot to write when the id is new: a free one, or the entry that
        /// expires soonest. A forgotten id costs one duplicate delivery, which
        /// the receiving end also tolerates, so evicting is not a failure.
        fn evictSlot(self: *Self) usize {
            if (self.len < capacity) {
                defer self.len += 1;
                return self.len;
            }
            var soonest: usize = 0;
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.expires_at < self.entries[soonest].expires_at) soonest = index;
            }
            return soonest;
        }
    };
}
