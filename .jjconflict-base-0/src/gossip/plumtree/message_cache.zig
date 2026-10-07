//! The payload half of `TimeBoundCache`: a copy of each message, kept so a
//! peer that grafts late can still be answered.
//!
//! The copy is what lets a `Graft` reply borrow from the state rather than from
//! the caller, and it is why a state is as large as it is: `max_content *
//! cache_slots` bytes are inline in it.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const limits = @import("limits.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");

const DeliveryScope = wire.DeliveryScope;
const Gossip = wire.Gossip;
const MessageId = message_id.MessageId;
const Nanos = limits.Nanos;
const max_content = limits.max_content;
const Error = limits.Error;

/// The payload half of `TimeBoundCache`: a copy of each message, kept so a
/// peer that grafts late can still be answered. The copy is what lets a
/// `Graft` reply borrow from the state rather than from the caller.
pub fn MessageCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Stored = struct {
            id: MessageId,
            expires_at: Nanos,
            scope: DeliveryScope,
            len: u16,
            bytes: [max_content]u8,
        };

        entries: [capacity]Stored = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Forget every payload. The bytes past `len` in each slot stay as they
        /// were and are never read, so this drops the messages without touching
        /// a kilobyte per slot.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn get(self: *const Self, id: MessageId) ?Gossip {
            for (self.entries[0..self.len]) |*entry| {
                if (!entry.id.eql(id)) continue;
                return .{
                    .id = entry.id,
                    .content = entry.bytes[0..entry.len],
                    .scope = entry.scope,
                };
            }
            return null;
        }

        /// `error.MessageTooLarge` once, for both reasons a payload can be
        /// unstorable: the length does not fit the entry's `len`, or it fits
        /// and is still over the bytes the entry holds. The two are proved
        /// here, at the write, and not in the caller — a gossip off the wire
        /// is validated by its hash, and its hash says nothing about length.
        pub fn put(self: *Self, gossip: Gossip, expires_at: Nanos) Error!void {
            // Narrow once, where the bound is proved: the cast admits only a
            // length a `u16` holds, and the comparison is the ceiling of
            // `bytes`. One error answers both, because a payload this entry
            // cannot spell is a payload it cannot keep, and one it truncates
            // answers a `Graft` with bytes that are not the message asked for.
            const length: u16 = std.math.cast(u16, gossip.content.len) orelse
                return error.MessageTooLarge;
            if (length > max_content) return error.MessageTooLarge;

            const at: usize = slot: {
                for (self.entries[0..self.len], 0..) |*entry, index| {
                    if (!entry.id.eql(gossip.id)) continue;
                    break :slot index;
                }
                break :slot self.evictSlot();
            };
            const entry = &self.entries[at];
            entry.id = gossip.id;
            entry.expires_at = expires_at;
            entry.scope = gossip.scope;
            entry.len = length;
            @memcpy(entry.bytes[0..length], gossip.content);
        }

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

        /// See `IdCache.evictSlot`: a full cache drops the payload that expires
        /// soonest rather than failing a broadcast.
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
