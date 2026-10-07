//! The caller-owned output list both gossip layers append to.
//!
//! The allocator lives in the container and not in `handle`, which is what lets
//! a protocol function take no allocator at all. The membership layer's own
//! container is this same type instantiated over its events.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// A caller-owned list of output events.
///
/// The allocator lives here and not in `handle`, so no protocol function takes
/// one: the caller hands in a container and the state machine appends to it.
/// The membership layer's actions container is this same type over its own
/// events.
///
/// **It owns the list, and not the bytes the entries name.** An `Out` here is
/// a value with slices in it, and those slices borrow: a payload the state
/// forwarded, or one it is holding in its cache for a peer that may graft
/// later, or a `PeerData` a message carried. `push` copies the `Out` value and
/// nothing more, so the entry stays valid exactly as long as the borrow is, and
/// not one moment longer. See `State.handle` for which borrow each event kind
/// carries and what invalidates it.
///
/// **Allocator identity is the caller's throughout.** `init` stores the
/// allocator and both `push` and `deinit` use that one, so the allocator a
/// caller passes is the allocator that must free the list. Growing the list
/// reallocates; `clear` keeps the allocation; `deinit` releases it, once.
/// `push` is the only fallible member, and it fails only with
/// `error.OutOfMemory` — the state machine never refuses to record an event for
/// a protocol reason, because the protocol reasons are its own errors and they
/// travel through `handle`.
///
/// Not thread-safe and not reentrant: two calls appending through one
/// `Actions` interleave. `handle` never calls back into the container it was
/// given, so a state machine holding one is not itself a reentrancy hazard.
pub fn Actions(comptime Out: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        items: std.ArrayList(Out),

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa, .items = .empty };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.gpa);
        }

        /// Keep the allocation, drop the events. A driver that handles events
        /// in a loop clears rather than rebuilds.
        pub fn clear(self: *Self) void {
            self.items.clearRetainingCapacity();
        }

        pub fn count(self: *const Self) usize {
            return self.items.items.len;
        }

        pub fn at(self: *const Self, index: usize) Out {
            return self.items.items[index];
        }

        pub fn slice(self: *const Self) []const Out {
            return self.items.items;
        }

        pub fn push(self: *Self, item: Out) Allocator.Error!void {
            try self.items.append(self.gpa, item);
        }
    };
}
