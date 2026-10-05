//! The payload paths: what a received `Gossip` does, and how a payload leaves.
//!
//! `onGossip` and the two pushes it drives — `eagerPush` for the peers that
//! get the payload now, `lazyPush` for the ones that get its id after the
//! dispatch timer — with the queue `lazyPush` fills and `onDispatchTimer`
//! flushes. The claim the arrival drops a graft timer for is in
//! `state_missing.zig`, and the tree optimisation that arrival may run is in
//! `state_control.zig`.
const std = @import("std");
const key = @import("../../base/key.zig");
const actions = @import("actions.zig");
const claim_table = @import("claim_table.zig");
const limits = @import("limits.zig");
const wire = @import("message.zig");
const node_id = @import("node_id.zig");
const tree = @import("state_tree.zig");
const missing = @import("state_missing.zig");
const control = @import("state_control.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = actions.Actions;
const Claim = claim_table.Claim;
const Error = limits.Error;
const Nanos = limits.Nanos;
const max_claims = limits.max_claims;
const max_ihaves_per_message = limits.max_ihaves_per_message;
const max_queue_peers = limits.max_queue_peers;
const max_queued_ihaves = limits.max_queued_ihaves;
const Gossip = wire.Gossip;
const IHaves = wire.IHaves;
const IHave = wire.IHave;
const OutEvent = wire.OutEvent;
const State = tree.State;

/// Upstream `on_gossip`.
///
/// The first arm is the invariant this module exists to hold: a message
/// whose id is not the hash of its content is dropped, and dropping it
/// does nothing at all to the sender. No `Prune`, no demotion to lazy, no
/// record, no reply, no timer.
pub fn onGossip(
    self: *State,
    sender: NodeId,
    message: Gossip,
    now: Nanos,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    if (!message.validate()) return;

    if (self.received_messages.contains(message.id)) {
        // A duplicate. The sender has a path to us that we do not need, so
        // it moves to the lazy side of the tree and is told so.
        try addLazy(self, sender);
        try out.push(.{
            .send_message = .{ .to = sender, .message = .{ .prune = {} } },
        });
        return;
    }

    switch (message.scope) {
        .swarm => |arrived| {
            const next = arrived.next();
            const forwarded: Gossip = .{
                .id = message.id,
                .content = message.content,
                .scope = .{ .swarm = next },
            };
            self.received_messages.put(message.id, now + self.config.message_id_retention);
            try self.cache.put(forwarded, now + self.config.message_cache_retention);
            try eagerPush(self, forwarded, sender, out);
            try lazyPush(self, forwarded, sender, out);
            missing.forgetGraftTimer(self, message.id);
            var claims: [max_claims]Claim = undefined;
            if (missing.takeMissing(self, message.id, &claims)) |drained| {
                try control.optimizeTree(self, sender, next, drained, out);
            }
            self.stats.max_last_delivery_hop =
                @max(self.stats.max_last_delivery_hop, arrived.value);
        },
        .neighbors => {},
    }

    try out.push(.{ .emit_event = .{
        .content = message.content,
        .delivered_from = sender,
        .scope = message.scope,
    } });
}

/// Upstream `on_dispatch_timer`. One long queue is cut into several
/// messages rather than overrunning a frame. The queue is in the order the
/// ids were queued, which is sorted within one `lazyPush` call — `queueIHave`
/// appends and `lazy_push_peers` iterates sorted — and in burst order
/// across calls.
pub fn onDispatchTimer(self: *State, out: *Actions(OutEvent)) (Error || Allocator.Error)!void {
    // Released before the flush, not after it, for the reason `onIHave`
    // gives: the caller handed us the timer this call consumes, so a latch
    // still set when an append below is refused is a claim that a timer
    // exists which nothing will ever fire. `lazyPush` arms one only while
    // the latch is clear, so clearing it here is what lets the next event
    // arm one — and the ids still queued go out on that timer.
    self.dispatch_timer_scheduled = false;
    while (self.lazy_push_queue_len > 0) {
        const entry = self.lazy_push_queue[0];
        var sent: usize = 0;
        while (sent < entry.count) {
            const n = @min(max_ihaves_per_message, entry.count - sent);
            const list = try IHaves.init(entry.items[sent..][0..n]);
            try out.push(.{ .send_message = .{
                .to = entry.peer,
                .message = .{ .i_have = list },
            } });
            sent += n;
        }
        @memmove(
            self.lazy_push_queue[0 .. self.lazy_push_queue_len - 1],
            self.lazy_push_queue[1..self.lazy_push_queue_len],
        );
        self.lazy_push_queue_len -= 1;
    }
}

/// Upstream `eager_push`: the whole payload, to every eager peer but the
/// one it came from and but ourselves.
pub fn eagerPush(
    self: *State,
    gossip: Gossip,
    sender: NodeId,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    for (self.eager_push_peers.slice()) |peer| {
        if (node_id.sameNode(peer, self.me) or node_id.sameNode(peer, sender)) continue;
        try out.push(.{ .send_message = .{
            .to = peer,
            .message = .{ .gossip = gossip },
        } });
    }
}

/// Upstream `lazy_push`: ids only, batched. The dispatch timer is
/// scheduled even when there is no lazy peer, which is upstream's
/// behaviour and shows up in the ported unit tests: the timer exists to
/// coalesce a burst, and a burst that happens to have no lazy peer still
/// armed one.
pub fn lazyPush(
    self: *State,
    gossip: Gossip,
    sender: NodeId,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    const round = gossip.round() orelse return;
    for (self.lazy_push_peers.slice()) |peer| {
        if (node_id.sameNode(peer, sender)) continue;
        try queueIHave(self, peer, .{ .id = gossip.id, .round = round });
    }
    if (!self.dispatch_timer_scheduled) {
        // Queued before the flag is set, for the reason `onIHave` gives.
        try out.push(.{ .schedule_timer = .{
            .after = self.config.dispatch_timeout,
            .timer = .dispatch_lazy_push,
        } });
        self.dispatch_timer_scheduled = true;
    }
}

/// Upstream `add_eager`.
pub fn addEager(self: *State, peer: NodeId) Error!void {
    _ = self.lazy_push_peers.remove(peer);
    try self.eager_push_peers.insert(peer);
}

/// Upstream `add_lazy`.
pub fn addLazy(self: *State, peer: NodeId) Error!void {
    _ = self.eager_push_peers.remove(peer);
    try self.lazy_push_peers.insert(peer);
}

fn queueIHave(self: *State, peer: NodeId, ihave: IHave) Error!void {
    for (self.lazy_push_queue[0..self.lazy_push_queue_len]) |*entry| {
        if (!node_id.sameNode(entry.peer, peer)) continue;
        if (entry.count == max_queued_ihaves) return error.LazyQueueFull;
        entry.items[entry.count] = ihave;
        entry.count += 1;
        return;
    }
    if (self.lazy_push_queue_len == max_queue_peers) return error.LazyQueueFull;
    const entry = &self.lazy_push_queue[self.lazy_push_queue_len];
    entry.peer = peer;
    entry.count = 1;
    entry.items[0] = ihave;
    self.lazy_push_queue_len += 1;
}