//! Ending a client, exactly once.
//!
//! A client ends when the core has finished with its connection, when the whole
//! endpoint is closing, or when `deinit` is given a node that was dropped
//! without either. All three go through `release`, so the registry is told once
//! per connection and the slot is left holding nothing a second call could
//! report.

const node_mod = @import("node.zig");
const node_relay_table = @import("node_relay_table.zig");
const node_transport = @import("node_transport.zig");

const relay_server = @import("../relay/server.zig");

const Node = node_mod.Node;
const Served = node_relay_table.Served;
const relay_displaced = node_relay_table.relay_displaced;

/// End every client whose connection the core has finished with.
///
/// The core has taken it out of its table and `sweep` has already run,
/// which is the reason this pass sits where it does: the connection is
/// gone rather than half gone.
pub fn serveRelease(self: *Node) bool {
    var moved = false;
    for (self.clients) |*slot| {
        if (!slot.live) continue;
        if (node_transport.connFor(self, slot.conn) != null) continue;
        release(self, slot);
        moved = true;
    }
    return moved;
}

/// End one client, reporting it exactly once.
///
/// The guard is *taken* and not merely deinited, so nothing is left on the
/// slot for a second call. That spends the type's own guarantee rather
/// than relying on it: a second `deinit` answers `.already_gone` without
/// reaching the registry, and taking the handle means there is no second
/// call to make.
///
/// Nothing is written to the client here. Either its connection is gone,
/// which is the case that got here, or the whole endpoint is closing and
/// `close_endpoint` covers it — and a stream written to after `sweep` would
/// be a write into freed memory.
pub fn release(self: *Node, slot: *Served) void {
    if (slot.guard) |*guard| reportDisconnection(self, guard);
    slot.inbox.deinit(self.gpa);
    slot.* = .{};
}

/// Tell access control, once, that a client has gone, and act on whatever
/// the registry did about it.
pub fn reportDisconnection(
    self: *Node,
    guard: *relay_server.Registry(relay_displaced).OnDisconnectGuard,
) void {
    switch (guard.deinit()) {
        .disconnected => self.stats.relay_disconnects += 1,
        // A connection that had already been displaced ends too, and the
        // entry survives with its active connection untouched.
        .duplicate => self.stats.relay_duplicates += 1,
        .promoted => |promotion| {
            self.stats.relay_disconnects += 1;
            self.stats.relay_promoted += 1;
            // Upstream tells the connection that took over that it is
            // healthy (`server/clients.rs:122-129`), and it goes on that
            // client's control queue like every other control message.
            const took_over = node_relay_table.servedFor(self, promotion.took_over) orelse return;
            // Queue saturation drops the notification, not the promoted client.
            took_over.queues.control.push(.{ .status = .healthy }) catch |err| switch (err) {
                error.QueueFull => self.stats.relay_queue_full += 1,
            };
        },
        // The registry holds no such connection, which is what a second
        // exit finds. Counting it is how a double report would show up.
        .already_gone => self.stats.relay_double_reports += 1,
    }
}

/// End every client, at once, in the phase the handler's shutdown runs in.
pub fn relayClose(self: *Node) void {
    for (self.clients) |*slot| {
        if (!slot.live) continue;
        release(self, slot);
    }
}
