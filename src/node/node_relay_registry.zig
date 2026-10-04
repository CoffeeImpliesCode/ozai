const std = @import("std");
const node_mod = @import("node.zig");
const relay_state = @import("relay_state.zig");

const RelayStorage = @FieldType(node_mod.Node, "relay_state");
const ClientSlot = std.meta.Child(@FieldType(RelayStorage, "clients"));

pub fn serveRegister(self: *node_mod.Node, slot: *ClientSlot) void {
    const proof = switch (slot.handshake) {
        .admitted => |proof| proof,
        else => return,
    };
    slot.node_id = proof.node_id;
    const admitted = self.relay_state.registry.admit(proof.node_id, slot.conn) catch |err| {
        // A registry with no slot left is a relay that has to shed
        // connections, and this is where it finds out.
        std.log.warn("node: the relay could not admit a client: {t}", .{err});
        self.stats.relay_refused += 1;
        return;
    };
    slot.guard = admitted.guard;
    self.stats.relay_admitted += 1;
    const replaced = switch (admitted.admit) {
        .fresh => return,
        .replaced => |id| id,
    };
    self.stats.relay_replaced += 1;
    // The displaced connection is told over its *control* queue, and that
    // is the whole reason there are two: a client whose datagram queue is
    // full is exactly the client that most needs to be told.
    const other = self.relay_state.servedFor(replaced) orelse return;
    other.queues.control.push(.{ .status = .same_endpoint_id_connected }) catch {
        self.stats.relay_queue_full += 1;
        return;
    };
    self.stats.relay_told_displaced += 1;
}

pub fn serveRelease(self: *node_mod.Node) bool {
    var moved = false;
    for (self.relay_state.clients) |*slot| {
        if (!slot.live) continue;
        if (node_mod.connFor(self, slot.conn) != null) continue;
        noteReleased(self, self.relay_state.release(self.gpa, slot));
        moved = true;
    }
    return moved;
}

/// End every client, at once, in the phase the handler's shutdown runs in.
pub fn relayClose(self: *node_mod.Node) void {
    noteReleased(self, self.relay_state.releaseAll(self.gpa));
}

/// Publish what releasing the relay's clients reported.
///
/// **The counting is here and the reporting is in the storage**, because
/// `Stats` is this file's vocabulary and the registry's own answer is which
/// arm it took. Keeping them apart is what lets the two agree: one place
/// decides what happened and one publishes what it means here.
pub fn noteReleased(self: *node_mod.Node, released: relay_state.Reported) void {
    self.stats.relay_disconnects += released.disconnects;
    self.stats.relay_duplicates += released.duplicates;
    self.stats.relay_promoted += released.promoted;
    self.stats.relay_queue_full += released.queue_full;
    self.stats.relay_double_reports += released.double_reports;
}
