//! The broadcast tree's protocol behaviour: what a `Gossip`, an `IHave`, a
//! `Graft` and a `Prune` do to the tree, and what the tree does back.

const std = @import("std");
const actions = @import("actions.zig");
const claim_table = @import("claim_table.zig");
const limits = @import("limits.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const node_id = @import("node_id.zig");
const tree = @import("state.zig");
const test_node_id = @import("test_node_id.zig");
const vectors = @import("blake3_vectors.zig");

const t = std.testing;

const Actions = actions.Actions;
const Claim = claim_table.Claim;
const max_claims = limits.max_claims;
const Gossip = wire.Gossip;
const IHaves = wire.IHaves;
const InEvent = wire.InEvent;
const OutEvent = wire.OutEvent;
const MessageId = message_id.MessageId;
const sameNode = node_id.sameNode;
const State = tree.State;
const testNodeId = test_node_id.testNodeId;
const blake3Input = vectors.blake3Input;
const blake3_vectors = vectors.blake3_vectors;
const messageIdFromHex = vectors.messageIdFromHex;

// The second half of the invariant: a spoofed id is dropped, and dropping it
// does not touch the peer that sent it. A path that also punished would let
// one bad frame per neighbour empty a victim's iTree.
test "a spoofed message id is dropped without penalising the peer" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    // A well-formed message from the peer: the peer is promoted, the payload
    // is announced to the application, and the dispatch timer is armed.
    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(1) == .emit_event);
    try t.expect(state.eager_push_peers.contains(peer));

    // The same peer, the same content, an id that is not the hash of it.
    const wrong = messageIdFromHex(blake3_vectors[2].derive_key);
    const received_before = state.stats.payload_messages_received;
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .gossip = .{
            .id = wrong,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);

    // Half one: nothing at all comes out. No `Prune`, no `Graft`, no event, no
    // timer, nothing queued for later.
    try t.expectEqual(@as(usize, 0), out.count());
    // Half two: nothing about the peer changed. It is still eager, still not
    // in the claim table, and the id was not remembered as seen.
    try t.expect(state.eager_push_peers.contains(peer));
    try t.expect(!state.lazy_push_peers.contains(peer));
    try t.expect(!state.received_messages.contains(wrong));
    try t.expectEqual(@as(usize, 0), state.missing_messages_len);
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    // The one thing that does move, by upstream's design: the frame was
    // received. This is a receive counter, not a delivery counter.
    try t.expectEqual(received_before + 1, state.stats.payload_messages_received);
}

// The iTree on a three-node topology: `2` and `3` are eager children, `4` is
// a lazy edge. A payload arriving from `2` goes whole to `3` and by id to
// `4`, and nothing goes back to `2`.
test "the iTree forwards along eager edges and announces along lazy ones" {
    const me = try testNodeId(1);
    const from = try testNodeId(2);
    const eager_child = try testNodeId(3);
    const lazy_child = try testNodeId(4);
    const content = try blake3Input(3);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = from }, 0, &out);
    try state.handle(.{ .neighbor_up = eager_child }, 0, &out);
    out.clear();
    // `lazy_child` is a neighbour but the tree put it on the lazy side.
    try state.addLazy(lazy_child);
    try t.expectEqual(@as(usize, 2), state.eagerPeers().len);
    try t.expectEqual(@as(usize, 1), state.lazyPeers().len);

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = from,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 3 } },
        } },
    } }, 0, &out);

    // The whole payload to the eager child at round 4, then the dispatch
    // timer, then the application event. The `IHave` to the lazy child is
    // still queued, which is the delay the lazy side exists for.
    try t.expectEqual(@as(usize, 3), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, eager_child));
    try t.expectEqual(@as(u16, 4), out.at(0).send_message.message.gossip.round().?.value);
    try t.expect(!sameNode(out.at(0).send_message.to, from));
    try t.expect(out.at(1) == .schedule_timer);
    try t.expect(out.at(1).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(2) == .emit_event);
    try t.expectEqual(@as(u16, 3), state.stats.max_last_delivery_hop);

    // Firing the dispatch timer is what turns the queued id into an `IHave`.
    out.clear();
    try state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, lazy_child));
    const ihaves = out.at(0).send_message.message.i_have.slice();
    try t.expectEqual(@as(usize, 1), ihaves.len);
    try t.expect(ihaves[0].id.eql(id));
    try t.expectEqual(@as(u16, 4), ihaves[0].round.value);
}

// The first half of the recovery path: a peer advertises a message this node
// never received, the timer fires, and the peer is grafted and asked for it.
test "an iHave that is not followed by a payload becomes a graft" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(8);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expectEqual(state.config.graft_timeout_1, out.at(0).schedule_timer.after);

    // Before the timer fires, the peer is still only a neighbour and not a
    // tree edge.
    try t.expect(state.eager_push_peers.contains(peer));

    out.clear();
    try state.handle(.{ .timer_expired = .{ .send_graft = id } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message.graft.id != null);
    try t.expect(out.at(0).send_message.message.graft.id.?.eql(id));
    try t.expect(out.at(1) == .schedule_timer);
    try t.expectEqual(state.config.graft_timeout_2, out.at(1).schedule_timer.after);
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

test "a graft is answered from the cache" {
    const me = try testNodeId(1);
    const holder = try testNodeId(3);
    const asker = try testNodeId(2);
    const content = try blake3Input(8);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = holder }, 0, &out);
    try state.handle(.{ .neighbor_up = asker }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = holder,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = asker,
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 2 } } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, asker));
    try t.expectEqualStrings(content, out.at(0).send_message.message.gossip.content);
    try t.expect(state.eager_push_peers.contains(asker));
}

// A graft for a message this node has itself is a no-op beyond the promotion,
// and one for a message the cache has already swept is silent.
test "a graft the cache cannot answer is silent" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 1 } } },
    } }, 0, &out);
    // Only the cache sweep, from the init latch. The peer is promoted, and
    // nothing is invented in reply.
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(state.eager_push_peers.contains(peer));
}

// Upstream `plumtree::test::optimize_tree`, pinned. The first run leaves the
// sender three rounds closer than the threshold and does nothing; the second
// leaves it nine rounds closer and grafts and prunes. The dispatch timer is
// armed once across both, which is what makes the second run's expected list
// shorter than the first's.
test "the tree optimises towards the shortest path anybody claimed" {
    const me = try testNodeId(1);
    const claimant = try testNodeId(2);
    const sender = try testNodeId(3);

    const near = try blake3Input(2);
    defer t.allocator.free(near);
    const far = try blake3Input(3);
    defer t.allocator.free(far);
    const near_id = messageIdFromHex(blake3_vectors[2].hash);
    const far_id = messageIdFromHex(blake3_vectors[3].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .recv_message = .{
        .from = claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = near_id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = .{
            .id = near_id,
            .content = near,
            .scope = .{ .swarm = .{ .value = 6 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(1) == .emit_event);
    try t.expect(sameNode(out.at(1).emit_event.delivered_from, sender));
    out.clear();

    try state.handle(.{ .recv_message = .{
        .from = claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = far_id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = .{
            .id = far_id,
            .content = far,
            .scope = .{ .swarm = .{ .value = 9 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 3), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, claimant));
    try t.expect(out.at(0).send_message.message.graft.id == null);
    try t.expectEqual(@as(u16, 2), out.at(0).send_message.message.graft.round.value);
    try t.expect(out.at(1) == .send_message);
    try t.expect(sameNode(out.at(1).send_message.to, sender));
    try t.expect(out.at(1).send_message.message == .prune);
    try t.expect(out.at(2) == .emit_event);
    try t.expect(state.eager_push_peers.contains(claimant));
    try t.expect(state.lazy_push_peers.contains(sender));
}

// `takeMissing` hands its result to `optimizeTree`, which reads it after the
// call returns, so the claim list has to outlive the drain. Upstream borrows
// the map entry; here the entry is removed by the drain, so the copy belongs
// to a buffer the caller owns. A drain that built the copy in its own frame
// returned a pointer to a dead slot, and the caller cannot see that — it is
// the next drain, into its own buffer, that reads whatever the dead frame
// left behind. So: two ids, two buffers, and the shortest claim of the second
// id is the one a shared buffer would hand to the first.
test "a drained claim list lives in the caller's buffer" {
    const me = try testNodeId(1);
    const near_peer = try testNodeId(2);
    const far_peer = try testNodeId(3);
    const other_peer = try testNodeId(4);
    const sender = try testNodeId(5);

    const first_id = messageIdFromHex(blake3_vectors[2].hash);
    const second_id = messageIdFromHex(blake3_vectors[3].hash);
    const unclaimed_id = messageIdFromHex(blake3_vectors[4].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    _ = try state.pushClaim(first_id, .{ .peer = near_peer, .round = .{ .value = 4 } });
    _ = try state.pushClaim(first_id, .{ .peer = far_peer, .round = .{ .value = 12 } });
    _ = try state.pushClaim(second_id, .{ .peer = other_peer, .round = .{ .value = 1 } });

    var first_buffer: [max_claims]Claim = undefined;
    const maybe_first = state.takeMissing(first_id, &first_buffer);
    try t.expect(maybe_first != null);
    const first_claims = maybe_first.?;
    try t.expectEqual(@as(usize, 2), first_claims.len);
    try t.expect(first_claims.ptr == @as([*]const Claim, first_buffer[0..].ptr));
    try t.expect(sameNode(first_claims[0].peer, near_peer));
    try t.expectEqual(@as(u16, 4), first_claims[0].round.value);
    try t.expect(sameNode(first_claims[1].peer, far_peer));
    try t.expectEqual(@as(u16, 12), first_claims[1].round.value);

    var second_buffer: [max_claims]Claim = undefined;
    const maybe_second = state.takeMissing(second_id, &second_buffer);
    try t.expect(maybe_second != null);
    const second_claims = maybe_second.?;
    try t.expectEqual(@as(usize, 1), second_claims.len);
    try t.expect(sameNode(second_claims[0].peer, other_peer));
    try t.expectEqual(@as(u16, 1), second_claims[0].round.value);

    // The second drain wrote the second buffer and left the first list
    // readable, unchanged, and its own.
    try t.expectEqual(@as(usize, 2), first_claims.len);
    try t.expect(sameNode(first_claims[0].peer, near_peer));
    try t.expectEqual(@as(u16, 4), first_claims[0].round.value);
    try t.expect(sameNode(first_claims[1].peer, far_peer));
    try t.expectEqual(@as(u16, 12), first_claims[1].round.value);

    // And the retained list still drives the optimisation: `near_peer`, the
    // shortest claim of the first id, not the shorter claim of the second.
    try state.optimizeTree(sender, .{ .value = 20 }, first_claims, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, near_peer));
    try t.expect(out.at(0).send_message.message.graft.id == null);
    try t.expectEqual(@as(u16, 4), out.at(0).send_message.message.graft.round.value);
    try t.expect(out.at(1) == .send_message);
    try t.expect(sameNode(out.at(1).send_message.to, sender));
    try t.expect(out.at(1).send_message.message == .prune);
    try t.expect(state.eager_push_peers.contains(near_peer));
    try t.expect(state.lazy_push_peers.contains(sender));

    // An id nobody claimed drains to nothing and writes nothing: the buffer
    // the caller handed in is still the caller's.
    var spare_buffer: [max_claims]Claim = undefined;
    @memset(&spare_buffer, Claim{ .peer = me, .round = .{ .value = 999 } });
    try t.expect(state.takeMissing(unclaimed_id, &spare_buffer) == null);
    try t.expect(sameNode(spare_buffer[0].peer, me));
    try t.expectEqual(@as(u16, 999), spare_buffer[0].round.value);

    // And a drained id is drained: the second attempt has nothing to give.
    var drained_buffer: [max_claims]Claim = undefined;
    try t.expect(state.takeMissing(first_id, &drained_buffer) == null);
}

// The same isolation through the public path, where no caller ever holds a
// claim list: two ids are pending, the second arrives and is optimised
// towards the peer that claimed *it*, and the first id's claim is still
// queued when its own graft timer fires. A drain that took the wrong id's
// claims would graft the wrong peer and leave the first id with nobody to
// ask.
test "one id's optimisation leaves another id's claim queued" {
    const me = try testNodeId(1);
    const near_claimant = try testNodeId(2);
    const far_claimant = try testNodeId(3);
    const sender = try testNodeId(4);

    const far = try blake3Input(3);
    defer t.allocator.free(far);
    const near_id = messageIdFromHex(blake3_vectors[2].hash);
    const far_id = messageIdFromHex(blake3_vectors[3].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .recv_message = .{
        .from = near_claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = near_id, .round = .{ .value = 4 } }}) },
    } }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = far_claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = far_id, .round = .{ .value = 1 } }}) },
    } }, 0, &out);
    out.clear();

    try state.handle(.{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = .{
            .id = far_id,
            .content = far,
            .scope = .{ .swarm = .{ .value = 20 } },
        } },
    } }, 0, &out);
    // The dispatch flush `lazyPush` latches, then this id's graft and its
    // sender's prune.
    try t.expectEqual(@as(usize, 4), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(1) == .send_message);
    try t.expect(sameNode(out.at(1).send_message.to, far_claimant));
    try t.expect(out.at(1).send_message.message.graft.id == null);
    try t.expectEqual(@as(u16, 1), out.at(1).send_message.message.graft.round.value);
    try t.expect(out.at(2) == .send_message);
    try t.expect(sameNode(out.at(2).send_message.to, sender));
    try t.expect(out.at(2).send_message.message == .prune);
    try t.expect(out.at(3) == .emit_event);

    // The first id never arrived, so its graft timer still has its claimant.
    out.clear();
    try state.handle(.{ .timer_expired = .{ .send_graft = near_id } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, near_claimant));
    try t.expect(out.at(0).send_message.message.graft.id.?.eql(near_id));
    try t.expectEqual(@as(u16, 4), out.at(0).send_message.message.graft.round.value);
    try t.expect(out.at(1) == .schedule_timer);
    try t.expect(out.at(1).schedule_timer.timer == .send_graft);
}

// A second copy of a message already held is not forwarded and not announced;
// it costs the sender its eager edge.
test "a duplicate moves the sender to the lazy side" {
    const me = try testNodeId(1);
    const sender = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);
    const gossip: Gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    };

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = sender }, 0, &out);
    out.clear();
    const arrival: InEvent = .{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = gossip },
    } };
    try state.handle(arrival, 0, &out);
    try t.expect(out.at(out.count() - 1) == .emit_event);

    out.clear();
    try state.handle(arrival, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message == .prune);
    try t.expect(sameNode(out.at(0).send_message.to, sender));
    try t.expect(state.lazy_push_peers.contains(sender));
    try t.expect(!state.eager_push_peers.contains(sender));
}

// A neighbour that goes away leaves both sets and the claim table.
test "a neighbour down leaves the tree" {
    const me = try testNodeId(1);
    const eager = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = eager }, 0, &out);
    try state.addLazy(try testNodeId(3));
    _ = try state.pushClaim(id, .{ .peer = eager, .round = .{ .value = 2 } });
    out.clear();
    try state.handle(.{ .neighbor_down = eager }, 0, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.eagerPeers().len);
    try t.expectEqual(@as(usize, 1), state.lazyPeers().len);
    try t.expect(!state.lazy_push_peers.contains(eager));
    try t.expectEqual(@as(u16, 0), state.missing_messages[0].count);
}
