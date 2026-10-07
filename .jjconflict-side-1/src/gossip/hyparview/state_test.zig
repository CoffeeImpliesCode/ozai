//! The membership state machine's behaviour: the `Neighbor` deviation, the
//! view arithmetic, the quit, and what a refused append leaves behind.
//!
//! The two halves of the deviation are the first two tests here and they are
//! the reason `sim.zig` exists; the rest is the state machine upstream shares.

const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const entropy = @import("rng.zig");
const node_id = @import("node_id.zig");
const settings = @import("config.zig");
const membership = @import("state.zig");
const topic = @import("topic.zig");
const sim = @import("sim.zig");

const t = std.testing;

const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const PeerData = peers.PeerData;
const PeerInfos = peers.PeerInfos;
const Priority = wire.Priority;
const Neighbor = wire.Neighbor;
const SwarmTimer = wire.SwarmTimer;
const SwarmInEvent = wire.SwarmInEvent;
const SwarmOutEvent = wire.SwarmOutEvent;
const Rng = entropy.Rng;
const sameNode = node_id.sameNode;
const containsNode = node_id.containsNode;
const Config = settings.Config;
const State = membership.State;
const OutEvent = topic.OutEvent;
const TopicState = topic.TopicState;

/// Run one throwaway event so the shuffle timer that the first call arms is
/// out of the way, leaving the next call's actions to be about that call. The
/// latch itself is real behaviour and has its own test below.
fn prime(state: *State, out: *Actions(SwarmOutEvent)) !void {
    out.clear();
    try state.handle(.{ .update_peer_data = PeerData{} }, out);
    out.clear();
}

fn newMembership(index: u8, config: Config, seed: u64) (Error || key.KeyError)!State {
    return State.init(try sim.nodeIdFor(index), null, config, .init(seed));
}

// The deviation, first half: a `ForwardJoin` that has run out of walk sends a
// `Neighbor` and inserts nothing.
//
// Eager insertion is the bug. A node that puts a peer in its active view on
// the strength of a message from a walk spends a slot on a peer it may not be
// able to reach, drops an honest neighbour to make room, and ends up holding
// a view the other end does not share. Every byte-level test still passes.
test "a forward join at the end of its walk asks and does not insert" {
    const walker = try sim.nodeIdFor(1);
    const target = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{ .active_view_capacity = 2 }, 7);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = target, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);

    // One Neighbor went to the target, and the walker is cut loose because it
    // is not a neighbour: that teardown is upstream's own "I am not sure this
    // is correct" rule, kept because the simulator is compared against it.
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, target));
    try t.expect(out.at(0).send_message.message == .neighbor);
    try t.expectEqual(Priority.high, out.at(0).send_message.message.neighbor.priority);
    try t.expect(out.at(1) == .disconnect_peer);
    try t.expect(sameNode(out.at(1).disconnect_peer, walker));

    // Nothing was inserted, nothing was reported to the application, and the
    // peer is on the pending list: asked, not answered.
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expect(state.pending_neighbor_requests.contains(target));
    for (out.slice()) |produced| try t.expect(produced != .emit_event);
}

// The deviation, second half: the peer enters the active view only when it
// answers, and answering is not answered again.
test "a neighbor enters the active view when it replies, and a reply is not a request" {
    const peer = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{}, 11);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    const walker = try sim.nodeIdFor(1);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = peer, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());

    // The peer answers with a Neighbor of its own.
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    // Now it is a neighbour, the request is spent, and nothing is sent back:
    // a reply that were treated as a request would ping-pong forever.
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], peer));
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
}

// The whole exchange between two nodes, and the shape it leaves behind.
test "the active view is bidirectional once the neighbor exchange finishes" {
    const left_index: u8 = 2;
    const right_index: u8 = 3;
    const left_id = try sim.nodeIdFor(left_index);
    const right_id = try sim.nodeIdFor(right_index);
    var left: State = try newMembership(left_index, .{}, 1);
    var right: State = try newMembership(right_index, .{}, 2);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();

    // Left asks right. Left's view is empty, right's too, and neither knows
    // the other is a neighbour yet.
    try prime(&left, &out);
    try stateNeighborRequest(&left, right_id, &out);
    try t.expectEqual(@as(usize, 0), left.activeView().len);
    try t.expectEqual(@as(usize, 0), right.activeView().len);

    // Right receives it, cannot know it is a reply, so it accepts and answers.
    try prime(&right, &out);
    const ask: Neighbor = .{ .priority = .high, .data = null };
    try right.handle(.{ .recv_message = .{
        .from = left_id,
        .message = .{ .neighbor = ask },
    } }, &out);
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expect(sameNode(right.activeView()[0], left_id));
    // The neighbour is reported, and the request is answered.
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(sameNode(out.at(0).emit_event.neighbor_up, left_id));
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .neighbor);
    try t.expect(sameNode(out.at(1).send_message.to, left_id));

    // The asymmetry exists only between the two events. Left takes the reply
    // as the answer to its own request and both views agree.
    out.clear();
    const reply: Neighbor = .{ .priority = .high, .data = null };
    try left.handle(.{ .recv_message = .{
        .from = right_id,
        .message = .{ .neighbor = reply },
    } }, &out);
    try t.expectEqual(@as(usize, 1), left.activeView().len);
    try t.expect(sameNode(left.activeView()[0], right_id));
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expectEqual(@as(usize, 0), left.pending_neighbor_requests.count());
    // The only thing left is the report: a reply is not answered, or the two
    // would trade `Neighbor` messages for as long as both were alive.
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(sameNode(out.at(0).emit_event.neighbor_up, right_id));

    // Upstream leaves the *asker's* own request outstanding on the other side:
    // the reply satisfies the pending set of whoever sent the Neighbor, and
    // nothing ever tells the sender that its request landed. The pending timer
    // is what clears it, and clearing it must not drop a working neighbour.
    try t.expectEqual(@as(usize, 1), right.pending_neighbor_requests.count());
    out.clear();
    try right.handle(.{ .timer_expired = .{ .pending_neighbor_request = left_id } }, &out);
    try t.expectEqual(@as(usize, 0), right.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expect(sameNode(right.activeView()[0], left_id));
}

/// Put the membership state in the position the deviation creates: a peer it
/// wants as a neighbour, and no evidence it can be reached.
fn stateNeighborRequest(
    state: *State,
    peer: NodeId,
    out: *Actions(SwarmOutEvent),
) !void {
    const walker = try sim.nodeIdFor(1);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = peer, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
}

// A `Neighbor` nobody asked for is answered, because the other end has no way
// to know it is a reply.
test "a neighbor we did not ask for is answered" {
    const peer = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{}, 13);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .neighbor);
    try t.expect(sameNode(out.at(1).send_message.to, peer));
    try t.expect(state.pending_neighbor_requests.contains(peer));
}

// A low-priority request into a full view is refused, and refused *properly*:
// a `Disconnect` and a link teardown, not silence.
test "a low-priority neighbor is refused when the view is full" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{ .active_view_capacity = 1 }, 17);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 1), state.activeView().len);

    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .low,
        .data = null,
    } } } }, &out);

    // A ShuffleReply so the refused node does not lose its own contacts, the
    // Disconnect, and the teardown — and then the teardown the "not an active
    // view member" rule asks for as well, because a refused peer was never
    // going to be one. Four actions, in that order.
    try t.expectEqual(@as(usize, 4), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message == .shuffle_reply);
    try t.expect(sameNode(out.at(0).send_message.to, second));
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .disconnect);
    try t.expect(out.at(1).send_message.message.disconnect.alive);
    try t.expect(out.at(2) == .disconnect_peer);
    try t.expect(sameNode(out.at(2).disconnect_peer, second));
    try t.expect(out.at(3) == .disconnect_peer);
    try t.expect(sameNode(out.at(3).disconnect_peer, second));

    // The view is untouched: a refused peer is not a neighbour.
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], first));
}

// A high-priority request into a full view evicts somebody, and the evicted
// peer is told with a `Disconnect` and kept in the passive view.
test "a high-priority neighbor evicts and the evicted peer is told" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{ .active_view_capacity = 1 }, 19);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    // NeighborDown for the evicted peer, a shuffle reply and a disconnect to
    // it, a NeighborUp for the new one, and a Neighbor back to it.
    var saw_down = false;
    var saw_disconnect_to_first = false;
    var saw_up = false;
    for (out.slice()) |produced| switch (produced) {
        .emit_event => |change| switch (change) {
            .neighbor_down => |gone| saw_down = sameNode(gone, first),
            .neighbor_up => |arrived| saw_up = sameNode(arrived, second),
        },
        .send_message => |send| {
            if (send.message == .disconnect and sameNode(send.to, first)) {
                saw_disconnect_to_first = true;
            }
        },
        else => {},
    };
    try t.expect(saw_down);
    try t.expect(saw_up);
    try t.expect(saw_disconnect_to_first);
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], second));
    // Kept, because the peer is alive and we only dropped it for room.
    try t.expect(state.passiveView().len >= 1);
}

// A `Neighbor` that is never answered times out, and the peer it was aimed at
// is dropped from the passive view.
test "a neighbor request that is never answered gives the peer up" {
    const reachable = try sim.nodeIdFor(2);
    const stale = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 23);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    // A shuffle reply hands us two passive peers and nothing else, so the
    // refill has somewhere to aim.
    const gifter = try sim.nodeIdFor(9);
    try state.handle(.{ .recv_message = .{ .from = gifter, .message = .{ .shuffle_reply = .{
        .nodes = try PeerInfos.init(&.{
            .{ .id = reachable, .data = null },
            .{ .id = stale, .data = null },
        }),
    } } } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 2), state.passiveView().len);
    try state.handle(.{ .timer_expired = .do_shuffle }, &out);
    out.clear();

    // The shuffle timer found an active peer to aim at only if the view was
    // non-empty; force the situation by asking for a neighbour directly.
    const walker = try sim.nodeIdFor(8);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = reachable, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);
    out.clear();
    try t.expect(state.pending_neighbor_requests.contains(reachable));
    try t.expectEqual(@as(usize, 0), state.activeView().len);

    // The timer fires and the peer is given up, without any evidence it was
    // ever a neighbour.
    try state.handle(.{ .timer_expired = .{ .pending_neighbor_request = reachable } }, &out);
    try t.expect(!state.pending_neighbor_requests.contains(reachable));
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expect(!containsNode(state.passiveView(), reachable));
}

// A direct `Join` is the paper's rule and is inserted eagerly: the peer
// reached us over a connection it already has, so there is nothing to prove.
test "a direct join is inserted, and the walk it starts is forwarded" {
    const contact = try sim.nodeIdFor(2);
    const already = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 29);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = already, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = contact, .message = .{ .join = null } } }, &out);

    // The new node is in the active view, and every *other* active node is
    // told about it, which is rule 7 and the start of the walk.
    var saw_up = false;
    var forwarded: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .emit_event => |change| {
            if (change == .neighbor_up and sameNode(change.neighbor_up, contact)) saw_up = true;
        },
        .send_message => |send| {
            if (send.message == .forward_join and sameNode(send.to, already)) {
                forwarded += 1;
                try t.expect(sameNode(send.message.forward_join.peer.id, contact));
                try t.expectEqual(
                    state.config.active_random_walk_length.value,
                    send.message.forward_join.ttl.value,
                );
            }
        },
        else => {},
    };
    try t.expect(saw_up);
    try t.expectEqual(@as(usize, 1), forwarded);
    try t.expectEqual(@as(usize, 2), state.activeView().len);
}

// A message from a peer that is not in the active view is followed by a
// teardown, which is upstream's own "I am not sure this is correct" comment
// kept as behaviour because the simulator is compared against it.
test "a message from a passive peer ends with a teardown" {
    const stranger = try sim.nodeIdFor(4);
    var state: State = try newMembership(1, .{}, 31);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    // A `Shuffle` rather than a `Join`: a join is answered by inserting, and
    // an inserted sender is not torn down.
    try state.handle(.{ .recv_message = .{ .from = stranger, .message = .{ .shuffle = .{
        .origin = stranger,
        .nodes = try PeerInfos.init(&.{}),
        .ttl = .{ .value = 0 },
    } } } }, &out);
    var tore_down = false;
    for (out.slice()) |produced| {
        if (produced == .disconnect_peer and sameNode(produced.disconnect_peer, stranger)) {
            tore_down = true;
        }
    }
    try t.expect(tore_down);
}

// The shuffle timer is armed on the first call whatever that call was, and
// only once. It is in `handle` rather than the constructor in upstream, and
// moving it changes when a node with no traffic ever shuffles.
test "the shuffle timer is armed once, on the first call" {
    var state: State = try newMembership(1, .{}, 37);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .do_shuffle);
    try t.expectEqual(state.config.shuffle_interval, out.at(0).schedule_timer.after);

    out.clear();
    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expectEqual(@as(usize, 0), out.count());
}

// A `Quit` disconnects every neighbour and leaves the view empty.
test "a quit disconnects every neighbour" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 41);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.quit, &out);

    try t.expectEqual(@as(usize, 0), state.activeView().len);
    var disconnects: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| {
            if (send.message == .disconnect) {
                disconnects += 1;
                // A quit is not an eviction: we are leaving, not staying
                // without them.
                try t.expect(!send.message.disconnect.alive);
            }
        },
        else => {},
    };
    try t.expectEqual(@as(usize, 2), disconnects);
}

// A `Quit` is a drop of the whole topic, not a disconnect of the active view.
// Every other table goes with it, and the state stops answering.
test "a quit drops the rest of the topic and leaves the state inert" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 41);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    // One neighbour, carrying contact data: the path into `peer_data` for an
    // active peer.
    const data = [_]u8{ 9, 8, 7 };
    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = &data,
    } } } }, &out);
    // A shuffle reply files its nodes in the passive view and then asks one of
    // them to be our neighbour, which is the path into the pending set.
    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .shuffle_reply = .{
        .nodes = try PeerInfos.init(&.{.{ .id = second, .data = null }}),
    } } } }, &out);
    // And a peer that says it is still alive as it goes, which is what the
    // alive-disconnect set exists for.
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .disconnect = .{
        .alive = true,
    } } } }, &out);

    // Every table is loaded, or the rest of this test proves nothing.
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expectEqual(@as(usize, 1), state.passiveView().len);
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 1), state.alive_disconnect_peers.count());
    try t.expectEqual(@as(usize, 1), state.peer_data.count());

    out.clear();
    try state.handle(.quit, &out);

    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.passiveView().len);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 0), state.alive_disconnect_peers.count());
    try t.expectEqual(@as(usize, 0), state.peer_data.count());
    try t.expect(state.left);

    // The disconnects are the one part of leaving a caller gets to see, and a
    // shuffle timer is not among them: there is no view left to shuffle, and a
    // timer armed after the quit would outlive the topic it was keeping.
    var disconnects: usize = 0;
    var timers: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| disconnects += @intFromBool(send.message == .disconnect),
        .schedule_timer => timers += 1,
        else => {},
    };
    try t.expectEqual(@as(usize, 1), disconnects);
    try t.expectEqual(@as(usize, 0), timers);

    // And the state is inert: a `Neighbor` that would have inserted a peer
    // inserts nothing, a second quit owes nothing, and a shuffle timer that
    // fires anyway changes nothing. All three succeed, because a driver that
    // keeps feeding a node it has stopped driving has no error to act on.
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = &data,
    } } } }, &out);
    try state.handle(.quit, &out);
    try state.handle(.{ .timer_expired = .do_shuffle }, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
}

// The drain a quit does is the one place a leaving node writes to the wire for
// every peer it had, so it is the one place a refused append can forget a peer
// outright. A peer taken out of the active view before its `Disconnect` was
// published is unreachable by the retry the doc offers, and the caller is left
// holding a neighbour it never told, which is exactly the belief
// `handleQuit`'s rationale says must not survive.
test "a disconnect that could not be published leaves the peer in the active view" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 43);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try t.expectEqual(@as(usize, 2), state.activeView().len);

    // A fresh container, because `clear` keeps its capacity and a container
    // that already has room would not allocate at all. The first append a quit
    // makes is the shuffle reply that opens the first peer's farewell, so this
    // refusal lands on the first peer of the drain.
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var refusing: Actions(SwarmOutEvent) = .init(failing.allocator());
    defer refusing.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(error.OutOfMemory, state.handle(.quit, &refusing));

    // Nothing was told and nothing forgotten, so the quit committed no part of
    // itself: both peers are still neighbours to retry from.
    try t.expectEqual(@as(usize, 0), refusing.count());
    try t.expectEqual(@as(usize, 2), state.activeView().len);
    try t.expect(!state.left);

    // So the retry reaches both of them, and only then is the node gone.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.quit, &refusing);
    try t.expect(state.left);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    var disconnects: usize = 0;
    for (refusing.slice()) |produced| switch (produced) {
        .send_message => |send| disconnects += @intFromBool(send.message == .disconnect),
        else => {},
    };
    try t.expectEqual(@as(usize, 2), disconnects);
}

// The wire payload a committed quit produced before the peer was told it was
// leaving, and the one the order change had to keep producing after. The peer
// is still in the active view while its farewell is built, and the farewell is
// a list of nodes worth knowing — the node asking to be remembered is not one
// of them. What the two peers are given is not the same length, and not
// because the exclusion is weaker for one of them: every farewell is read
// from the view the drain is already emptying. Told first, a peer still has
// the other one standing beside it and is offered it; told last, every other
// neighbour is already forgotten and there is nothing left to name. Both are
// told either way — a list that thins to nothing is the drain finishing.

test "a farewell shuffle reply does not offer the peer it is for" {
    const me = try sim.nodeIdFor(1);
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 47);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try t.expectEqual(@as(usize, 2), state.activeView().len);
    // The passive view is empty, so every farewell here is topped up from the
    // active view — which holds the peer it is for, and is the only place
    // there is anything to offer from.
    try t.expectEqual(@as(usize, 0), state.passiveView().len);

    out.clear();
    try state.handle(.quit, &out);

    var replies: usize = 0;
    // Only the prongs below write these, so a third farewell is caught by the
    // count rather than by an out-of-bounds write.
    var told: [2]NodeId = undefined;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| switch (send.message) {
            .shuffle_reply => |reply| {
                switch (replies) {
                    0 => {
                        told[0] = send.to;
                        try t.expectEqual(@as(usize, 1), reply.nodes.count);
                        // The other neighbour, which is what makes the
                        // exclusion a choice rather than an accident of an
                        // empty view.
                        const offered = reply.nodes.slice()[0].id;
                        const other = if (sameNode(send.to, first)) second else first;
                        try t.expect(sameNode(offered, other));
                        try t.expect(!sameNode(offered, send.to));
                        try t.expect(!sameNode(offered, me));
                    },
                    // Its only other neighbour left the view when the loop
                    // told it, so the list it is offered is empty — and it is
                    // still told, which is the part that matters.
                    1 => {
                        told[1] = send.to;
                        try t.expectEqual(@as(usize, 0), reply.nodes.count);
                    },
                    else => {},
                }
                replies += 1;
            },
            else => {},
        },
        else => {},
    };
    // Both peers were told, and neither twice: every send in this drain goes
    // to a peer the loop has not forgotten, and there were only two of them.
    try t.expectEqual(@as(usize, 2), replies);
    try t.expect(!sameNode(told[0], told[1]));
}

// The latch on the shuffle timer is a claim that a timer exists. Setting it
// before the append that publishes the timer makes that claim true when the
// caller never received one, and an allocator that refuses that single append
// costs the node its shuffle for good.
test "a shuffle timer that could not be queued is armed again on the next turn" {
    var state: State = try newMembership(1, .{}, 41);
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(SwarmOutEvent) = .init(failing.allocator());
    defer out.deinit();

    // Nothing this event does appends before the shuffle timer, so the very
    // next allocation is that timer's.
    failing.fail_index = failing.alloc_index;
    try t.expectError(
        error.OutOfMemory,
        state.handle(.{ .update_peer_data = PeerData{} }, &out),
    );
    try t.expect(!state.shuffle_scheduled);
    try t.expectEqual(@as(usize, 0), out.count());

    // The claim was never made, so the next turn makes it and the timer is
    // queued. With the latch set first it survived the failure, the second turn
    // produced nothing, and the node never shuffled again.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expect(state.shuffle_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expectEqual(SwarmTimer.do_shuffle, out.at(0).schedule_timer.timer);
}

// The same latch, read from the other end. The tail of `handle` owns every
// re-arming and queues before it sets, so a refusal there costs one turn. A
// *consumed* timer is the case the tail cannot reach: the caller has already
// taken that timer out of its queue to hand it to this call, so a latch still
// set when the shuffle is refused is a claim about a timer that will never
// fire again, and nothing else in the state ever clears it.
test "a consumed shuffle that could not be published leaves no phantom timer" {
    const peer = try sim.nodeIdFor(2);
    var state: State = try newMembership(1, .{}, 41);
    var warm: Actions(SwarmOutEvent) = .init(t.allocator);
    defer warm.deinit();
    try prime(&state, &warm);

    // A neighbour, so the shuffle timer has something to publish and the
    // refusal lands on the `Shuffle` itself rather than on the re-arm.
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &warm);
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(state.shuffle_scheduled);

    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(SwarmOutEvent) = .init(failing.allocator());
    defer out.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(
        error.OutOfMemory,
        state.handle(.{ .timer_expired = .do_shuffle }, &out),
    );

    // The timer the caller handed us is gone and nothing replaced it.
    try t.expect(!state.shuffle_scheduled);
    try t.expectEqual(@as(usize, 0), out.count());

    // So the next turn re-arms it. With the latch left set, that turn produced
    // nothing and the node never shuffled again.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expect(state.shuffle_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expectEqual(SwarmTimer.do_shuffle, out.at(0).schedule_timer.timer);
}

// The same rule on the other latch in this module. `pending_neighbor_requests`
// is the claim that we asked a peer to be our neighbour, and it is what
// `handlePendingNeighborTimer` clears — but only if the timer that clears it
// was ever queued, and `refillActiveFromPassive` queues it *after* the
// `sendNeighbor` that publishes the request. A refusal in between therefore
// leaves a claim nothing owns: a refill skips a pending peer and counts it
// against the active-view capacity, so one refusal spends the slot for good.
test "a neighbor request that could not be published spends no slot" {
    const candidate = try sim.nodeIdFor(2);
    var state: State = try newMembership(1, .{}, 41);
    var warm: Actions(SwarmOutEvent) = .init(t.allocator);
    defer warm.deinit();
    try prime(&state, &warm);

    // One passive peer and an empty active view, so a refill has exactly one
    // peer it could ask and the test cannot pass by asking somebody else.
    try state.handle(.{ .recv_message = .{ .from = candidate, .message = .{ .shuffle = .{
        .origin = candidate,
        .nodes = try PeerInfos.init(&.{.{ .id = candidate, .data = null }}),
        .ttl = .{ .value = 0 },
    } } } }, &warm);
    try t.expectEqual(@as(usize, 1), state.passiveView().len);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());

    // A `shuffle_reply` carrying no nodes: the only thing it does is refill, so
    // the very next allocation is the `Neighbor` the refill publishes.
    const ask: SwarmInEvent = .{ .recv_message = .{ .from = candidate, .message = .{
        .shuffle_reply = .{ .nodes = try PeerInfos.init(&.{}) },
    } } };
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(SwarmOutEvent) = .init(failing.allocator());
    defer out.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(error.OutOfMemory, state.handle(ask, &out));

    // No request went out, so none is pending: a claim nobody owns is exactly
    // what the pending timer exists to be able to clear.
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());

    // And the node can still ask its only passive peer, with the timer that
    // would give the request up if it went unanswered. Left pending, every
    // later refill skips this peer, and nothing ever queues that timer.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(ask, &out);
    var asked: usize = 0;
    var timers: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| switch (send.message) {
            .neighbor => asked += 1,
            else => {},
        },
        .schedule_timer => |schedule| switch (schedule.timer) {
            .pending_neighbor_request => timers += 1,
            else => {},
        },
        else => {},
    };
    try t.expectEqual(@as(usize, 1), asked);
    try t.expectEqual(@as(usize, 1), timers);
}

// The topic's promise is "leave the topic and drop its state", and the
// broadcast layer is state. A quit that empties the active view and leaves the
// iTree, the lazy queue and both caches standing is not a drop.
test "a quit through the topic empties the broadcast layer and the topic goes quiet" {
    const me = try sim.nodeIdFor(1);
    const peer = try sim.nodeIdFor(2);
    var state: TopicState = try TopicState.init(me, null, .{}, .init(9));
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    // A neighbour, which puts a peer in the active view and then in the tree's
    // eager set, and a broadcast, which fills both caches and the id table.
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .swarm = .{
        .neighbor = .{ .priority = .high, .data = null },
    } } } }, 0, &out);
    try state.handle(.{ .command = .{ .broadcast = .{
        .content = "hello",
        .scope = .swarm,
    } } }, 0, &out);

    // Both layers hold something before the quit, or the rest proves nothing.
    // What is inside the broadcast layer is asserted in `plumtree.zig`, which
    // owns those tables; what the topic owns is that both layers answered the
    // event and that the quit reaches both.
    try t.expectEqual(@as(usize, 1), state.swarm.activeView().len);
    try t.expectEqual(@as(usize, 1), state.gossip.eagerPeers().len);

    out.clear();
    try state.handle(.{ .command = .quit }, 0, &out);

    try t.expect(state.left);
    try t.expect(state.swarm.left);
    try t.expectEqual(@as(usize, 0), state.swarm.activeView().len);
    try t.expectEqual(@as(usize, 0), state.gossip.eagerPeers().len);
    try t.expectEqual(@as(usize, 0), state.gossip.lazyPeers().len);

    // Inert afterwards: a broadcast, a membership message, a peer that drops
    // and an application asking for its contact data all produce nothing, and
    // all four succeed. Before the fix the broadcast still went out to a tree
    // whose neighbours had been dropped, and the membership message still
    // answered a `Neighbor` for a topic this node had left.
    out.clear();
    try state.handle(.{ .command = .{ .broadcast = .{
        .content = "after",
        .scope = .swarm,
    } } }, 1, &out);
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .swarm = .{
        .neighbor = .{ .priority = .high, .data = null },
    } } } }, 1, &out);
    try state.handle(.{ .peer_disconnected = peer }, 1, &out);
    try state.handle(.{ .update_peer_data = PeerData{} }, 1, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.gossip.eagerPeers().len);
    try t.expectEqual(@as(usize, 0), state.swarm.activeView().len);
}

/// Fill a frame big enough to cover whatever the reader below unwound, so a
/// slice into a dead frame reads back as poison instead of as the bytes it
/// happened to leave behind. `never_inline` is load-bearing: an inlined
/// helper would poison the caller's own live locals rather than the dead
/// region.
fn clobberStack() void {
    var poison: [2048]u8 = undefined;
    @memset(&poison, 0xcd);
    std.mem.doNotOptimizeAway(&poison);
}

// The contact data a node advertises is read into a frame, and the messages it
// goes into outlive that frame. Reading it back with nothing in between finds
// the right bytes either way, which is why this needs a frame in between to
// tell the two apart.
test "a node's own contact data outlives the frame it was read in" {
    var state = try State.init(
        try sim.nodeIdFor(0),
        try PeerData.fromBytes("41234"),
        .{},
        Rng.init(1),
    );
    // `never_inline` on the read as well as the clobber: inlined, the frame
    // this test is about would be this test's own and the poison would miss
    // it. The same shape as `CustomAddr` in `src/base/addr.zig`.
    const seen = @call(.never_inline, State.myData, .{&state});
    @call(.never_inline, clobberStack, .{});

    // Snapshot with no call in between: the assertion is a call, and its frame
    // lands on the region this test exists to inspect. `orelse` is a branch and
    // not a call, so capturing the optional here costs the read nothing.
    const borrowed = seen orelse return error.TestUnexpectedResult;
    const held = [_]u8{ borrowed[0], borrowed[1], borrowed[2], borrowed[3], borrowed[4] };
    try t.expectEqualSlices(u8, "41234", &held);

    // A node with no contact data says so, and says it from the address rather
    // than from a copy that happens to be empty.
    var bare = try State.init(try sim.nodeIdFor(1), null, .{}, Rng.init(2));
    try t.expectEqual(@as(?[]const u8, null), @call(.never_inline, State.myData, .{&bare}));
}
