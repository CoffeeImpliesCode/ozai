//! HyParView and the topic composition: the tests.
//!
//! # Why this file exists
//!
//! `hyparview.zig` holds two state machines — membership (`State`) and the
//! composition of membership with broadcast (`TopicState`) — and nothing else.
//! No clock, no environment, no allocator, no I/O and no test. Every assertion
//! that needs a `std.testing` seam was lifted out into this file, the way
//! `node/node_tests.zig` and `node/node_retirement_tests.zig` lifted theirs,
//! so the file that states what a `Neighbor` does is not also the file that
//! argues with it.
//!
//! Its sibling `hyparview_sim_tests.zig` holds the discrete-event simulator and
//! the whole-swarm runs. The split is along the subject: a run of several nodes
//! is a different claim from a state's behaviour under one event, and the
//! simulator needed to leave `hyparview.zig` because it allocates.
//!
//! # Reaching into the machine
//!
//! These tests read `state.pending_neighbor_requests`, `state.config`,
//! `state.shuffle_scheduled`, `state.peer_data`, `state.alive_disconnect_peers`
//! and both layers' trees — tables a caller cannot enumerate any other way.
//! That is deliberate: "the pending set still holds one peer" is a claim about
//! the machine, and an emitted `disconnect_peer` is only a claim about what it
//! intended. A caller holding a `State` has exactly one way to observe it, and
//! that way is the event it sends next.
//!
//! # The allocation-failure sweeps
//!
//! `State.handle` is documented as not transactional: an event advances the
//! state and appends to the output list as it goes, so a refusal part way
//! through leaves both partly advanced. The sweeps at the end of this file are
//! the evidence for the recovery the documentation promises — every boundary in
//! a run, driven with an allocator that fails at it, the snapshot restored, the
//! event replayed, and the republished actions compared against a reference run
//! rather than against a count. "Did not crash" is not the claim these make.
//!
//! # Reach
//!
//! Both roots run this file, exactly as both run `hyparview.zig`: the native
//! `src/unit_test.zig` and the socket-free `src/portable_test.zig`. Nothing
//! here reaches a socket, so the split moves no platform boundary.

const std = @import("std");
const key = @import("../base/key.zig");
const hyparview = @import("hyparview.zig");
const sim_tests = @import("hyparview_sim_tests.zig");

const NodeId = key.NodeId;
const Allocator = std.mem.Allocator;

/// Every production declaration the tests below name unqualified.
///
/// They came out of `hyparview.zig`, where they shared a namespace with the
/// state machines and could spell every one of these bare. Binding them here
/// rather than importing the namespace under test keeps the seam visible: a
/// test that reached for `hyparview.sameNode` would be checking that the module
/// agrees with itself. The order is the order the first test reaches for each,
/// because a binding list is this file's dependency list and only reads as one
/// in that order.
const State = hyparview.State;
const TopicState = hyparview.TopicState;
const Actions = hyparview.Actions;
const Config = hyparview.Config;
const Error = hyparview.Error;
const Rng = hyparview.Rng;
const Peers = hyparview.Peers;
const PeerInfos = hyparview.PeerInfos;
const PeerData = hyparview.PeerData;
const PeerDataMap = hyparview.PeerDataMap;
const Neighbor = hyparview.Neighbor;
const Priority = hyparview.Priority;
const SwarmTimer = hyparview.SwarmTimer;
const SwarmInEvent = hyparview.SwarmInEvent;
const SwarmOutEvent = hyparview.SwarmOutEvent;
const InEvent = hyparview.InEvent;
const OutEvent = hyparview.OutEvent;
const TopicId = hyparview.TopicId;
const topic_id_length = hyparview.topic_id_length;
const peer_data_max = hyparview.peer_data_max;
const max_shuffle_nodes = hyparview.max_shuffle_nodes;
const max_active = hyparview.max_active;
const max_passive = hyparview.max_passive;
const max_bootstrap = hyparview.max_bootstrap;

/// The simulator's namespace, for the fixed node identities every test here
/// draws from. Membership tests do not need a network to have a peer to talk
/// about, and `sim.nodeIdFor` is where the seeded identities live.
const sim = sim_tests.sim;

/// The node-id comparison `hyparview` makes, restated rather than imported.
///
/// `hyparview.sameNode` is file-private there, and a test that reached for the
/// production copy would be checking that the module agrees with itself rather
/// than checking that two ids mean the same peer.
fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}

/// Whether `peers` holds `peer`. `hyparview.containsNode` is file-private for
/// the same reason `sameNode` is restated above.
fn containsNode(peers: []const NodeId, peer: NodeId) bool {
    for (peers) |item| {
        if (sameNode(item, peer)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

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

/// How many allocations `run` makes. The error the probe saw is dropped on
/// purpose: the count is what this is for, and every sweep below re-runs each
/// boundary and asserts the error it gets there.
///
/// `resize_fail_index` is pinned at zero. A growth the backing allocator can
/// satisfy in place goes through `resize` rather than `alloc`, consumes no
/// allocation index, and is a boundary no `fail_index` can reach — the sweep
/// would step over it and the case would look complete while a growth went
/// untested. Refusing every resize routes each growth through `alloc`.
///
/// Plumtree has its own copy of this, because a private declaration in one
/// module is not a declaration the other can see, and a shared test helper is
/// not worth making public for.
fn boundariesOf(comptime run: anytype, args: anytype) !usize {
    var probe = t.FailingAllocator.init(t.allocator, .{ .resize_fail_index = 0 });
    // Bound and dropped by name rather than swallowed by `catch {}`: the error
    // is the measurement's companion, not a surprise, and the sweep below
    // re-runs each boundary and asserts the error it gets there.
    _ = @call(.auto, run, .{probe.allocator()} ++ args) catch |probe_error| {
        std.mem.doNotOptimizeAway(&probe_error);
    };
    return probe.alloc_index;
}

/// Live bytes a refused `handle` left behind that `out` does not account for.
///
/// `Actions` owns its list and nothing else, and every view, claim set and
/// contact table in a `State` is inline in the value, so the caller's own
/// container is the only thing that can hold memory at the end of a refused
/// call. A sweep that moved an address list onto the heap, or freed the
/// container's buffer under it, would not come out as zero here.
fn liveIn(
    out: anytype,
    failing: *const t.FailingAllocator,
) usize {
    const Element = std.meta.Elem(@TypeOf(out.items.items));
    return failing.allocated_bytes - failing.freed_bytes -
        out.items.capacity * @sizeOf(Element);
}

/// One published action, without the slices in it: which kind it is and the
/// peer or timer it names. That is the whole of what a caller acts on, and so
/// the whole of what a restored-and-retried run has to reproduce.
const Action = struct {
    tag: std.meta.Tag(SwarmOutEvent),
    to: NodeId,
    /// How many nodes a `ShuffleReply` offered, and zero for every other kind.
    listed: u8,
};

/// The largest action list any case below reaches. A join that evicts a peer
/// publishes eleven and the quit drain nine, so sixteen leaves room without
/// being a bound the code has to agree with.
const max_actions = 16;

fn describe(out: *const Actions(SwarmOutEvent), me: NodeId) ![max_actions]Action {
    var described: [max_actions]Action = undefined;
    std.debug.assert(out.count() <= max_actions);
    for (out.slice(), 0..) |produced, index| described[index] = switch (produced) {
        .send_message => |send| switch (send.message) {
            .shuffle_reply => |reply| .{
                .tag = .send_message,
                .to = send.to,
                .listed = reply.nodes.count,
            },
            else => .{ .tag = .send_message, .to = send.to, .listed = 0 },
        },
        .schedule_timer => |schedule| .{
            .tag = .schedule_timer,
            .to = switch (schedule.timer) {
                .do_shuffle => me,
                .pending_neighbor_request => |peer| peer,
            },
            .listed = 0,
        },
        .disconnect_peer => |peer| .{ .tag = .disconnect_peer, .to = peer, .listed = 0 },
        .emit_event => |change| .{
            .tag = .emit_event,
            .to = switch (change) {
                .neighbor_up => |peer| peer,
                .neighbor_down => |peer| peer,
            },
            .listed = 0,
        },
        .peer_data => |data| .{ .tag = .peer_data, .to = data.peer, .listed = 0 },
    };
    return described;
}

/// Two action lists publish the same thing: same count, same kinds, same
/// recipients, same node-list lengths.
fn expectSameActions(
    got: *const Actions(SwarmOutEvent),
    want: *const Actions(SwarmOutEvent),
    me: NodeId,
) !void {
    try t.expectEqual(want.count(), got.count());
    const left_actions = try describe(want, me);
    const right_actions = try describe(got, me);
    for (left_actions[0..want.count()], right_actions[0..got.count()]) |a, b| {
        try t.expectEqual(a.tag, b.tag);
        try t.expect(sameNode(a.to, b.to));
        try t.expectEqual(a.listed, b.listed);
    }
}

/// Two membership states describe the same swarm: the same views, the same
/// claims, the same contact data and the same latches. This is what a snapshot
/// restore has to achieve, and it is why the recovery below is compared
/// against a copy rather than against a count.
fn expectSameMembership(got: *const State, want: *const State) !void {
    try t.expectEqual(want.activeView().len, got.activeView().len);
    for (want.activeView(), got.activeView()) |a, b| try t.expect(sameNode(a, b));
    try t.expectEqual(want.passiveView().len, got.passiveView().len);
    for (want.passiveView(), got.passiveView()) |a, b| try t.expect(sameNode(a, b));
    try t.expectEqual(
        want.pending_neighbor_requests.slice().len,
        got.pending_neighbor_requests.slice().len,
    );
    for (want.pending_neighbor_requests.slice(), got.pending_neighbor_requests.slice()) |a, b| {
        try t.expect(sameNode(a, b));
    }
    try t.expectEqual(
        want.alive_disconnect_peers.slice().len,
        got.alive_disconnect_peers.slice().len,
    );
    for (want.alive_disconnect_peers.slice(), got.alive_disconnect_peers.slice()) |a, b| {
        try t.expect(sameNode(a, b));
    }
    try t.expectEqual(want.peer_data.len, got.peer_data.len);
    try t.expectEqual(want.left, got.left);
    try t.expectEqual(want.shuffle_scheduled, got.shuffle_scheduled);
    try t.expectEqual(want.stats.total_connections, got.stats.total_connections);
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

/// Contact data a neighbour brought with it, as a driver would hand it over.
/// Distinct per peer, so the tables a partial drain must not have cleared are
/// observable and a published shuffle reply names the right bytes.
fn peerContact(index: u8) []const u8 {
    return switch (index) {
        2 => "contact-two",
        3 => "contact-three",
        4 => "contact-four",
        5 => "contact-five",
        6 => "contact-six",
        7 => "contact-seven",
        else => "contact-other",
    };
}

/// Three neighbours, each with contact data, and the shuffle timer already out
/// of the way by `prime`.
fn joinedThree(state: *State, out: *Actions(SwarmOutEvent)) !void {
    for ([_]u8{ 2, 3, 4 }) |index| {
        try state.handle(.{ .recv_message = .{
            .from = try sim.nodeIdFor(index),
            .message = .{ .neighbor = .{ .priority = .high, .data = peerContact(index) } },
        } }, out);
    }
}

fn quitOnce(alloc: std.mem.Allocator) !void {
    var state: State = try newMembership(1, .{}, 43);
    var warm: Actions(SwarmOutEvent) = .init(t.allocator);
    defer warm.deinit();
    try prime(&state, &warm);
    try joinedThree(&state, &warm);
    var out: Actions(SwarmOutEvent) = .init(alloc);
    defer out.deinit();
    try state.handle(.quit, &out);
}

// The drain a quit does is the one place a leaving node writes to the wire for
// every peer it had, so it is the one place a refused append can forget a peer
// outright. A peer taken out of the active view before its `Disconnect` was
// published is unreachable by the retry the doc offers, and the caller is left
// holding a neighbour it never told, which is exactly the belief
// `handleQuit`'s rationale says must not survive. Three peers and every
// boundary, because the residue a refusal leaves is a property of *where* in
// a peer's three appends it landed, and the first-append case cannot see the
// other two.
test "a refused quit drains what it reached and forgets none of it" {
    // The reference drain: three appends per peer, in the active view's own
    // order. Every boundary below is compared against this rather than
    // against a position someone wrote down.
    var drain_order: [3]NodeId = undefined;
    {
        var state: State = try newMembership(1, .{}, 43);
        var out: Actions(SwarmOutEvent) = .init(t.allocator);
        defer out.deinit();
        try prime(&state, &out);
        try joinedThree(&state, &out);
        try t.expectEqual(@as(usize, 3), state.activeView().len);
        out.clear();
        try state.handle(.quit, &out);
        try t.expectEqual(@as(usize, 9), out.count());
        // Indexed rather than a pointer capture over the array: this is the one
        // write, and the oracle below reads all three entries back.
        for (0..3) |index| {
            drain_order[index] = out.at(index * 3).send_message.to;
        }
    }

    const boundaries = try boundariesOf(quitOnce, .{});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        var state: State = try newMembership(1, .{}, 43);
        var warm: Actions(SwarmOutEvent) = .init(t.allocator);
        defer warm.deinit();
        try prime(&state, &warm);
        try joinedThree(&state, &warm);
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        const published: usize = blk: {
            var out: Actions(SwarmOutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(error.OutOfMemory, state.handle(.quit, &out));
            // A prefix of the reference, and within each peer the order the
            // farewell is built in: the shuffle reply first, then the
            // disconnect, then the teardown.
            for (out.slice(), 0..) |produced, index| {
                const peer = drain_order[index / 3];
                switch (index % 3) {
                    0 => {
                        try t.expect(produced == .send_message);
                        try t.expect(sameNode(produced.send_message.to, peer));
                        try t.expect(produced.send_message.message == .shuffle_reply);
                    },
                    1 => {
                        try t.expect(produced == .send_message);
                        try t.expect(sameNode(produced.send_message.to, peer));
                        try t.expect(produced.send_message.message == .disconnect);
                    },
                    else => {
                        try t.expect(produced == .disconnect_peer);
                        try t.expect(sameNode(produced.disconnect_peer, peer));
                    },
                }
            }
            try t.expectEqual(@as(usize, 0), liveIn(&out, &failing));
            break :blk out.count();
        };

        // Told first, forgotten second. A peer leaves the active view only
        // once its whole farewell has been published, so the peers the refusal
        // did not finish are exactly the peers still in the view, and the
        // retry can reach every one of them.
        try t.expectEqual(3 - published / 3, state.activeView().len);
        try t.expect(sameNode(state.activeView()[0], drain_order[published / 3]));
        // And the quit has committed none of itself: the node has not left,
        // and the contact data every published shuffle reply named is still on
        // record for the peers that are left to be told.
        try t.expect(!state.left);
        try t.expectEqual(@as(usize, 3), state.peer_data.len);

        // The retry the doc offers: finish the drain from where it stopped.
        const remaining = state.activeView().len;
        const interrupted = state.activeView()[0];
        var replies_after: usize = 0;
        var disconnects_after: usize = 0;
        var teardowns_after: usize = 0;
        {
            failing.fail_index = std.math.maxInt(usize);
            var out: Actions(SwarmOutEvent) = .init(alloc);
            defer out.deinit();
            try state.handle(.quit, &out);
            try t.expectEqual(3 * remaining, out.count());
            for (out.slice()) |produced| switch (produced) {
                .send_message => |send| {
                    if (!sameNode(send.to, interrupted)) continue;
                    switch (send.message) {
                        .shuffle_reply => replies_after += 1,
                        .disconnect => disconnects_after += 1,
                        else => {},
                    }
                },
                .disconnect_peer => |peer| {
                    teardowns_after += @intFromBool(sameNode(peer, interrupted));
                },
                else => {},
            };
            // Every peer still in the view was told, and told exactly once by
            // this call: the residue is only ever a duplicate node list.
            try t.expectEqual(@as(usize, 1), replies_after);
            try t.expectEqual(@as(usize, 1), disconnects_after);
        }

        // Counted across both calls, the interrupted peer is told to go, once,
        // and is offered a node list once per attempt that reached it. That is
        // `handleQuit`'s named residue and it is the price of a retry here.
        try t.expectEqual(
            1 + @as(usize, @intFromBool(published % 3 >= 1)),
            @as(usize, @intFromBool(published % 3 >= 1)) + replies_after,
        );
        try t.expectEqual(
            1 + @as(usize, @intFromBool(published % 3 >= 2)),
            @as(usize, @intFromBool(published % 3 >= 2)) + disconnects_after,
        );
        try t.expectEqual(
            @as(usize, 1),
            teardowns_after,
        );

        // The drain finished, so everything a quit drops is dropped: the view,
        // the claims, the contact table the shuffle replies above were built
        // from, and the timer, because a node that has left does not shuffle.
        try t.expect(state.left);
        try t.expectEqual(@as(usize, 0), state.activeView().len);
        try t.expectEqual(@as(usize, 0), state.passiveView().len);
        try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
        try t.expectEqual(@as(usize, 0), state.alive_disconnect_peers.count());
        try t.expectEqual(@as(usize, 0), state.peer_data.len);
        try t.expect(!state.shuffle_scheduled);
        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
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

// A `TopicId` is 32 bytes the application chose. There is no derivation and no
// scope, and a test that pinned a derived one would be pinning a scheme this
// module deliberately does not have.
test "a topic id is 32 opaque bytes and nothing more" {
    try t.expectEqual(@as(usize, 32), topic_id_length);
    try t.expectEqual(@as(usize, 32), @sizeOf(TopicId));
    const zero = [_]u8{0} ** topic_id_length;
    var one = [_]u8{0} ** topic_id_length;
    one[0] = 1;
    const left = TopicId.fromBytes(one);
    const right = TopicId.fromBytes(zero);
    try t.expect(left.eql(TopicId.fromBytes(one)));
    try t.expect(!left.eql(right));
    try t.expectEqual(std.math.Order.gt, left.order(right));
    try t.expectEqualStrings("0100000000", &left.shortHex());
}

// Contact data is bounded, and the bound is reported rather than truncated.
test "contact data over the bound is refused" {
    const long = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(long);
    @memset(long, 0x11);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(long));
    // A length the length field cannot spell is refused the same way, by the
    // narrowing rather than by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x33);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(unspellable));
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x22);
    const data = try PeerData.fromBytes(exact);
    try t.expectEqual(peer_data_max, data.slice().len);
    try t.expectEqual(@as(usize, 0), (try PeerData.fromBytes(&.{})).slice().len);
}

// The contact table proves the same bound at the copy, where nothing above it
// has: the slice is a peer's claim about itself, and a message is not obliged
// to be short.
test "the contact table refuses what a record cannot spell" {
    var map: PeerDataMap = .{};
    const peer = try sim.nodeIdFor(2);
    // One byte over the ceiling, and still a length a `u16` spells: only the
    // comparison refuses this one, so only the comparison keeps the copy in
    // bounds.
    const over = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(over);
    @memset(over, 0x44);
    try t.expectError(error.PeerDataTooLong, map.put(peer, over));
    // A length the length field cannot spell is refused by the narrowing, and
    // not by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x55);
    try t.expectError(error.PeerDataTooLong, map.put(peer, unspellable));
    // Nothing refused left a half-written entry behind, and the ceiling is a
    // length rather than a hint.
    try t.expectEqual(@as(usize, 0), map.count());
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x66);
    try map.put(peer, exact);
    try t.expectEqualSlices(u8, exact, map.get(peer).?.slice());
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

// A bootstrap list is bounded twice: by what a `u8` can count, and by
// `max_bootstrap`. Either half on its own would let the other one past.
test "a bootstrap list is refused by its count and by its length" {
    const peer = try sim.nodeIdFor(2);
    const over = [_]NodeId{peer} ** (max_bootstrap + 1);
    const unspellable = [_]NodeId{peer} ** (std.math.maxInt(u8) + 1);
    try t.expectError(error.BootstrapListTooLong, Peers.init(over[0..]));
    try t.expectError(error.BootstrapListTooLong, Peers.init(unspellable[0..]));
    const list = try Peers.init(over[0..max_bootstrap]);
    try t.expectEqual(max_bootstrap, list.slice().len);
}

// A config the fixed-capacity sets cannot hold is refused up front.
test "a config beyond the fixed views is refused" {
    try t.expectError(
        error.ActiveViewFull,
        (Config{ .active_view_capacity = max_active + 1 }).validate(),
    );
    try t.expectError(
        error.PassiveViewFull,
        (Config{ .passive_view_capacity = max_passive + 1 }).validate(),
    );
    try t.expectError(
        error.ShuffleNodeListTooLong,
        (Config{ .shuffle_active_view_count = max_shuffle_nodes }).validate(),
    );
    try (Config{}).validate();
}

/// Five neighbours, each with contact data, so the next `Join` has to make
/// room and the eviction it causes is observable.
fn joinedFive(state: *State, out: *Actions(SwarmOutEvent)) !void {
    for ([_]u8{ 2, 3, 4, 5, 6 }) |index| {
        try state.handle(.{ .recv_message = .{
            .from = try sim.nodeIdFor(index),
            .message = .{ .neighbor = .{ .priority = .high, .data = peerContact(index) } },
        } }, out);
    }
}

/// A direct `Join`, which the paper admits eagerly: it evicts a neighbour,
/// tells that neighbour it is going with a three-part farewell, inserts the
/// joiner, asks it to be a neighbour, and then fans the join out to every peer
/// left standing. Eleven actions, and one boundary in every three of them.
fn joinEvent(from: u8) !SwarmInEvent {
    return .{ .recv_message = .{
        .from = try sim.nodeIdFor(from),
        .message = .{ .join = peerContact(from) },
    } };
}

fn joinOnce(alloc: std.mem.Allocator) !void {
    var state: State = try newMembership(1, .{}, 43);
    var warm: Actions(SwarmOutEvent) = .init(t.allocator);
    defer warm.deinit();
    try prime(&state, &warm);
    try joinedFive(&state, &warm);
    var out: Actions(SwarmOutEvent) = .init(alloc);
    defer out.deinit();
    try state.handle(try joinEvent(7), &out);
}

// The event above is the busiest one in this layer: it evicts a peer, tells
// that peer in three appends, inserts the joiner, asks it to be a neighbour,
// and forwards the join to four more peers. Every one of those is an allocating
// boundary, and the state is committed in the middle of them rather than at
// the end — which is what makes this the case where the documented recovery
// has to be shown rather than asserted.
test "a refused join is recovered by restoring the snapshot and delivering it again" {
    const me = try sim.nodeIdFor(1);
    const joiner = try sim.nodeIdFor(7);

    // The reference run, so the recovery below is compared against what this
    // event does rather than against a count someone wrote down.
    var reference_actions: Actions(SwarmOutEvent) = .init(t.allocator);
    defer reference_actions.deinit();
    var reference_state: State = undefined;
    {
        var state: State = try newMembership(1, .{}, 43);
        var warm: Actions(SwarmOutEvent) = .init(t.allocator);
        defer warm.deinit();
        try prime(&state, &warm);
        try joinedFive(&state, &warm);
        try t.expectEqual(@as(usize, 5), state.activeView().len);
        warm.clear();
        try state.handle(try joinEvent(7), &reference_actions);
        reference_state = state;
        try t.expectEqual(@as(usize, 11), reference_actions.count());
    }
    const evicted = reference_state.passiveView()[0];

    const boundaries = try boundariesOf(joinOnce, .{});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        var state: State = try newMembership(1, .{}, 43);
        var warm: Actions(SwarmOutEvent) = .init(t.allocator);
        defer warm.deinit();
        try prime(&state, &warm);
        try joinedFive(&state, &warm);
        const snapshot = state;
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        {
            var out: Actions(SwarmOutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(error.OutOfMemory, state.handle(try joinEvent(7), &out));
            const published = out.count();
            try t.expect(published <= reference_actions.count());
            try t.expectEqual(@as(usize, 0), liveIn(&out, &failing));

            // What the event had committed when the refusal landed, read off
            // the state rather than off the list. The contact table gains the
            // joiner as soon as its `peer_data` action was published. The
            // active view loses one peer and gains one: the eviction happens
            // once the first action is out of the way and before the evicted
            // peer's farewell starts, and the joiner is inserted before its
            // `neighbor_up` — so the view is full, then short, then full
            // again, and where the refusal landed is what decides which. The
            // claim the neighbour request makes is withdrawn by
            // `sendNeighbor`'s own `errdefer` when the request itself could
            // not be published, which is what keeps a slot from being spent
            // for good.
            try t.expectEqual(
                5 + @as(usize, @intFromBool(published >= 1)),
                state.peer_data.len,
            );
            try t.expectEqual(
                5 - @as(usize, @intFromBool(published >= 1)) +
                    @as(usize, @intFromBool(published >= 5)),
                state.activeView().len,
            );
            try t.expectEqual(state.active_view.contains(joiner), published >= 5);
            try t.expectEqual(state.pending_neighbor_requests.contains(joiner), published >= 7);
            try t.expectEqual(state.passive_view.contains(evicted), published >= 5);
            try t.expectEqual(state.alive_disconnect_peers.contains(evicted), published >= 5);
            try t.expect(!state.left);
            try t.expect(state.shuffle_scheduled);

            // The recovery `State.handle` names, in the order it names it. The
            // snapshot goes back first because the value is plain and carries
            // its own storage, so it restores the generator as well as the
            // views; `out` was empty when the call started, so clearing it is
            // the whole undo — `Actions` cannot truncate to a saved length.
            try t.expectEqual(published, out.count());
            out.clear();
            try t.expectEqual(@as(usize, 0), out.count());
            state = snapshot;
            failing.fail_index = std.math.maxInt(usize);
            try state.handle(try joinEvent(7), &out);

            // And the second run is the first run: same actions in the same
            // order to the same peers, and the same swarm afterwards. That is
            // what makes this a recovery rather than a second chance.
            try expectSameActions(&out, &reference_actions, me);
            try expectSameMembership(&state, &reference_state);
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

/// A node with no neighbours yet, which is the state `TopicState` is handed to
/// in the cases below.
fn newTopic() (Error || key.KeyError)!TopicState {
    return TopicState.init(try sim.nodeIdFor(1), null, .{}, .init(9));
}

/// One `Neighbor` from a peer that is not connected yet, as the topic layer
/// receives it: the membership layer answers it, the broadcast layer is told
/// about the neighbour, and both layers' output is lifted into one list.
fn neighborEvent(from: u8) !InEvent {
    return .{ .recv_message = .{
        .from = try sim.nodeIdFor(from),
        .message = .{ .swarm = .{ .neighbor = .{
            .priority = .high,
            .data = peerContact(from),
        } } },
    } };
}

fn topicOnce(alloc: std.mem.Allocator) !void {
    var state: TopicState = try newTopic();
    var out: Actions(OutEvent) = .init(alloc);
    defer out.deinit();
    try state.handle(try neighborEvent(2), 0, &out);
}

/// One topic action without the slices in it: which kind it is and the peer or
/// timer it names.
const TopicAction = struct {
    tag: std.meta.Tag(OutEvent),
    to: NodeId,
    /// Which layer a `send_message` belongs to, and zero for every other kind.
    layer: u8,
};

fn describeTopic(out: *const Actions(OutEvent), me: NodeId) ![max_actions]TopicAction {
    var described: [max_actions]TopicAction = undefined;
    std.debug.assert(out.count() <= max_actions);
    for (out.slice(), 0..) |produced, index| described[index] = switch (produced) {
        .send_message => |send| .{
            .tag = .send_message,
            .to = send.to,
            .layer = switch (send.message) {
                .swarm => 1,
                .gossip => 2,
            },
        },
        .schedule_timer => |schedule| .{
            .tag = .schedule_timer,
            .to = switch (schedule.timer) {
                .swarm => |inner| switch (inner) {
                    .do_shuffle => me,
                    .pending_neighbor_request => |peer| peer,
                },
                .gossip => |inner| switch (inner) {
                    .dispatch_lazy_push, .evict_cache => me,
                    .send_graft => me,
                },
            },
            .layer = 0,
        },
        .disconnect_peer => |peer| .{ .tag = .disconnect_peer, .to = peer, .layer = 0 },
        .emit_event => |change| .{
            .tag = .emit_event,
            .to = switch (change) {
                .neighbor_up => |peer| peer,
                .neighbor_down => |peer| peer,
                .received => me,
            },
            .layer = 0,
        },
        .peer_data => |data| .{ .tag = .peer_data, .to = data.peer, .layer = 0 },
    };
    return described;
}

fn expectSameTopicActions(
    got: *const Actions(OutEvent),
    want: *const Actions(OutEvent),
    me: NodeId,
) !void {
    try t.expectEqual(want.count(), got.count());
    const left_actions = try describeTopic(want, me);
    const right_actions = try describeTopic(got, me);
    for (left_actions[0..want.count()], right_actions[0..got.count()]) |a, b| {
        try t.expectEqual(a.tag, b.tag);
        try t.expect(sameNode(a.to, b.to));
        try t.expectEqual(a.layer, b.layer);
    }
}

/// Two topic states carry the same membership and the same broadcast tree,
/// which together are what a snapshot restore has to put back.
fn expectSameTopic(got: *const TopicState, want: *const TopicState) !void {
    try expectSameMembership(&got.swarm, &want.swarm);
    try t.expectEqual(want.gossip.started, got.gossip.started);
    try t.expectEqual(want.gossip.left, got.gossip.left);
    try t.expectEqual(want.gossip.cache.count(), got.gossip.cache.count());
    try t.expectEqual(want.gossip.received_messages.count(), got.gossip.received_messages.count());
    try t.expectEqual(want.gossip.missing_messages_len, got.gossip.missing_messages_len);
    try t.expectEqual(want.gossip.lazy_push_queue_len, got.gossip.lazy_push_queue_len);
    try t.expectEqual(
        want.gossip.dispatch_timer_scheduled,
        got.gossip.dispatch_timer_scheduled,
    );
    try t.expectEqual(want.gossip.eagerPeers().len, got.gossip.eagerPeers().len);
    try t.expectEqual(want.gossip.lazyPeers().len, got.gossip.lazyPeers().len);
    for (want.gossip.eagerPeers(), got.gossip.eagerPeers()) |a, b| {
        try t.expect(sameNode(a, b));
    }
    try t.expectEqual(want.stats.messages_sent, got.stats.messages_sent);
    try t.expectEqual(want.stats.messages_received, got.stats.messages_received);
    try t.expectEqual(want.left, got.left);
}

// The topic layer is where the two passes live: the membership layer and the
// broadcast layer fill scratch containers this function owns, and only the
// passes at the end copy them into the caller's list. So a refusal can land
// inside a layer, where the caller's list is untouched and both layers have
// advanced, or inside a pass, where the list holds the entries copied before
// it. Both are the same from outside — a prefix and a moved state — and this
// walks every boundary to prove it, and then shows the documented recovery
// putting the topic back exactly where it was.
test "a refused topic event publishes a prefix and is recovered by a restore" {
    const me = try sim.nodeIdFor(1);

    var reference_actions: Actions(OutEvent) = .init(t.allocator);
    defer reference_actions.deinit();
    var reference_state: TopicState = undefined;
    {
        var state: TopicState = try newTopic();
        try state.handle(try neighborEvent(2), 0, &reference_actions);
        reference_state = state;
        // Four membership actions and the broadcast layer's entry sweep.
        try t.expectEqual(@as(usize, 5), reference_actions.count());
    }

    const boundaries = try boundariesOf(topicOnce, .{});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        var state: TopicState = try newTopic();
        const snapshot = state;
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        {
            var out: Actions(OutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(error.OutOfMemory, state.handle(try neighborEvent(2), 0, &out));
            const published = out.count();
            try t.expect(published <= reference_actions.count());
            try t.expectEqual(@as(usize, 0), liveIn(&out, &failing));

            // `Stats.messages_sent` counts what this call appended to `out` and
            // nothing else, so a refusal cannot have counted an action the
            // caller never received or lost one it did. It is the counter a
            // driver reports from, which is why it is checked against the
            // list itself rather than against a number.
            var sent: usize = 0;
            for (out.slice()) |produced| sent += @intFromBool(produced == .send_message);
            try t.expectEqual(@as(u64, sent), state.stats.messages_sent);
            // A received frame is counted whatever the refusal did to the rest.
            try t.expectEqual(@as(u64, 1), state.stats.messages_received);

            // The recovery `TopicState.handle` names: both layers inline in the
            // value, so one copy restores the views, the broadcast tree and the
            // generator, and the caller's list was empty on entry so clearing
            // it is the whole undo.
            try t.expectEqual(published, out.count());
            out.clear();
            state = snapshot;
            failing.fail_index = std.math.maxInt(usize);
            try state.handle(try neighborEvent(2), 0, &out);

            try expectSameTopicActions(&out, &reference_actions, me);
            try expectSameTopic(&state, &reference_state);
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

// The other half of the recovery `State.handle` offers, and the one a driver
// reaches when it cannot keep a copy: treat the refused event as the end of
// this peer's run. What has to hold for that to be a decision rather than a
// mess is that the state is still a `State` — every mutation checked, nothing
// half-written — so a *different* event is still answered correctly on top of
// it. This walks every boundary of the join above and then sends an event the
// protocol has no excuse to mishandle because of where the last one stopped.
test "a state refused part way through a join still answers the next event" {
    const boundaries = try boundariesOf(joinOnce, .{});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        var state: State = try newMembership(1, .{}, 43);
        var warm: Actions(SwarmOutEvent) = .init(t.allocator);
        defer warm.deinit();
        try prime(&state, &warm);
        try joinedFive(&state, &warm);
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        {
            var refused_out: Actions(SwarmOutEvent) = .init(alloc);
            defer refused_out.deinit();
            try t.expectError(
                error.OutOfMemory,
                state.handle(try joinEvent(7), &refused_out),
            );
            try t.expectEqual(@as(usize, 0), liveIn(&refused_out, &failing));
            // The frame was received and counted before the first append, so
            // the counter moved even though the refusal did not: this is a
            // receive counter and not a delivery counter.
            try t.expectEqual(@as(u64, 6), state.stats.total_connections);
            try t.expect(!state.left);
        }

        // The abandonment: no snapshot, no retry, this peer's run ends here.
        // What makes that a decision rather than a mess is that the state is
        // still a `State` — every mutation checked, nothing half-written — so
        // the claims it is holding can still be given up, one timer at a time,
        // as they would have been on a state that had never been refused. The
        // list is copied out first, because firing a timer withdraws the very
        // claim the loop would otherwise walk next.
        var owed: [max_active]NodeId = undefined;
        const owed_count = state.pending_neighbor_requests.count();
        try t.expect(owed_count > 0);
        for (state.pending_neighbor_requests.slice(), 0..) |peer, index| {
            owed[index] = peer;
        }
        {
            var after: Actions(SwarmOutEvent) = .init(alloc);
            defer after.deinit();
            for (owed[0..owed_count]) |peer| {
                try state.handle(.{ .timer_expired = .{ .pending_neighbor_request = peer } }, &after);
            }
            // Every claim was given up, so none is pending a timer that was
            // never queued.
            try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
            // The active view is still a set of peers inside the configured
            // capacity, and the shuffle timer the node already held is still
            // held rather than waiting on an append that never happened.
            try t.expect(state.activeView().len <= state.config.active_view_capacity);
            try t.expect(state.shuffle_scheduled);
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
