//! What the tree does when an output append is refused.
//!
//! Every latch below — the dispatch timer, each entry's graft timer, the entry
//! sweep — is a claim that a timer exists. Each of these tests refuses one
//! append and then asserts the claim was not left standing over a timer the
//! caller never received, and that the next event asks for it again.

const std = @import("std");
const actions = @import("actions.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const node_id = @import("node_id.zig");
const tree = @import("state.zig");
const test_node_id = @import("test_node_id.zig");
const vectors = @import("blake3_vectors.zig");

const t = std.testing;

const Actions = actions.Actions;
const IHaves = wire.IHaves;
const OutEvent = wire.OutEvent;
const MessageId = message_id.MessageId;
const sameNode = node_id.sameNode;
const State = tree.State;
const testNodeId = test_node_id.testNodeId;
const blake3Input = vectors.blake3Input;

// Both timer latches below are claims that a timer exists. Set before the
// append that publishes the timer, the claim survives an allocator refusing
// that append, and the timer is then never produced: for the graft timer the
// message is never asked for, and for the dispatch timer the queued ids wait
// for a flush that nothing will trigger. Both are fixed the same way — the
// append happens first — and both tests below fail without that order.
test "a graft timer that could not be queued is asked for on the next claim" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(8);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    // A first container over a real allocator, because the entry sweep is
    // queued once on the first call whatever it is and must not be the
    // allocation that fails here.
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try state.handle(.{ .neighbor_up = peer }, 0, &warm);

    // A fresh container each time, because `clear` keeps its capacity and a
    // container that already has room would not allocate at all.
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(OutEvent) = .init(failing.allocator());
    defer out.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(error.OutOfMemory, state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = id, .round = .{ .value = 2 } }}) },
    } }, 0, &out));

    // The claim was filed and the timer was not queued.
    try t.expectEqual(@as(usize, 1), state.missing_messages_len);
    try t.expect(!state.missing_messages[0].graft_timer_scheduled);
    try t.expectEqual(@as(usize, 0), out.count());

    // So the next claim queues it.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    try t.expect(state.missing_messages[0].graft_timer_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expectEqual(state.config.graft_timeout_1, out.at(0).schedule_timer.after);
}

test "a dispatch timer that could not be queued is flushed on the next burst" {
    const me = try testNodeId(1);
    const lazy_child = try testNodeId(4);
    const content = try blake3Input(3);
    defer t.allocator.free(content);

    var state: State = .init(me, .{});
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try state.handle(.{ .neighbor_up = lazy_child }, 0, &warm);
    // The tree puts this edge on the lazy side, which is what makes a burst
    // queue ids instead of pushing payloads.
    try state.addLazy(lazy_child);

    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(OutEvent) = .init(failing.allocator());
    defer out.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(
        error.OutOfMemory,
        state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &out),
    );
    try t.expect(!state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 0), out.count());

    // The queued ids are still there, so one more burst and the flush goes out.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &out);
    try t.expect(state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
}

// The other half of the latch rule. `lazyPush` queues before it sets, because
// a latch set first is a claim that a timer exists which the caller never
// received. A *consumed* timer is the mirror image: the caller has already
// taken that timer out of its queue and handed it to this call, so a latch
// still set when the flush is refused is a claim about a timer that will never
// fire again — and nothing in the tree ever sets it false, because the only
// event that clears it is the one that cannot be scheduled.
test "a dispatch flush that could not be published leaves no phantom timer" {
    const me = try testNodeId(1);
    const lazy_child = try testNodeId(4);
    const content = try blake3Input(3);
    defer t.allocator.free(content);

    var state: State = .init(me, .{});
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try state.handle(.{ .neighbor_up = lazy_child }, 0, &warm);
    try state.addLazy(lazy_child);
    // One burst, which queues this node's id and arms the timer the event
    // below will consume.
    try state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &warm);
    try t.expect(state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 1), state.lazy_push_queue_len);

    // A fresh container, because `clear` keeps its capacity and a container
    // that already has room would not allocate at all.
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(OutEvent) = .init(failing.allocator());
    defer out.deinit();
    failing.fail_index = failing.alloc_index;
    try t.expectError(
        error.OutOfMemory,
        state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &out),
    );

    // The timer the caller handed us is gone and nothing replaced it, so the
    // claim that one is outstanding has to go with it.
    try t.expect(!state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 1), state.lazy_push_queue_len);
    try t.expectEqual(@as(usize, 0), out.count());

    // The next burst re-arms it, and the ids the failed flush never sent are
    // still queued, so the second flush goes out rather than stranding them.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &out);
    try t.expect(state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);

    out.clear();
    try state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &out);
    try t.expect(!state.dispatch_timer_scheduled);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, lazy_child));
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
}

// The third arm of the latch rule, and the only one `handle` owns. The entry
// sweep is queued once, on the first call, and the latch that says the first
// call has run is set only after the append that publishes it. A latch set
// first is a claim that a timer exists which the caller never received, so an
// allocator refusing that one append would leave a tree that never sweeps
// again for the life of the state: `Config.message_cache_retention` and
// `Config.message_id_retention` would go dead with nothing to report it.
test "an entry sweep that could not be queued is queued again on the next event" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);

    var state: State = .init(me, .{});
    var failing = std.testing.FailingAllocator.init(t.allocator, .{});
    var out: Actions(OutEvent) = .init(failing.allocator());
    defer out.deinit();

    // A `neighbor_down` appends nothing and mutates nothing, so the very next
    // allocation the event reaches is the entry sweep's.
    failing.fail_index = failing.alloc_index;
    try t.expectError(error.OutOfMemory, state.handle(.{ .neighbor_down = peer }, 0, &out));

    // The sweep was not published, so the state must not claim its first call
    // has run: a second sweep is what this call would have to make.
    try t.expect(!state.started);
    try t.expectEqual(@as(usize, 0), out.count());

    // So the next event queues it, and only then latches.
    failing.fail_index = std.math.maxInt(usize);
    try state.handle(.{ .neighbor_down = peer }, 0, &out);
    try t.expect(state.started);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .evict_cache);
    try t.expectEqual(state.config.cache_evict_interval, out.at(0).schedule_timer.after);
}

// `leave` is a promise about the state, and `broadcast` is a public door into
// it. A state that has left and is then asked to broadcast directly re-fills
// both caches, arms a dispatch timer and publishes it — which is the residue
// `leave` exists to make unreachable. `handle`'s latch is not enough on its
// own, because a caller holding the tree can reach past it.
test "a broadcast offered to a state that has left reaches nothing" {
    const me = try testNodeId(1);
    const eager_child = try testNodeId(3);
    const lazy_child = try testNodeId(4);
    const content = try blake3Input(3);
    defer t.allocator.free(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .neighbor_up = eager_child }, 0, &out);
    try state.addLazy(lazy_child);
    state.leave();

    // The list belongs to the caller, and neither `leave` nor the broadcast
    // below reaches into it to take anything back — so whatever the event
    // before them already published is the baseline, and the claim under test
    // is that the broadcast adds nothing to it.
    const before = out.count();

    try state.broadcast(content, .swarm, 0, &out);

    try t.expectEqual(before, out.count());
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expect(!state.dispatch_timer_scheduled);
}

// A topic's `quit` promises to drop its state. The caches are state, and the
// observable proof that they are gone is silence: a graft for a payload this
// node no longer holds gets no reply, which is the only honest one.
test "leaving drops the tree, its queues and both caches" {
    const me = try testNodeId(1);
    const eager_child = try testNodeId(3);
    const lazy_child = try testNodeId(4);
    const claimer = try testNodeId(2);
    const content = try blake3Input(3);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);
    // An id this node has never seen, so the claim table has an entry in it.
    const stranger = MessageId.fromContent("not-mine");

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = eager_child }, 0, &out);
    try state.addLazy(lazy_child);
    try state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &out);
    try state.handle(.{ .recv_message = .{
        .from = claimer,
        .message = .{ .i_have = try IHaves.init(&.{
            .{ .id = stranger, .round = .{ .value = 2 } },
        }) },
    } }, 0, &out);

    // Every table is loaded, or the rest of this test proves nothing.
    try t.expectEqual(@as(usize, 1), state.eager_push_peers.count());
    try t.expectEqual(@as(usize, 1), state.lazy_push_peers.count());
    try t.expectEqual(@as(usize, 1), state.cache.count());
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
    try t.expectEqual(@as(usize, 1), state.missing_messages_len);
    try t.expect(state.lazy_push_queue_len > 0);
    try t.expect(state.dispatch_timer_scheduled);

    state.leave();

    try t.expectEqual(@as(usize, 0), state.eager_push_peers.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_peers.count());
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), state.missing_messages_len);
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);

    // And silence, which is what the drop is observable as. The graft asks for
    // the payload this node held a moment ago; there is nothing to answer it
    // from, so nothing goes out.
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = claimer,
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 3 } } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 0), out.count());

    // A broadcast afterwards reaches no peer: the edges are gone, so there is
    // no eager push and no lazy queue.
    try state.handle(.{ .broadcast = .{ .content = content, .scope = .swarm } }, 0, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.cache.count());

    // `leave` twice is the same as once, and it owes the caller no output.
    out.clear();
    state.leave();
    try t.expectEqual(@as(usize, 0), out.count());
}

test "leaving before the first turn does not schedule a cache timer" {
    var state: State = .init(try testNodeId(1), .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();
    state.leave();
    try state.handle(.{ .timer_expired = .evict_cache }, 0, &out);
    try t.expectEqual(@as(usize, 0), out.count());
}

// The second half: a peer that hears the same id from a third party grafts us
// directly, and the cache is what answers. The payload is copied on the way in
// precisely so that this reply can be made after the original message is gone.
