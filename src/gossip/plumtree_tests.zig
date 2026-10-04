//! PlumTree's tests: what a second implementation has to agree with, byte for
//! byte and edge for edge.
//!
//! # Why this file exists
//!
//! `plumtree.zig` is the broadcast state machine and nothing else — no clock,
//! no allocator, no environment, no test. Every assertion that needs a
//! `std.testing` seam was lifted out of it into this file, the way
//! `node/node_tests.zig` and `node/node_retirement_tests.zig` lifted theirs,
//! so that the file that states what a `Graft` does is not also the file that
//! argues with it.
//!
//! # Reaching into the machine
//!
//! These tests read `state.eager`, `state.lazy`, `state.cache`,
//! `state.missing`, `state.lazy_push_queue` and the timer latches — tables a
//! caller outside this module cannot see. That is the point of most of the
//! assertions here: "the queue holds exactly two entries" is a claim about the
//! machine, and an emitted `IHave` is only a claim about what it intended.
//! A caller holding a `State` has one way to observe it, and it is the event
//! it sends next; everything below would be untestable through it.
//!
//! # What is here
//!
//! Three regions, in the order the machine reaches them.
//!
//! 1. **The digest.** `MessageId` is `blake3(content)` with no domain
//!    separation, pinned against published vectors rather than against this
//!    implementation's own output, and a received `Gossip` is re-hashed and
//!    dropped without penalising the peer that sent it.
//! 2. **The iTree.** Eager and lazy edges, the `IHave` → `Graft` exchange, the
//!    two caches and their clocks, the shortest-path optimisation, and the
//!    leave latch that makes a quit a fact about the state rather than a hope
//!    about its fields.
//! 3. **The allocation-failure sweeps.** Each one drives a refused event at
//!    every boundary in turn, restores a snapshot, replays the event, and
//!    compares the republished actions against a reference run — because
//!    "did not crash" is not the claim, "publishes a prefix and recovers" is.
//!
//! # Reach
//!
//! Both roots run this file, exactly as both run `plumtree.zig`: the native
//! `src/unit_test.zig` and the socket-free `src/portable_test.zig`. Nothing
//! here reaches a socket, and the split does not move a platform boundary.

const std = @import("std");
const key = @import("../base/key.zig");
const plumtree = @import("plumtree.zig");

const NodeId = key.NodeId;

const t = std.testing;

/// Node ids from fixed seeds, as `discovery/item.zig` does them. A `NodeId`
/// cannot be built from arbitrary bytes — `fromBytes` rejects a non-point — so
/// a test pool draws from seeds.
///
/// Fallible, because a seed that derives the identity point is a `u8` value
/// away and nothing about `0xa5` rules it out. A test that hit one says
/// `error.DegenerateSeed` and names its seed; a `unreachable` here would take
/// the whole test binary down and say nothing.
fn testNodeId(index: u8) key.KeyError!NodeId {
    var seed: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&seed, 0xa5);
    seed[0] = index;
    return (try key.SecretKey.fromSeed(seed)).nodeId();
}

/// The input of a BLAKE3 test-vector case: 0, 1, ... 250 repeating.
///
/// Fallible for the ordinary reason: the testing allocator runs out like any
/// other, and a test that cannot say so is a test that reports a crash.
fn blake3Input(len: usize) ![]u8 {
    const input = try t.allocator.alloc(u8, len);
    for (input, 0..) |*byte, index| byte.* = @intCast(index % 251);
    return input;
}

/// BLAKE3 test vectors from `BLAKE3-team/BLAKE3`,
/// `test_vectors/test_vectors.json`, commit
/// `6aab490a26124663329dfd3961b8469f8fdb158b`, fetched 2026-09-30. The input of
/// each case is the 251-byte sequence 0, 1, ... 250 repeating, per the
/// `COMMENT` in `test_vectors/src/lib.rs` at the same commit.
///
/// `hash` is the plain hash, which is what a `MessageId` is. `derive_key` is
/// the same input under the key-derivation mode and the context string
/// `BLAKE3 2019-12-27 16:29:52 test vectors context`; it is here so the
/// rejection test can use a real domain-separated digest.
/// The 32 bytes behind a 64-character hex digest, decoded at run time.
/// A `MessageId` is a byte array, so a table of published digests has to be
/// decoded before it can be compared with one, and a comptime decode of two
/// dozen literals costs more compile time than the whole rest of the module.
fn messageIdFromHex(hex: []const u8) MessageId {
    if (hex.len != id_length * 2) @panic("a digest literal must be 64 hex characters");
    var bytes: [id_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch @panic("a digest literal must be hex");
    return MessageId.fromBytes(bytes);
}

const Blake3Vector = struct {
    len: usize,
    /// The plain hash: this is what a `MessageId` is.
    hash: []const u8,
    /// The same input under key derivation and the published context string.
    derive_key: []const u8,
};

const blake3_vectors = [_]Blake3Vector{
    .{
        .len = 0,
        .hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        .derive_key = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
    },
    .{
        .len = 1,
        .hash = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        .derive_key = "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
    },
    .{
        .len = 2,
        .hash = "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        .derive_key = "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6",
    },
    .{
        .len = 3,
        .hash = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        .derive_key = "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797",
    },
    .{
        .len = 8,
        .hash = "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
        .derive_key = "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940",
    },
    .{
        .len = 63,
        .hash = "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        .derive_key = "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3",
    },
    .{
        .len = 64,
        .hash = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        .derive_key = "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e",
    },
    .{
        .len = 127,
        .hash = "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
        .derive_key = "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3",
    },
    .{
        .len = 128,
        .hash = "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
        .derive_key = "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225",
    },
    .{
        .len = 1023,
        .hash = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        .derive_key = "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
    },
    .{
        .len = 1024,
        .hash = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        .derive_key = "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
    },
};
// A `MessageId` is the plain BLAKE3 hash of the content, checked against the
// published vectors rather than against this implementation's own output.
test "a message id is blake3 of the content, and nothing else" {
    for (blake3_vectors) |vector| {
        const input = try blake3Input(vector.len);
        defer t.allocator.free(input);
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(
            MessageId.fromContent(input).toBytes(),
            .lower,
        ));
        try t.expect(messageIdFromHex(vector.hash).eql(MessageId.fromContent(input)));
        try t.expect(!messageIdFromHex(vector.derive_key).eql(MessageId.fromContent(input)));
    }
}

// The failure this module is most likely to suffer: an id computed under a
// context string. It is a different value for the same content, so it is not
// an id, and a message carrying one is dropped.
test "a domain-separated id is not a message id" {
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    const separated = domainSeparatedId(context, content);
    try t.expect(!MessageId.fromContent(content).eql(separated));

    for (blake3_vectors) |vector| {
        const input = try blake3Input(vector.len);
        defer t.allocator.free(input);
        const wrong = messageIdFromHex(vector.derive_key);
        const gossip: Gossip = .{
            .id = wrong,
            .content = input,
            .scope = .{ .swarm = Round.zero },
        };
        try t.expect(!gossip.validate());
    }
}

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

// Upstream `plumtree::test::cache_is_evicted`: the payload cache holds a
// message for `message_cache_retention` and not one tick longer.
test "the payload cache is evicted on its own clock" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    const one_interval = state.config.cache_evict_interval;
    try state.handle(.{ .timer_expired = .evict_cache }, one_interval, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    try state.handle(
        .{ .timer_expired = .evict_cache },
        one_interval + state.config.message_cache_retention,
        &out,
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
    // The id is still remembered: `message_id_retention` is three times
    // `message_cache_retention`, which is what stops a late graft being
    // answered with a payload we have already forgotten but still recognise.
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
}

// The eager and lazy sets are sorted, and a fan-out follows that order, so
// two implementations agree on who is asked first.
test "the iTree sets are sorted" {
    const me = try testNodeId(9);
    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    for ([_]u8{ 5, 1, 8, 3 }) |index| try state.addEager(try testNodeId(index));
    try t.expectEqual(@as(usize, 4), state.eagerPeers().len);
    var at: usize = 1;
    while (at < state.eagerPeers().len) : (at += 1) {
        try t.expect(state.eagerPeers()[at - 1].order(state.eagerPeers()[at]) == .lt);
    }

    const content = try blake3Input(1);
    defer t.allocator.free(content);
    out.clear();
    try state.broadcast(content, .swarm, 0, &out);
    // Four payloads and one dispatch timer, the timer first because the lazy
    // push is queued before the eager one goes out.
    try t.expectEqual(@as(usize, 5), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    at = 2;
    while (at < out.count()) : (at += 1) {
        const before = out.at(at - 1).send_message.to;
        const after = out.at(at).send_message.to;
        try t.expect(before.order(after) == .lt);
    }
}

// A payload over the cache's bound is refused rather than truncated, because
// a truncated payload with the right id is a message nobody can verify.
test "a payload over the bound is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.broadcast(content, .swarm, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// The receive path bounds the payload as well, and the bound belongs in the
// cache: an oversized gossip off the wire must be refused there, never
// truncated into an entry whose id is the hash of a longer message.
test "a received payload over the bound is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = try testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// `max_content + 1` fits a `u16` and this does not, so the two bounds are
// separate arms and this pins the narrowing one. With the ceiling alone and a
// bare `@intCast`, this length truncates to zero in an unchecked build and
// traps in this one — either way the entry ends up an empty payload under the
// hash of 65536 bytes.
test "a received payload too long to record is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = try testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// ---------------------------------------------------------------------------
// Allocation-failure sweeps
// ---------------------------------------------------------------------------

/// How many allocations `run` makes. The error the probe saw is dropped on
/// purpose: the count is what this is for, and every sweep below re-runs each
/// boundary and asserts the error it gets there.
///
/// `resize_fail_index` is pinned at zero. A growth the backing allocator can
/// satisfy in place goes through `resize` rather than `alloc`, consumes no
/// allocation index, and is a boundary no `fail_index` can reach — the sweep
/// would step over it and the case would look complete while a growth went
/// untested. Refusing every resize routes each growth through `alloc`.
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
/// `Actions` owns its list and nothing else, and every cache, queue and claim
/// table in a `State` is inline in the value, so the caller's own container is
/// the only thing that can hold memory at the end of a refused call. This is
/// the assertion that says so rather than assuming it: a sweep that leaked a
/// chunk into the state, or freed the container's buffer under it, would not
/// come out as zero here.
fn liveIn(
    comptime Out: type,
    out: *const Actions(Out),
    failing: *const t.FailingAllocator,
) usize {
    return failing.allocated_bytes - failing.freed_bytes -
        out.items.capacity * @sizeOf(Out);
}

/// Node ids `first`..`first + span`, in the order the tree iterates them: the
/// iTree sets are sorted by node id, not by the seed the ids are drawn from,
/// so a test that asserts where a payload went has to sort them the same way.
fn sortedIds(comptime span: usize, comptime first: u8) ![span]NodeId {
    var ids: [span]NodeId = undefined;
    for (0..span) |index| {
        ids[index] = try testNodeId(first + @as(u8, @intCast(index)));
    }
    std.mem.sort(NodeId, &ids, {}, struct {
        fn less(_: void, a: NodeId, b: NodeId) bool {
            return a.order(b) == .lt;
        }
    }.less);
    return ids;
}

/// The payload every sweep below moves. A compile-time constant so the setup
/// costs no allocation: a boundary count that included the test's own buffer
/// would be a count of the test rather than of the code under it.
const sweep_payload = "ozai-gossip-allocation-sweep";

/// Six neighbours: five on the eager side and one lazy edge, which is a tree
/// wide enough that a forwarded payload is four appends before anything else.
fn eagerTree(state: *State, out: *Actions(OutEvent)) !void {
    // `2` is the sender the payload arrives from; `3`..`6` are the children it
    // is forwarded to; `7` is the lazy edge it is announced on instead.
    for ([_]u8{ 2, 3, 4, 5, 6 }) |index| {
        try state.handle(.{ .neighbor_up = try testNodeId(index) }, 0, out);
    }
    try state.addLazy(try testNodeId(7));
}

fn forwardedGossip(content: []const u8) !InEvent {
    return .{ .recv_message = .{
        .from = try testNodeId(2),
        .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = .{ .value = 3 } },
        } },
    } };
}

fn forwardOnce(alloc: std.mem.Allocator) !void {
    var state: State = .init(try testNodeId(1), .{});
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try eagerTree(&state, &warm);
    var out: Actions(OutEvent) = .init(alloc);
    defer out.deinit();
    try state.handle(try forwardedGossip(sweep_payload), 0, &out);
}

// A forwarded payload across a tree with four eager children and a lazy edge:
// six appends, of which the fifth is the dispatch timer the lazy arm queues
// and the sixth is the application event. This is the path where the refusal
// lands *after* work the state has already committed — the id is remembered
// and the payload is cached before the first append — so it is where "not
// transactional" has to be read as something the caller can act on.
test "a refused forward publishes a prefix and keeps what the prefix names" {
    const id = MessageId.fromContent(sweep_payload);
    const children = try sortedIds(4, 3);

    // The reference run, so the sweep below is compared against what this
    // event publishes rather than against a number someone wrote down.
    var reference_count: usize = 0;
    {
        var state: State = .init(try testNodeId(1), .{});
        var warm: Actions(OutEvent) = .init(t.allocator);
        defer warm.deinit();
        try eagerTree(&state, &warm);
        var out: Actions(OutEvent) = .init(t.allocator);
        defer out.deinit();
        try state.handle(try forwardedGossip(sweep_payload), 0, &out);
        reference_count = out.count();
    }
    try t.expectEqual(@as(usize, 6), reference_count);

    const boundaries = try boundariesOf(forwardOnce, .{});
    // One boundary is the first append and nothing else, which would make the
    // case a single row with extra steps.
    try t.expect(boundaries > 1);

    var deepest: usize = 0;
    for (0..boundaries) |refused| {
        var state: State = .init(try testNodeId(1), .{});
        var warm: Actions(OutEvent) = .init(t.allocator);
        defer warm.deinit();
        try eagerTree(&state, &warm);
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        const published: usize = blk: {
            var out: Actions(OutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(
                error.OutOfMemory,
                state.handle(try forwardedGossip(sweep_payload), 0, &out),
            );
            // A prefix of the reference: the payload sends first, in the tree's
            // own sorted order, then the dispatch timer, then the application
            // event, which no refusal here can reach.
            const count = out.count();
            const sent = @min(count, children.len);
            for (out.slice()[0..sent], 0..) |produced, index| {
                try t.expect(produced == .send_message);
                try t.expect(sameNode(produced.send_message.to, children[index]));
            }
            if (count > sent) {
                try t.expect(out.at(sent) == .schedule_timer);
                try t.expect(out.at(sent).schedule_timer.timer == .dispatch_lazy_push);
            }
            try t.expect(count <= reference_count);
            // The payload the published sends name is the one the cache is
            // holding, and it is still there after the refusal: the entry is a
            // borrow, so a sweep that lost the cache would leave the caller
            // holding a pointer into nothing.
            const cached = state.cache.get(id) orelse return error.TestUnexpectedResult;
            try t.expectEqualStrings(sweep_payload, cached.content);
            try t.expect(state.received_messages.contains(id));
            try t.expectEqual(@as(usize, 0), liveIn(OutEvent, &out, &failing));
            break :blk count;
        };
        deepest = @max(deepest, published);

        // The dispatch latch is a claim that the caller holds the timer, and it
        // is true exactly when that append made it into the list — so a
        // refusal of the arm itself leaves it clear, which is what lets the
        // next burst arm it. The idle arm's queued ids are a different thing:
        // they are written before the timer is, so a refusal after them leaves
        // work the next burst still flushes.
        try t.expectEqual(published >= 4, state.dispatch_timer_scheduled);
        try t.expectEqual(
            @as(usize, @intFromBool(published >= 4)),
            state.lazy_push_queue_len,
        );

        // The consumer's way forward. The id was remembered before the
        // refusal, so asking again is not a repeat of the forward: the tree
        // already holds this message, the sender moves to the lazy side and is
        // pruned, and the id the lazy edge is waiting for is still queued.
        {
            failing.fail_index = std.math.maxInt(usize);
            var again: Actions(OutEvent) = .init(alloc);
            defer again.deinit();
            try state.handle(try forwardedGossip(sweep_payload), 0, &again);
            try t.expectEqual(@as(usize, 1), again.count());
            try t.expect(again.at(0) == .send_message);
            try t.expect(sameNode(again.at(0).send_message.to, try testNodeId(2)));
            try t.expect(again.at(0).send_message.message == .prune);
            try t.expect(state.lazy_push_peers.contains(try testNodeId(2)));
            try t.expect(!state.eager_push_peers.contains(try testNodeId(2)));
        }

        // And the timer the caller is owed. The latch read above is what the
        // caller is actually holding, so the burst after it arms a timer
        // exactly when the refusal left the latch clear, and firing the timer
        // it already holds empties the queue that timer was going to flush.
        {
            const owed = !state.dispatch_timer_scheduled;
            var burst: Actions(OutEvent) = .init(alloc);
            defer burst.deinit();
            try state.broadcast(sweep_payload, .swarm, 0, &burst);
            try t.expectEqual(owed, burst.at(0) == .schedule_timer);
            try t.expect(state.dispatch_timer_scheduled);
            var flush: Actions(OutEvent) = .init(alloc);
            defer flush.deinit();
            try state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &flush);
            try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
            try t.expect(!state.dispatch_timer_scheduled);
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    // The deepest prefix any of those refusals could leave is five: the
    // sixth append is the application event and no allocation stands between
    // it and the fifth, so no boundary can be refused after it.
    try t.expectEqual(@as(usize, 5), deepest);
}

/// Eight distinct messages a peer advertises in one `IHave`. Distinct
/// compile-time constants, so the burst costs no allocation of its own and a
/// boundary count is a count of the protocol and not of the fixture.
const advertised = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" };

fn advertisement(from: u8) !InEvent {
    var ihaves: [advertised.len]IHave = undefined;
    for (advertised, 0..) |content, index| {
        ihaves[index] = .{
            .id = MessageId.fromContent(content),
            .round = .{ .value = 2 },
        };
    }
    return .{ .recv_message = .{
        .from = try testNodeId(from),
        .message = .{ .i_have = try IHaves.init(&ihaves) },
    } };
}

fn burstOnce(alloc: std.mem.Allocator) !void {
    var state: State = .init(try testNodeId(1), .{});
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try state.handle(.{ .neighbor_up = try testNodeId(2) }, 0, &warm);
    var out: Actions(OutEvent) = .init(alloc);
    defer out.deinit();
    try state.handle(try advertisement(2), 0, &out);
}

// A burst of eight advertisements: one claim and one graft timer each, so
// eight appends and three boundaries. The single-claim case above can only
// fail its first timer, so the latch rule has nothing to be wrong about past
// that point; here a refusal in the middle leaves half the claims owing a
// timer and half not, and every later claim is skipped because the error
// leaves the loop.
test "a refused advertisement burst queues the timers that are still owed" {
    const boundaries = try boundariesOf(burstOnce, .{});
    try t.expect(boundaries > 1);

    var deepest: usize = 0;
    for (0..boundaries) |refused| {
        var state: State = .init(try testNodeId(1), .{});
        var warm: Actions(OutEvent) = .init(t.allocator);
        defer warm.deinit();
        try state.handle(.{ .neighbor_up = try testNodeId(2) }, 0, &warm);
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        const published: usize = blk: {
            var out: Actions(OutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(
                error.OutOfMemory,
                state.handle(try advertisement(2), 0, &out),
            );
            for (out.slice()) |produced| {
                try t.expect(produced == .schedule_timer);
                try t.expect(produced.schedule_timer.timer == .send_graft);
            }
            try t.expectEqual(@as(usize, 0), liveIn(OutEvent, &out, &failing));
            break :blk out.count();
        };
        deepest = @max(deepest, published);

        // One claim per advertisement, in arrival order, and one more than the
        // published timers: the claim is filed before its timer is queued, so
        // the claim whose timer was refused is on record and owes one.
        try t.expectEqual(published + 1, state.missing_messages_len);
        for (state.missing_messages[0..published], 0..) |entry, index| {
            try t.expect(entry.id.eql(MessageId.fromContent(advertised[index])));
            try t.expect(entry.graft_timer_scheduled);
        }
        const owed = state.missing_messages[published];
        try t.expect(owed.id.eql(MessageId.fromContent(advertised[published])));
        // A latch set before the append would say a timer exists for this
        // claim, and nothing would ever ask for that message.
        try t.expect(!owed.graft_timer_scheduled);

        // The consumer's way forward: the same burst again. Claims whose timer
        // was published are skipped, so the retry queues exactly the timers
        // that are still owed and re-queues none of the others.
        {
            failing.fail_index = std.math.maxInt(usize);
            var again: Actions(OutEvent) = .init(alloc);
            defer again.deinit();
            try state.handle(try advertisement(2), 0, &again);
            try t.expectEqual(advertised.len - published, again.count());
            for (again.slice()) |produced| {
                try t.expect(produced == .schedule_timer);
                try t.expect(produced.schedule_timer.timer == .send_graft);
            }
            try t.expectEqual(advertised.len, state.missing_messages_len);
            for (state.missing_messages[0..advertised.len]) |entry| {
                try t.expect(entry.graft_timer_scheduled);
            }
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }

    // Five is the deepest prefix any of those refusals leaves: the sixth
    // append fits the capacity the third growth bought, and the eighth is the
    // last one there is.
    try t.expectEqual(@as(usize, 5), deepest);
}

/// Seven eager children and one lazy edge: a tree wide enough that a broadcast
/// is eight appends.
fn wideTree(state: *State, out: *Actions(OutEvent)) !void {
    for ([_]u8{ 3, 4, 5, 6, 7, 8, 9 }) |index| {
        try state.handle(.{ .neighbor_up = try testNodeId(index) }, 0, out);
    }
    try state.addLazy(try testNodeId(10));
}

fn broadcastOnce(alloc: std.mem.Allocator) !void {
    var state: State = .init(try testNodeId(1), .{});
    var warm: Actions(OutEvent) = .init(t.allocator);
    defer warm.deinit();
    try wideTree(&state, &warm);
    var out: Actions(OutEvent) = .init(alloc);
    defer out.deinit();
    try state.broadcast(sweep_payload, .swarm, 0, &out);
}

// `broadcast` is the other public door into a tree, and it publishes its
// dispatch timer *before* the payload sends — the reverse of the forward path
// above, so the latch rule is observable from both ends and neither case can
// stand in for the other.
test "a refused broadcast arms the timer it published and no other" {
    const id = MessageId.fromContent(sweep_payload);
    const children = try sortedIds(7, 3);

    const boundaries = try boundariesOf(broadcastOnce, .{});
    try t.expect(boundaries > 1);

    for (0..boundaries) |refused| {
        var state: State = .init(try testNodeId(1), .{});
        var warm: Actions(OutEvent) = .init(t.allocator);
        defer warm.deinit();
        try wideTree(&state, &warm);
        var failing = t.FailingAllocator.init(t.allocator, .{
            .fail_index = refused,
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();

        const published: usize = blk: {
            var out: Actions(OutEvent) = .init(alloc);
            defer out.deinit();
            try t.expectError(
                error.OutOfMemory,
                state.broadcast(sweep_payload, .swarm, 0, &out),
            );
            // The timer is the first thing published, so a refusal at any
            // later boundary still shows it first, and nothing is published at
            // all when the very first append is the one refused.
            if (out.count() > 0) {
                try t.expect(out.at(0) == .schedule_timer);
                try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
                for (out.slice()[1..], 0..) |produced, index| {
                    try t.expect(produced == .send_message);
                    try t.expect(sameNode(produced.send_message.to, children[index]));
                    try t.expectEqualStrings(
                        sweep_payload,
                        produced.send_message.message.gossip.content,
                    );
                }
            }
            try t.expectEqual(@as(usize, 0), liveIn(OutEvent, &out, &failing));
            break :blk out.count();
        };

        // The latch says the caller holds the timer, and it is true exactly
        // when the append that publishes it made it into the list.
        try t.expectEqual(published > 0, state.dispatch_timer_scheduled);
        // The idle arm queues its ids before it queues the timer, so the queue
        // outlives a refusal of that timer — and it is the flush the caller
        // still has to be given.
        try t.expectEqual(@as(usize, 1), state.lazy_push_queue_len);
        // The payload is in the cache whatever the refusal did to the list, and
        // the entries published name it.
        try t.expectEqual(@as(usize, 1), state.cache.count());
        try t.expectEqualStrings(sweep_payload, state.cache.get(id).?.content);

        if (published > 0) {
            // The caller holds the timer it was given. Firing it is what
            // delivers the id the idle arm queued, and the latch is released
            // before the flush so nothing stands in for the timer the caller
            // just consumed.
            failing.fail_index = std.math.maxInt(usize);
            var flush: Actions(OutEvent) = .init(alloc);
            defer flush.deinit();
            try state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &flush);
            try t.expectEqual(@as(usize, 1), flush.count());
            try t.expect(sameNode(flush.at(0).send_message.to, try testNodeId(10)));
            const ihaves = flush.at(0).send_message.message.i_have.slice();
            try t.expectEqual(@as(usize, 1), ihaves.len);
            try t.expect(ihaves[0].id.eql(id));
            try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
            try t.expect(!state.dispatch_timer_scheduled);
        } else {
            // No timer was published, so the caller holds none to fire and
            // delivering one would be its own mistake. The next burst is what
            // arms it, and the id that was queued is still waiting for that
            // timer rather than lost with the refusal.
            failing.fail_index = std.math.maxInt(usize);
            var burst: Actions(OutEvent) = .init(alloc);
            defer burst.deinit();
            try state.broadcast(sweep_payload, .swarm, 0, &burst);
            try t.expect(burst.at(0) == .schedule_timer);
            try t.expect(burst.at(0).schedule_timer.timer == .dispatch_lazy_push);
            try t.expect(state.dispatch_timer_scheduled);
            try t.expectEqual(@as(usize, 1), state.lazy_push_queue_len);
            try t.expectEqual(@as(usize, 2), state.lazy_push_queue[0].count);
        }

        try t.expect(failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

// The `plumtree` names these tests spell out. The rest of the machine they read
// is reached through fields, and a field is public by construction.
const id_length = plumtree.id_length;
const max_content = plumtree.max_content;
const max_claims = plumtree.max_claims;
const Actions = plumtree.Actions;
const Round = plumtree.Round;
const MessageId = plumtree.MessageId;
const domainSeparatedId = plumtree.domainSeparatedId;
const Gossip = plumtree.Gossip;
const IHave = plumtree.IHave;
const IHaves = plumtree.IHaves;
const OutEvent = plumtree.OutEvent;
const InEvent = plumtree.InEvent;
const State = plumtree.State;
const Claim = plumtree.Claim;

/// `plumtree.sameNode` restated: the production copy is file-private, and a
/// test that used it would be checking that the module agrees with itself.
fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}