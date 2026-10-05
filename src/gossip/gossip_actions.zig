//! A decoded message and the state this node is in, answered with an action
//! list. This is `AGENTS.md` §2's rule in one file: a state machine takes a
//! decoded message and a state value and returns a new state plus an action
//! list, and nothing in the decision touches the network.
//!
//! **It is not a second membership machine.** `hyparview/state_arms.zig` owns
//! every protocol decision — the views, the walk, the `Neighbor` deviation —
//! and this file decides none of them. It answers the two questions the *node*
//! asks before it will run that machine at all, and both are questions about
//! **this node** rather than about the swarm:
//!
//! 1. **Is the topic on this frame one this node is in?** A node holds up to
//!    `topic_policy.max_topics` topics and `hyparview/topic.zig` holds one
//!    `TopicState` for each; nothing anywhere maps a frame's topic onto the
//!    state that should take it, because upstream never had to — upstream runs
//!    one topic per actor. A frame for a topic this node is not in has no state
//!    to go to, so `decide` refuses it.
//! 2. **Can this node reach the peer the frame names?** The node's connection
//!    directory (`node/conn_index.zig`) is node-wide, and the topic's own
//!    contact table is per-topic and arrives later than the frame.
//!
//! # Purity, and what it costs to keep
//!
//! No socket, no clock, no allocator, no global. `decide` takes the state by a
//! `*const` pointer and the frame by a `*const` pointer and returns a value:
//! there is no I/O to thread and nothing to fail but the caller's own send.
//! **There is no `now` in `Frame`,** unlike `TopicState.handle`'s signature,
//! because a question about which topics this node is in has no time component
//! and a signature that carried a clock would invite one.
//!
//! The frame is a pointer rather than a value because `hyparview.Message` is
//! about a kilobyte — a `Shuffle` carries eight `PeerInfo` and an `IHave`
//! carries sixteen `MessageId`s — and this runs on every received frame.
//!
//! **The actions borrow the caller's buffer.** A `peer_data` entry's `data`
//! names the bytes the decoded frame carried, exactly as every `peer_data`
//! `State.handle` emits does (`state_machine.zig`'s `handle` doc names the
//! three places those bytes live). A caller that keeps an action list across
//! the next decode must copy; the caller owns the buffer and this file only
//! ever reads it.
//!
//! # The bound, and why it is one entry
//!
//! **`max_actions` is 1, and it is 1 because one frame names one peer this
//! node must be able to reach.** A `Join` and a `Neighbor` speak for their
//! sender; a `ForwardJoin` speaks for the peer it introduces; and that is the
//! whole list, because a `Shuffle`'s and a `ShuffleReply`'s nodes belong to
//! the topic's own table — `state_shuffle.zig` feeds every one of them to
//! `addPassive`, which already reports them — and a `Disconnect` carries
//! nothing to dial. So the node-level list is a constant. It is not a
//! function of the mesh, of the topic count, or of the active view.
//!
//! **That is the whole point, and the reason it is worth a separate type from
//! `hyparview.Actions`.** The list that *does* grow with the mesh is the topic
//! state machine's own: `onJoin` sends a `forward_join` to every peer in the
//! active view, and `plumtree.Actions` grows to hold them. That list has an
//! allocator in it for exactly that reason. This one is inline storage on the
//! stack, so a node cannot be made to allocate by a busy topic on this path —
//! and a node-level list that grew with the mesh would be a second copy of the
//! topic's own accounting, answering for peers the topic machine has not
//! decided about yet.
//!
//! **There is no `push`, so there is no overflow to handle.** The bound is a
//! property of the type rather than a check at run time: `decide` fills the one
//! slot or fills none, and a bound nothing can reach needs no error and has
//! none. `count()` and `slice()` are the only doors onto it.
//!
//! **The vocabulary is `hyparview.OutEvent` itself**, re-exported here as
//! `Action` and not restated. A second action type with the same five arms and
//! different names is a second dialect, and a caller holding both would have to
//! translate; this file produces the topic-level `OutEvent` a caller can hand
//! straight to the same loop that drains `TopicState.handle`'s output.
//!
//! **Nothing here has been checked against bytes from the reference, so no
//! interoperability claim is made.** What is pinned is that a node refusing a
//! frame names no action and answers nothing — a local property with no wire in
//! it at all, which is the only kind this file can honestly assert.

const std = @import("std");
const gossip = @import("hyparview.zig");
const plumtree = @import("plumtree.zig");
const topic_policy = @import("topic_policy.zig");

const NodeId = gossip.NodeId;
const TopicId = gossip.TopicId;
const TopicPolicy = topic_policy.TopicPolicy;

/// The most actions one frame can justify. See the module doc: one, because one
/// frame names one peer this node must be able to reach.
///
/// **A bound declared, not a capacity chosen for the caller.** A node-level
/// decision is a function of the frame and of which topics this node is in, and
/// neither is a function of the mesh; a number here that grew with the active
/// view would be a second copy of `hyparview/state_arms.zig`'s accounting.
pub const max_actions = 1;

/// What this node asks the outside world to do about one frame.
///
/// **`hyparview.OutEvent` and not a type of its own**, re-exported under the
/// name the module uses. The arms are `send_message`, `schedule_timer`,
/// `disconnect_peer`, `emit_event` and `peer_data`, and only `peer_data` is
/// ever produced here — the other four are the topic state machine's, and
/// restating them would invite a caller to look for actions this file decides
/// nothing about.
pub const Action = gossip.OutEvent;

/// Whether the frame was routed or refused.
///
/// **Two answers, because there is one question.** The topic machine's own
/// outcomes are errors out of `TopicState.handle` and there are seven of them
/// (`gossip/hyparview/bounds.zig`); none of them is about whether this node is
/// in the topic at all, which is the question this file answers and the reason
/// it exists.
pub const Outcome = enum {
    /// This node is in the topic and the frame is the topic state machine's.
    route,
    /// This node is not in the topic. The frame is dropped and nothing is sent,
    /// recorded or emitted.
    ///
    /// **Silently.** A frame naming a topic this node never admitted is not a
    /// question about the swarm and gets no answer, for the reason a re-validated
    /// `Gossip` is dropped without a `Prune`: `plumtree.zig` says a path that
    /// also punished "is a different protocol, and a peer that wanted to empty
    /// a victim's iTree would send one bad frame per neighbour". A peer that
    /// named a topic it was never given is the same shape of abuse.
    refuse,
};

/// A frame as it came off the wire: the topic its stream carries, the peer it
/// came from, and the decoded body.
///
/// The topic is here rather than inside the message because that is where the
/// bytes are: `gossip/codec/frame.zig` writes it once per stream in
/// `StreamHeader` and no arm of `SwarmMessage` carries one.
pub const Frame = struct {
    /// The swarm every message on this stream belongs to.
    topic: TopicId,
    /// The peer this frame came from.
    from: NodeId,
    /// The decoded body, layer tag included.
    message: gossip.Message,
};

/// The node-level action list, and the bound on it.
///
/// **It owns the list and not the bytes its entries name.** A `peer_data`
/// action's `data` borrows the caller's decoded buffer; see the module doc.
pub const Actions = struct {
    /// The actions. Only `[0..len]` is ever read, so the slot past `len` is
    /// `undefined` rather than empty: nothing walks past `len` to find it.
    items: [max_actions]Action = undefined,
    /// How many of `items` are in use, never a capacity.
    len: usize = 0,

    /// How many actions this frame justified.
    pub fn count(self: *const Actions) usize {
        return self.len;
    }

    /// The actions, borrowed. Pointer receiver for the reason
    /// `plumtree.IHaves.slice` takes one: a by-value receiver can hand back a
    /// slice into a temporary that dies the moment it returns.
    pub fn slice(self: *const Actions) []const Action {
        return self.items[0..self.len];
    }
};

/// The peer a frame asks this node to be able to reach, and the bytes that say
/// how. `data` borrows the caller's decoded buffer.
pub const Dial = struct {
    /// The peer, which is the frame's sender except for a `ForwardJoin`, where
    /// it is the peer being introduced and the sender is only the messenger.
    peer: NodeId,
    /// The contact bytes, never empty — `null` and a zero-length `PeerData` are
    /// the same answer on the wire (`State.myData`), so there is nothing to
    /// dial from.
    data: []const u8,
};

/// What one frame came to. `outcome` says where it went; `actions` says what
/// this node has to do about the peer it names, which is at most one entry and
/// is usually none.
pub const Disposal = struct {
    outcome: Outcome,
    actions: Actions,
};

/// Decide what one decoded frame is, and what it asks of this node.
///
/// Pure over `state` and `frame`: it reads both and returns a value. The state
/// is not advanced, and there is nothing to roll back — a decision that cannot
/// fail and does not mutate has no residue to name, which is the difference
/// from `TopicState.handle` and the reason this file is not a wrapper for it.
///
/// A `route` outcome means the caller hands the frame to the `TopicState` for
/// `frame.topic`. A `refuse` outcome means it does not, and that this node
/// sends nothing, records nothing and emits nothing about the frame — including
/// nothing about the peer that sent it, which is why a peer in a topic this
/// node *is* in keeps its connection when a frame arrives on a topic it is not.
pub fn decide(state: *const TopicPolicy, frame: *const Frame) Disposal {
    var disposal: Disposal = .{ .outcome = .refuse, .actions = .{} };
    if (!state.holds(frame.topic)) return disposal;
    disposal.outcome = .route;
    const dial = dialTarget(frame) orelse return disposal;
    disposal.actions.items[0] = .{ .peer_data = .{ .peer = dial.peer, .data = dial.data } };
    disposal.actions.len = 1;
    return disposal;
}

/// The peer this frame asks the node to be able to reach, or null for a frame
/// that names none.
///
/// **The arms that speak for a peer**, and not the others. `join` and
/// `neighbor` carry the sender's own bytes; `forward_join` carries the bytes of
/// the peer being introduced, which is the one a node cannot do without — the
/// forwarding arm of `onForwardJoin` inserts nobody and reports nobody, so a
/// node that waited for its topic's own `peer_data` would hear about a
/// forwarded peer only once the walk came back or its TTL expired. The two
/// `Shuffle` arms carry a list, and every peer in it belongs to the topic's
/// table: `onShuffle` and `onShuffleReply` feed all of them to `addPassive`,
/// which reports each one already. A `disconnect` carries nothing at all.
fn dialTarget(frame: *const Frame) ?Dial {
    switch (frame.message) {
        .swarm => |message| switch (message) {
            .join => |data| return contact(frame.from, data),
            .neighbor => |details| return contact(frame.from, details.data),
            .forward_join => |details| return contact(details.peer.id, details.peer.data),
            .shuffle, .shuffle_reply, .disconnect => {},
        },
        .gossip => {},
    }
    return null;
}

/// One frame's contact bytes for one peer, or null for the two answers that
/// mean "nothing to dial from".
fn contact(peer: NodeId, data: ?[]const u8) ?Dial {
    const bytes = data orelse return null;
    if (bytes.len == 0) return null;
    return .{ .peer = peer, .data = bytes };
}

// --- tests

const t = std.testing;
const test_node_id = @import("plumtree/test_node_id.zig");
const PeerData = gossip.PeerData;

const Message = gossip.Message;
const SwarmMessage = gossip.SwarmMessage;

/// A topic named by one byte. A `TopicId` is 32 bytes an application chose and
/// every one of them is as good as any other, so the bytes only have to differ.
fn testTopic(tag: u8) TopicId {
    var bytes = [_]u8{0} ** gossip.topic_id_length;
    bytes[0] = tag;
    return TopicId.fromBytes(bytes);
}

/// A policy in one topic, which is what a node that has joined one swarm looks
/// like.
fn joinedPolicy(topic: TopicId) !TopicPolicy {
    var policy = TopicPolicy.init();
    _ = try policy.admit(topic, null, .{ .count = 0, .items = undefined });
    return policy;
}

/// One message of every arm, each carrying `bytes` where the arm has a place to
/// carry them and nothing where it does not: all six membership arms and all
/// four broadcast arms.
fn everyArm(bytes: []const u8) ![10]Message {
    return .{
        .{ .swarm = .{ .join = bytes } },
        .{ .swarm = .{ .neighbor = .{ .priority = .high, .data = bytes } } },
        .{ .swarm = .{ .forward_join = .{
            .peer = .{ .id = try test_node_id.testNodeId(90), .data = bytes },
            .ttl = .{ .value = 3 },
        } } },
        .{ .swarm = .{ .shuffle = .{
            .origin = try test_node_id.testNodeId(91),
            .nodes = .{ .count = 0, .items = undefined },
            .ttl = .{ .value = 3 },
        } } },
        .{ .swarm = .{ .shuffle_reply = .{
            .nodes = .{ .count = 0, .items = undefined },
        } } },
        .{ .swarm = .{ .disconnect = .{ .alive = true } } },
        .{ .gossip = .{ .gossip = .{
            .id = plumtree.MessageId.fromContent(bytes),
            .content = bytes,
            .scope = .{ .swarm = plumtree.Round.zero },
        } } },
        .{ .gossip = .prune },
        .{ .gossip = .{ .graft = .{ .id = null, .round = plumtree.Round.zero } } },
        .{ .gossip = .{ .i_have = try plumtree.IHaves.init(&[_]plumtree.IHave{}) } },
    };
}

test "a frame for a topic this node is not in is refused and asks for nothing" {
    const policy = TopicPolicy.init();
    const peer = try test_node_id.testNodeId(1);
    const elsewhere = testTopic(9);
    const frame: Frame = .{
        .topic = elsewhere,
        .from = peer,
        .message = .{ .swarm = .{ .join = "bytes" } },
    };

    const disposal = decide(&policy, &frame);
    try t.expectEqual(Outcome.refuse, disposal.outcome);
    // Zero actions, and not one of them a `disconnect_peer`: a peer that named
    // a topic this node is not in keeps whatever connection it had, because the
    // node-level list has no way to say otherwise and a refusal that punished
    // would be a peer naming its way to disconnection.
    try t.expectEqual(@as(usize, 0), disposal.actions.count());
    try t.expectEqual(@as(usize, 0), disposal.actions.slice().len);

    // And the peer that sent it is untouched by the refusal: the policy says
    // nothing about peers, so the caller has nothing to act on either.
    try t.expectEqual(@as(usize, 0), policy.count());
}

test "a peer that is in one topic keeps its connection when a frame names another" {
    const room = testTopic(1);
    const policy = try joinedPolicy(room);
    const peer = try test_node_id.testNodeId(2);
    const frame: Frame = .{
        .topic = testTopic(2),
        .from = peer,
        .message = .{ .swarm = .{ .disconnect = .{ .alive = false } } },
    };

    try t.expectEqual(Outcome.refuse, decide(&policy, &frame).outcome);
    // The topic the node *is* in is untouched by the refusal, which is the
    // difference between refusing a frame and refusing a peer: two topics may
    // share a peer, and a frame on one of them says nothing about the other.
    try t.expect(policy.holds(room));
    try t.expectEqual(@as(usize, 1), policy.count());
}

test "a join that carries contact data asks for its sender to be dialled" {
    const room = testTopic(1);
    const policy = try joinedPolicy(room);
    const peer = try test_node_id.testNodeId(3);
    const frame: Frame = .{
        .topic = room,
        .from = peer,
        .message = .{ .swarm = .{ .join = "alpha" } },
    };

    const disposal = decide(&policy, &frame);
    try t.expectEqual(Outcome.route, disposal.outcome);
    try t.expectEqual(@as(usize, 1), disposal.actions.count());
    // The action is `peer_data` and names the peer the frame came from with the
    // bytes that came with it: the node-level instruction is "be able to reach
    // this one", and it is the protocol's own arm rather than a new one.
    switch (disposal.actions.slice()[0]) {
        .peer_data => |named| {
            try t.expect(peer.order(named.peer) == .eq);
            try t.expectEqualStrings("alpha", named.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "a forwarded join asks for the peer it introduces, not the one that sent it" {
    const room = testTopic(1);
    const policy = try joinedPolicy(room);
    const introducer = try test_node_id.testNodeId(4);
    const introduced = try test_node_id.testNodeId(5);
    const frame: Frame = .{
        .topic = room,
        .from = introducer,
        .message = .{ .swarm = .{ .forward_join = .{
            .peer = .{ .id = introduced, .data = "beta" },
            .ttl = .{ .value = 3 },
        } } },
    };

    const asked = decide(&policy, &frame).actions.slice()[0];
    // The messenger is a peer this node already has; the peer being introduced
    // is one it has never heard of, and the forwarding arm of `onForwardJoin`
    // reports nobody, so this is the only place that peer is named before the
    // walk comes back.
    switch (asked) {
        .peer_data => |named| {
            try t.expect(introduced.order(named.peer) == .eq);
            try t.expectEqualStrings("beta", named.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "a frame with nothing to dial from asks for nothing" {
    const room = testTopic(1);
    const policy = try joinedPolicy(room);
    const peer = try test_node_id.testNodeId(6);

    // `null` and an empty slice are the same answer on the wire, so they are
    // the same answer here: a frame that advertises nothing leaves the node
    // with no address to dial and therefore no action.
    for ([_]?[]const u8{ null, "" }) |empty| {
        const neighbour: Frame = .{
            .topic = room,
            .from = peer,
            .message = .{ .swarm = .{ .neighbor = .{ .priority = .low, .data = empty } } },
        };
        const disposal = decide(&policy, &neighbour);
        try t.expectEqual(Outcome.route, disposal.outcome);
        try t.expectEqual(@as(usize, 0), disposal.actions.count());
    }

    // The arms that carry a peer list carry it for the topic's own table, and
    // the arm that carries nothing at all cannot ask for a dial. Both are
    // routed, and both ask for nothing.
    const departure: Frame = .{
        .topic = room,
        .from = peer,
        .message = .{ .swarm = .{ .disconnect = .{ .alive = true } } },
    };
    try t.expectEqual(Outcome.route, decide(&policy, &departure).outcome);
    try t.expectEqual(@as(usize, 0), decide(&policy, &departure).actions.count());
}

test "every arm of every message fits inside the declared bound" {
    const room = testTopic(1);
    const policy = try joinedPolicy(room);
    const peer = try test_node_id.testNodeId(7);
    // The bound is the answer to "how many actions can one frame ask for", so
    // it is pinned: a number that grew here would be a number a peer picks.
    try t.expectEqual(@as(usize, 1), max_actions);

    // Every arm of both layers, driven against a topic this node is in. None of
    // them can produce two actions, and that is the property the fixed array
    // exists to make unbreakable.
    for (try everyArm("bytes")) |message| {
        const frame: Frame = .{ .topic = room, .from = peer, .message = message };
        const disposal = decide(&policy, &frame);
        try t.expectEqual(Outcome.route, disposal.outcome);
        try t.expect(disposal.actions.count() <= max_actions);
    }

    // The list is the whole of what this path produces: at most one, and the
    // only arm it can carry is `peer_data`. A second action kind would be a
    // decision this file has not been given the state to make.
    try t.expectEqual(@as(usize, 1), policy.count());
    var kinds: usize = 0;
    for (try everyArm("bytes")) |message| {
        const frame: Frame = .{ .topic = room, .from = peer, .message = message };
        for (decide(&policy, &frame).actions.slice()) |action| {
            kinds += @intFromBool(action == .peer_data);
        }
    }
    try t.expectEqual(@as(usize, 3), kinds);
}

test "deciding twice leaves the policy exactly as it was" {
    const room = testTopic(1);
    const policy0 = try joinedPolicy(room);
    const peer = try test_node_id.testNodeId(8);
    const frame: Frame = .{
        .topic = room,
        .from = peer,
        .message = .{ .swarm = .{ .join = "gamma" } },
    };

    // The decision is a function of the state and the frame, and it advances
    // neither: the same frame on the same policy answers the same way twice,
    // and a refusal for a topic the node is not in cannot have left a trace to
    // notice either.
    const first = decide(&policy0, &frame);
    const second = decide(&policy0, &frame);
    try t.expectEqual(@as(usize, 1), first.actions.count());
    try t.expectEqual(@as(usize, 1), second.actions.count());
    switch (first.actions.slice()[0]) {
        .peer_data => |named| {
            try t.expect(peer.order(named.peer) == .eq);
            try t.expectEqualStrings("gamma", named.data);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (second.actions.slice()[0]) {
        .peer_data => |named| {
            try t.expect(peer.order(named.peer) == .eq);
            try t.expectEqualStrings("gamma", named.data);
        },
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 1), policy0.count());
    try t.expect(policy0.holds(room));
    try t.expectEqual(@as(?[]const u8, null), policy0.advertised(room));

    // The advertised bytes this node tells a topic are exactly the ones it was
    // admitted with: a received frame never rewrites what this node says.
    var other = try joinedPolicy(room);
    _ = try other.admit(testTopic(2), try PeerData.fromBytes("delta"), .{
        .count = 0,
        .items = undefined,
    });
    try t.expectEqualStrings("delta", other.advertised(testTopic(2)).?);
    try t.expectEqual(@as(usize, 2), other.count());
}

// Compile-time proof that the arms `everyArm` writes are the arms `dialTarget`
// and `TopicState.handle` agree on, so a second arm added upstream is a build
// error here rather than a frame that reaches a decision function that never
// looked at it.
comptime {
    const arms = @typeInfo(SwarmMessage).@"union".fields;
    const named = [_][]const u8{
        "join",
        "forward_join",
        "shuffle",
        "shuffle_reply",
        "neighbor",
        "disconnect",
    };
    if (arms.len != named.len) {
        @compileError("a membership arm was added or removed; this module decides on it");
    }
    for (named, 0..) |name, index| {
        if (!std.mem.eql(u8, arms[index].name, name)) {
            @compileError("a membership arm was reordered; this module decides on it");
        }
    }
}
