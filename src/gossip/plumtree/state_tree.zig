//! `State` itself: the fields, the doors in, and the dispatch.
//!
//! Everything else in the tree is here or in a file beside this one: the
//! payload paths (`state_push.zig`), the control messages and the optimisation
//! they drive (`state_control.zig`), and the table of messages this node is
//! missing with the claims on them (`state_missing.zig`). They are free
//! functions on `*State` rather than methods, because Zig makes a struct one
//! declaration and cannot reopen one from another file; the four that a caller
//! names — `optimizeTree`, `lazyPush`, `pushClaim` and `takeMissing` — stay
//! methods here so `topic.zig` and the tests keep calling them the way they
//! always have.
const std = @import("std");
const key = @import("../../base/key.zig");
const actions = @import("actions.zig");
const claim_table = @import("claim_table.zig");
const settings = @import("config.zig");
const ids = @import("id_cache.zig");
const limits = @import("limits.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const payloads = @import("message_cache.zig");
const peers = @import("peer_set.zig");
const missing = @import("state_missing.zig");
const control = @import("state_control.zig");
const push = @import("state_push.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = actions.Actions;
const Claim = claim_table.Claim;
const MissingEntry = claim_table.MissingEntry;
const Config = settings.Config;
const Stats = settings.Stats;
const IdCache = ids.IdCache;
const MessageCache = payloads.MessageCache;
const MessageId = message_id.MessageId;
const Error = limits.Error;
const Nanos = limits.Nanos;
const cache_slots = limits.cache_slots;
const max_claims = limits.max_claims;
const max_content = limits.max_content;
const max_missing = limits.max_missing;
const max_peers = limits.max_peers;
const max_queue_peers = limits.max_queue_peers;
const max_queued_ihaves = limits.max_queued_ihaves;
const max_received_ids = limits.max_received_ids;
const PeerSet = peers.PeerSet;
const DeliveryScope = wire.DeliveryScope;
const Gossip = wire.Gossip;
const IHave = wire.IHave;
const Message = wire.Message;
const Round = wire.Round;
const Scope = wire.Scope;
const Timer = wire.Timer;
const InEvent = wire.InEvent;
const OutEvent = wire.OutEvent;
const deliveryScope = wire.deliveryScope;

/// The lazy-push queue: `IHave`s waiting for the dispatch timer, per peer.
const QueueEntry = struct {
    peer: NodeId,
    count: u16,
    items: [max_queued_ihaves]IHave,
};

/// The state of one node's broadcast tree for one topic. Upstream
/// `plumtree::State`.
///
/// It knows nothing about membership: the active view arrives as
/// `neighbor_up` and `neighbor_down`, and everything else is the tree's own
/// bookkeeping.
pub const State = struct {
    /// This node's identity, fixed by `init`. It is the one peer the tree never
    /// forwards to: `eagerPush` skips any peer equal to it, and `lazyPush`
    /// queues against it, so writing it after `init` changes which peers a
    /// broadcast reaches and which queued `IHave`s are suppressed. Zig fields
    /// are not private — this one is fixed by convention and by `init`, not by
    /// the language.
    me: NodeId,
    /// Retention, timeout and round settings, fixed by `init` and not
    /// re-validated afterwards. It is read per event — every cache write,
    /// every timer arming and every tree optimisation — so writing it after
    /// `init` changes the behaviour of entries that were written under the
    /// old values; nothing rewrites them.
    config: Config,

    /// Peers that get whole payloads. The eager edges are the iTree.
    eager_push_peers: PeerSet(max_peers) = .{},
    /// Peers that get ids only, after a delay.
    lazy_push_peers: PeerSet(max_peers) = .{},

    lazy_push_queue: [max_queue_peers]QueueEntry = undefined,
    lazy_push_queue_len: usize = 0,
    /// Whether a `DispatchLazyPush` is outstanding. Latched, so a burst of
    /// broadcasts batches into one timer rather than one timer per message.
    dispatch_timer_scheduled: bool = false,

    missing_messages: [max_missing]MissingEntry = undefined,
    missing_messages_len: usize = 0,

    received_messages: IdCache(max_received_ids) = .{},
    cache: MessageCache(cache_slots) = .{},

    /// Whether the entry sweep has been queued. The sweep is scheduled once,
    /// on entry, exactly as upstream does it in `handle`. Named `started`
    /// rather than `init` because the constructor is `init`.
    ///
    /// It is set only after the append that publishes that sweep, so a refusal
    /// leaves the state wanting one: the next event queues it. It is a claim
    /// about a timer the caller holds, and `handle` never makes it true about a
    /// timer nobody received.
    started: bool = false,

    /// Whether `leave` has run. A state that has left holds no tree and answers
    /// nothing, and this is the latch that says so rather than the emptiness of
    /// the fields themselves. Both doors into the tree read it — `handle` and
    /// `broadcast` — so a caller holding this value cannot reach past it.
    left: bool = false,

    /// How many hops and payloads this tree has seen. Counters about what the
    /// node did while it was on the topic, not protocol state: they survive
    /// `leave`, so a caller can report what happened before it left.
    ///
    /// `payload_messages_received` counts every received `Gossip` *before* the
    /// arm is chosen, so a spoofed frame is counted as received and then
    /// discarded. That is a receive counter and not a delivery counter, and the
    /// test that a spoofed message is not penalised asserts on everything
    /// except it.
    stats: Stats = .{},

    /// A tree with no edges, no queue and no cache, for `me` under `config`.
    ///
    /// Infallible and allocation-free: `Config` is six durations and one round
    /// threshold rather than something to validate, and every bound in this
    /// module is a compile-time constant, so there is nothing here that can be
    /// refused. Nothing is scheduled until the first `handle`.
    ///
    /// Copyable: `State` holds no slice of its own storage, so a snapshot the
    /// caller restores after a failed `handle` is a plain copy. See `handle`.
    pub fn init(me: NodeId, config: Config) State {
        return .{ .me = me, .config = config };
    }

    /// The eager edges, in sorted order: the peers a new payload is pushed to.
    ///
    /// Pointer receiver and a borrowed slice, so the result lives as long as
    /// this state and no longer; the next `handle` can remove an edge, and
    /// `leave` empties the set. Read it, do not keep it.
    pub fn eagerPeers(self: *const State) []const NodeId {
        return self.eager_push_peers.slice();
    }

    /// The lazy edges, in sorted order: the peers an id is announced to, after
    /// the dispatch timer. Same borrow rule as `eagerPeers`, and the two sets
    /// are disjoint by construction: a peer is in exactly one of them.
    pub fn lazyPeers(self: *const State) []const NodeId {
        return self.lazy_push_peers.slice();
    }

    /// Forget the topic: drop every peer, queue, claim and cache entry, and
    /// leave the state ready to answer nothing.
    ///
    /// `hyparview.TopicState` calls this when the application sends
    /// `Command.quit`, and the promise it is keeping is the one on that
    /// command — a node that has left does not keep a broadcast tree, a lazy
    /// queue or a payload cache that a later event could still reach. Dropping
    /// them here rather than clearing them lazily is what makes "left" a fact
    /// about the state and not about the caller's bookkeeping.
    ///
    /// **Idempotent, and it produces no output.** The disconnects a leaving
    /// node owes its neighbours are membership's to send, and this half has
    /// none: by the time a `Quit` reaches this layer, membership has already
    /// dropped the neighbours whose trees these were.
    ///
    /// `stats` survives, because a counter is a report about what the node did
    /// while it was on the topic rather than state it was carrying. `me` and
    /// `config` survive because they identify the state and not its contents.
    /// `started` survives as the first-event latch. The caller owns scheduled
    /// timers and may discard them; late events cannot restart cache eviction.
    pub fn leave(self: *State) void {
        self.eager_push_peers.clear();
        self.lazy_push_peers.clear();
        self.lazy_push_queue_len = 0;
        self.dispatch_timer_scheduled = false;
        self.missing_messages_len = 0;
        self.received_messages.clear();
        self.cache.clear();
        self.left = true;
    }

    /// Handle one event. `now` is the caller's clock; nothing here reads one.
    ///
    /// **Not transactional, and the residue is named rather than hidden.** An
    /// event advances `self` and appends to `out` as it goes, so an
    /// `error.OutOfMemory` out of an append leaves the state advanced as far as
    /// that event got and leaves the appends that succeeded in `out`. The state
    /// is still a valid `State` — every mutation here is checked, so nothing is
    /// left half-written — but it is not the state the caller handed in.
    ///
    /// Three ways out, and only the first is a promise:
    ///
    /// - **Snapshot.** `State` is a plain value holding no slice of its own
    ///   storage, so a caller that needs all-or-nothing copies it before the
    ///   call and restores that copy on error. The copy is `@sizeOf(State)`
    ///   bytes and no allocation, and it is not small: the payload cache, the
    ///   lazy-push queue, the claim table and the id table are all inline, so
    ///   what dominates it is `max_content * cache_slots` and
    ///   `max_queue_peers * max_queued_ihaves`. A caller sizing a stack or
    ///   arena slot measures `@sizeOf(State)` on its own target rather than
    ///   assuming. It is per-event work — a copy taken and dropped around every
    ///   message is a `@sizeOf(State)` memcpy on the hot path — so a caller
    ///   that keeps one keeps it per topic, outside the event loop. Three
    ///   things bound what the restore recovers, and all three are the caller's
    ///   to arrange:
    ///
    ///   1. **It recovers `self` and nothing else.** Every protocol function in
    ///      this module writes no memory outside `self` and `out` — the caches,
    ///      the queues and the claim table are all inline in `State` — so the
    ///      borrowed payload bytes a failed call handed to `out` *are* restored
    ///      with the value. What is not restored is anything the caller did with
    ///      them: a caller that acts on `out` as it drains it has already sent
    ///      what it read, and a restored state does not unsend it.
    ///   2. **It recovers `out` only if `out` was empty when the call started.**
    ///      That is the precondition, and `out.clear()` is then exactly the undo
    ///      because there is nothing else in the list. `Actions` has no
    ///      truncate-to-a-saved-length, so a caller that accumulates output
    ///      across events cannot use this recovery at all and must abandon.
    ///   3. **It does not restore the caller's timers.** This state owns no
    ///      timer queue — the caller's `out` names the timers it must run — so
    ///      a `.timer_expired` event is delivered *because* the caller took
    ///      that timer out of its queue to fire it. A restored copy therefore
    ///      carries whatever latch that timer had set, with no timer behind it:
    ///      `dispatch_timer_scheduled`, or an entry's
    ///      `graft_timer_scheduled`. A caller that restores a copy taken
    ///      before a timer event must re-queue the timer it consumed, or leave
    ///      that latch clear.
    ///
    /// - **Abandon.** A caller that cannot snapshot — because it accumulates
    ///   output, or because it has no copy to keep — treats a failed `handle` as
    ///   the end of this topic's run: drop the state, tell the transport to
    ///   close whatever it has open, and build a new `State` if the node comes
    ///   back. `node.zig`'s `feedGossip` makes the same choice with the same
    ///   `errdefer`: it keeps no copy, and a refused event unwinds the node.
    /// - **Replay**, which is *not* promised. Re-sending the same event does not
    ///   undo the neighbour already promoted, the payload already cached or the
    ///   `IHave` already queued, and making it would put a second opinion about
    ///   the protocol on the path of every event.
    ///
    /// Whatever is already in `out` is real work the state did, and whether to
    /// act on it, clear it or snapshot over it is the caller's choice.
    ///
    /// **What the entries in `out` borrow.** `Actions` owns the list and not the
    /// bytes its entries name: a `send_message` payload and an `emit_event`
    /// payload borrow either the caller's own buffer or `self.cache`, and the
    /// next `handle` on this state sweeps that cache and may evict the very
    /// entry being forwarded. A caller that keeps an output list across a
    /// `handle` copies the bytes.
    ///
    /// **The arms below run in this order, and the order is the contract.**
    /// Within `onGossip` the arms are: validate, then either the duplicate
    /// branch or the forward branch, and inside the forward branch the order
    /// is remember the id, cache the payload, push to eager peers, queue ids
    /// for lazy peers, drop the graft timer, run the tree optimisation, and
    /// only then tell the application. Reordering those changes what a caller
    /// observes: the `Graft` and `Prune` of an optimisation go out *before* the
    /// `Received` event, so a driver that has not been told the message
    /// arrived still sees the tree move under it. It is also why the
    /// `schedule_timer` for the dispatch flush appears once for a burst rather
    /// than once per message, because the flag is latched. The entry sweep is
    /// the same rule at the front of the function: it is queued before
    /// `started` is set, so a refusal costs one sweep and not all of them. A
    /// reader who finds the sequence untidy should not sort it.
    pub fn handle(
        self: *State,
        event: InEvent,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        // A state that has left answers nothing. `Command.quit` says the node
        // is done with this topic, and an event that arrives after it is a
        // driver that has not stopped feeding; there is nothing to do and no
        // error to hand back for doing nothing.
        if (self.left) return;
        if (!self.started) {
            // Queued before the latch is set, for the reason `onIHave` gives.
            // A refused append is the one event that would leave this tree
            // without its entry sweep for ever: nothing else queues an
            // `evict_cache`, and the latch set first would say one was
            // outstanding while the caller holds none.
            try onEvictCacheTimer(self, now, out);
            self.started = true;
        }
        switch (event) {
            .recv_message => |recv| try self.handleMessage(recv.from, recv.message, now, out),
            .broadcast => |b| try self.broadcast(b.content, b.scope, now, out),
            .timer_expired => |timer| try self.handleTimer(timer, now, out),
            .neighbor_up => |peer| try push.addEager(self, peer),
            .neighbor_down => |peer| control.onNeighborDown(self, peer),
        }
    }

    fn handleTimer(
        self: *State,
        timer: Timer,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        switch (timer) {
            .dispatch_lazy_push => try push.onDispatchTimer(self, out),
            .send_graft => |id| try control.onSendGraftTimer(self, id, out),
            .evict_cache => try onEvictCacheTimer(self, now, out),
        }
    }

    /// Upstream `handle_message`. The payload counter moves before the arm is
    /// chosen, so a spoofed frame is counted and then dropped; see the module
    /// doc.
    fn handleMessage(
        self: *State,
        from: NodeId,
        message: Message,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        switch (message) {
            .gossip => |gossip| {
                self.stats.payload_messages_received += 1;
                try push.onGossip(self, from, gossip, now, out);
            },
            .prune => {
                self.stats.control_messages_received += 1;
                control.onPrune(self, from);
            },
            .i_have => |ihaves| {
                self.stats.control_messages_received += 1;
                try control.onIHave(self, from, ihaves.slice(), out);
            },
            .graft => |graft| {
                self.stats.control_messages_received += 1;
                try control.onGraft(self, from, graft, out);
            },
        }
    }

    /// Upstream `broadcast`.
    ///
    /// The payload goes to the eager peers now and the ids to the lazy peers
    /// after `dispatch_timeout`, and that split is the point: a lazy peer that
    /// shares a path with an eager one should get the payload from the eager
    /// peer first and only ask for it if that fails.
    ///
    /// **Inert on a state that has left**, exactly as `handle` is: it returns
    /// before it touches a cache, a queue or the dispatch latch, so the direct
    /// route into a tree `leave` emptied cannot refill it. A caller that
    /// broadcasts after a `Command.quit` gets silence, not a fresh tree —
    /// and silence means it appends nothing: the events the caller is already
    /// holding stay the caller's, because neither `leave` nor this call
    /// reaches into the list to take them back.
    pub fn broadcast(
        self: *State,
        content: []const u8,
        scope: Scope,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.left) return;
        if (content.len > max_content) return error.MessageTooLarge;
        const id = MessageId.fromContent(content);
        const message: Gossip = .{
            .id = id,
            .content = content,
            .scope = deliveryScope(scope),
        };
        if (isSwarm(message.scope)) {
            self.received_messages.put(id, now + self.config.message_id_retention);
            try self.cache.put(message, now + self.config.message_cache_retention);
            try push.lazyPush(self, message, self.me, out);
        }
        try push.eagerPush(self, message, self.me, out);
    }

    /// Upstream `on_evict_cache_timer`. The sweep of the two caches, and the
    /// timer that runs it; it lives with the fields it expires.
    fn onEvictCacheTimer(
        self: *State,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        self.cache.expireUntil(now);
        self.received_messages.expireUntil(now);
        try out.push(.{ .schedule_timer = .{
            .after = self.config.cache_evict_interval,
            .timer = .evict_cache,
        } });
    }

    /// Upstream `optimize_tree`, in `state_control.zig`. Kept as a method
    /// because `topic.zig` and the tests name it as one.
    pub fn optimizeTree(
        self: *State,
        gossip_sender: NodeId,
        round: Round,
        claims: []const Claim,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        return control.optimizeTree(self, gossip_sender, round, claims, out);
    }

    /// Upstream `lazy_push`, in `state_push.zig`. Kept as a method because the
    /// tests name it as one.
    pub fn lazyPush(
        self: *State,
        gossip: Gossip,
        sender: NodeId,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        return push.lazyPush(self, gossip, sender, out);
    }

    /// Upstream `add_eager`, in `state_push.zig`. Kept as a method because the
    /// tests name it as one.
    pub fn addEager(self: *State, peer: NodeId) Error!void {
        return push.addEager(self, peer);
    }

    /// Upstream `add_lazy`, in `state_push.zig`. Kept as a method because the
    /// tests name it as one.
    pub fn addLazy(self: *State, peer: NodeId) Error!void {
        return push.addLazy(self, peer);
    }

    /// The entry the claim landed in, in `state_missing.zig`. Kept as a method
    /// because the tests name it as one.
    pub fn pushClaim(self: *State, id: MessageId, claim: Claim) Error!*MissingEntry {
        return missing.pushClaim(self, id, claim);
    }

    /// Drain one id's claims into the caller's buffer, in `state_missing.zig`.
    /// Kept as a method because the tests name it as one.
    pub fn takeMissing(self: *State, id: MessageId, storage: *[max_claims]Claim) ?[]const Claim {
        return missing.takeMissing(self, id, storage);
    }
};

fn isSwarm(scope: DeliveryScope) bool {
    return switch (scope) {
        .swarm => true,
        .neighbors => false,
    };
}