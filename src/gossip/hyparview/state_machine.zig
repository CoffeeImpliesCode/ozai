//! `State` itself: the fields, the doors in, and the contact table.
//!
//! Everything else in the machine is here or in a file beside this one: the
//! arms a received message takes (`state_arms.zig`), the random walk
//! (`state_shuffle.zig`), the two views (`state_views.zig`) and what happens
//! when a peer or this node goes away (`state_departure.zig`). They are free
//! functions on `*State` rather than methods, because Zig makes a struct one
//! declaration and cannot reopen one from another file; the order `handle`
//! calls the arms in is the order they are listed in its own doc, and nothing
//! here reorders it.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const entropy = @import("rng.zig");
const index_set = @import("index_set.zig");
const settings = @import("config.zig");
const arms = @import("state_arms.zig");
const departure = @import("state_departure.zig");
const shuffle = @import("state_shuffle.zig");
const views = @import("state_views.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const max_active = bounds.max_active;
const max_passive = bounds.max_passive;
const PeerData = peers.PeerData;
const PeerDataMap = peers.PeerDataMap;
const PeerInfo = peers.PeerInfo;
const SwarmInEvent = wire.SwarmInEvent;
const SwarmOutEvent = wire.SwarmOutEvent;
const Rng = entropy.Rng;
const IndexSet = index_set.IndexSet;
const Config = settings.Config;
const SwarmStats = settings.SwarmStats;

/// Why a peer left the active view. Upstream `RemovalReason`, with its
/// `DisconnectReceived { is_alive }` payload kept as the union's `bool`.
pub const RemovalReason = union(enum) {
    /// The connection closed without a `Disconnect`. The peer is dropped.
    connection_closed: void,
    /// A `Disconnect` arrived. The peer is kept if the sender is still alive.
    disconnect_received: bool,
    /// Dropped at random to make room. The peer is kept.
    random: void,
};

/// The membership state of one node. Upstream `hyparview::State`.
///
/// `active_view` is the set of peers this node believes it is connected to,
/// and — because of the `Neighbor` exchange — those peers hold the same
/// belief about it. That is what "the active view is bidirectional" means in
/// code: not a symmetric data structure, but two nodes that reach the same
/// view by each asking the other and waiting.
pub const State = struct {
    /// This node's identity, fixed by `init`. A `Join` naming it is refused and
    /// an active view holding it is impossible, so writing it after `init`
    /// changes which peers this node will connect to. Zig fields are not
    /// private — this one is fixed by convention and by `init`, not by the
    /// language.
    me: NodeId,
    /// This node's own contact data, fixed by `init`; `null` and an empty
    /// `PeerData` both mean *advertise nothing*, and `myData` sends no slice
    /// either way. The bytes are stored by value in this `PeerData` — a
    /// `PeerData.fromBytes` copied them on the way in — so the caller keeps no
    /// claim on them and need not keep its own copy alive.
    ///
    /// A `Neighbor`, `Join` or `Shuffle` this state sends borrows these bytes,
    /// so the one call that invalidates an `out` entry holding such a slice is
    /// the next `.update_peer_data` event: it writes this record in place. No
    /// other event touches it, and `left` keeps it.
    me_data: ?PeerData,
    /// Peers we are connected to. Insertion-ordered, as upstream's.
    active_view: IndexSet(max_active) = .{},
    /// Peers we know about and are not connected to.
    passive_view: IndexSet(max_passive) = .{},
    /// View capacities, shuffle and walk sizes and every timeout, fixed by
    /// `init`, which validates them once and does not validate them again. It
    /// is read per event — every view insertion, every timer arming and every
    /// shuffle — so writing it after `init` changes the behaviour of views
    /// that were already built under the old values; nothing rewrites them.
    config: Config,
    /// Whether the shuffle timer is outstanding. Latched on the first call.
    shuffle_scheduled: bool = false,
    /// The caller's generator, carried as state so the whole module is a
    /// function of `(state, input)`.
    rng: Rng,
    stats: SwarmStats = .{},
    /// `Neighbor` messages we sent that have not been answered. This set *is*
    /// the deviation: a peer in it is one we have asked to be neighbours with
    /// and is not yet one.
    pending_neighbor_requests: IndexSet(max_active) = .{},
    peer_data: PeerDataMap = .{},
    /// Peers that disconnected while saying they were still alive, and so must
    /// survive the connection closing.
    alive_disconnect_peers: IndexSet(max_active) = .{},

    /// Whether this state has left the topic. Upstream drops the whole
    /// per-peer state on `Quit` and then ignores every later event for it, so
    /// a state that has quit answers nothing and produces nothing.
    ///
    /// Terminal, and there is no way back from here: rejoining means a new
    /// `State` from `init`. A join offered to a state that has quit would be
    /// answered by machinery whose passive view, claims and contact data no
    /// longer describe anything, which is the situation upstream avoids by
    /// dropping the actor rather than emptying it.
    left: bool = false,

    pub fn init(me: NodeId, me_data: ?PeerData, config: Config, rng: Rng) Error!State {
        try config.validate();
        return .{
            .me = me,
            .me_data = me_data,
            .config = config,
            .rng = rng,
        };
    }

    pub fn activeView(self: *const State) []const NodeId {
        return self.active_view.slice();
    }

    pub fn passiveView(self: *const State) []const NodeId {
        return self.passive_view.slice();
    }

    /// Handle one event.
    ///
    /// **A state that has quit is inert.** Upstream drops the per-peer state on
    /// `Quit` and ignores every later event for it; the `left` flag is how that
    /// is expressed here. An inert `handle` succeeds, appends nothing and
    /// changes nothing, so a driver that keeps feeding a node it has stopped
    /// driving gets silence rather than an error it cannot act on.
    ///
    /// The shuffle timer is armed on the first call whatever that call was,
    /// which is upstream's `handle`: the tail of the function, after the
    /// dispatch, not a constructor side effect. It matters because a node that
    /// only ever received messages still has to shuffle, and one that armed the
    /// timer in its constructor would arm it at a different moment in the run.
    /// It is *queued before the latch is set*, because a latch set first is a
    /// claim that a timer exists which the caller never received: an allocator
    /// refusing that one append would leave the node believing it had a shuffle
    /// scheduled, and no shuffle would ever happen again. The same rule runs
    /// the other way: a `.do_shuffle` event is delivered because the caller
    /// took that timer out of its queue, so `handleShuffleTimer` releases the
    /// latch after its candidate fits and before publishing it. A size refusal
    /// preserves the latch and RNG; the caller must re-queue the consumed timer
    /// if it continues driving that state. An allocation refusal leaves the
    /// latch clear so this tail can re-arm on a later turn.
    ///
    /// **Not transactional, and the residue is named rather than hidden.** An
    /// event advances `self` and appends to `out` as it goes, so an
    /// `error.OutOfMemory` out of an append leaves the state advanced as far as
    /// that event got and leaves the appends that succeeded in `out`. The state
    /// is still a valid `State` — every mutation here is checked, so nothing is
    /// left half-written — but it is not the state the caller handed in.
    ///
    /// The recovery is the caller's, and `plumtree.State.handle` states it in
    /// full because it is the same recovery: snapshot the value before the call
    /// and restore it on error, which works because `State` is a plain value
    /// holding no slice of its own storage. The copy is `@sizeOf(State)` and no
    /// allocation. The bounds stated there apply here. It restores `self` and
    /// nothing else, so a caller that acts on `out` as it drains it has already
    /// sent what it read; it restores `out` only when `out` was empty when the
    /// call started, because `Actions` cannot truncate to a saved length; and it
    /// does not restore the caller's timers — a `.do_shuffle` event is
    /// delivered because the caller removed that timer to fire it, so a restored
    /// copy carries `shuffle_scheduled` with no timer behind it and the caller
    /// must re-queue the shuffle itself. A caller that accumulates output across
    /// events, or that cannot keep a copy, must abandon instead: treat the
    /// failed `handle` as the end of this peer's run. Replaying the event is not
    /// promised to be idempotent.
    ///
    /// **What the entries in `out` borrow.** `Actions` owns the list and not the
    /// bytes its entries name, and those bytes live in three places. An emitted
    /// `peer_data` entry names the slice the event carried, which is the
    /// caller's own buffer. A `Shuffle` or `ShuffleReply` node list names a
    /// `peer_data` slot, and a `Join`'s, a `Neighbor`'s and a `Shuffle`'s own
    /// data names a `me_data` slot. Both of those are stored inline by value —
    /// `PeerDataMap.put` and `PeerData.fromBytes` each copied on the way in —
    /// so nothing is borrowed from the message that filled them. Appending
    /// copies the event value and no bytes, so an entry lives exactly as long
    /// as those places.
    ///
    /// Two calls end the claim on a `peer_data` slot: the next `handle` that
    /// writes one, and a quit, whose `peer_data.clear()` forgets them all. One
    /// call ends the claim on a `me_data` slot: a `.update_peer_data` event,
    /// which is the only thing that writes the field. A caller that keeps an
    /// output list across any of them must copy.
    pub fn handle(
        self: *State,
        event: SwarmInEvent,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.left) return;
        switch (event) {
            .recv_message => |recv| try arms.handleMessage(self, recv.from, recv.message, out),
            .timer_expired => |timer| switch (timer) {
                .do_shuffle => try shuffle.handleShuffleTimer(self, out),
                .pending_neighbor_request => |peer| try views.handlePendingNeighborTimer(
                    self,
                    peer,
                    out,
                ),
            },
            .peer_disconnected => |peer| try departure.handleConnectionClosed(self, peer, out),
            .request_join => |peer| try arms.handleJoin(self, peer, out),
            .update_peer_data => |data| self.me_data = data,
            .quit => try departure.handleQuit(self, out),
        }
        // A node that has just quit does not shuffle: there is no view left to
        // shuffle, and a timer armed after the quit is exactly the stale timer
        // the drop exists to prevent.
        if (self.left or self.shuffle_scheduled) return;
        try out.push(.{ .schedule_timer = .{
            .after = self.config.shuffle_interval,
            .timer = .do_shuffle,
        } });
        self.shuffle_scheduled = true;
    }

    pub fn myData(self: *const State) ?[]const u8 {
        // `&`, not a copy. The slice goes into a `Neighbor`, a `Join` and a
        // `Shuffle`, every one of which outlives this frame; a local
        // `const data` would hand back a pointer into a frame that dies on
        // return. Nothing here reports it — the bytes read back are whatever
        // the next call left in the dead slot — so the address is the fix and
        // this line is not load-bearing to tidy away.
        const data = &(self.me_data orelse return null);
        if (data.isEmpty()) return null;
        return data.slice();
    }

    /// Upstream `insert_peer_info`: record contact data, and tell the
    /// application when it is new.
    pub fn insertPeerInfo(
        self: *State,
        info: PeerInfo,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const data = info.data orelse return;
        const old = self.peer_data.get(info.id);
        const same = if (old) |held| std.mem.eql(u8, held.slice(), data) else false;
        if (!same and data.len != 0) {
            try out.push(.{ .peer_data = .{ .peer = info.id, .data = data } });
        }
        try self.peer_data.put(info.id, data);
    }

    /// Upstream `peer_info`: a node and the contact data we hold for it.
    pub fn peerInfoInto(self: *const State, peer: NodeId, into: *PeerInfo) void {
        const data = self.peer_data.get(peer);
        into.* = .{ .id = peer, .data = if (data) |held| held.slice() else null };
    }
};
