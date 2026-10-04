//! One topic of gossip: the state machine, the timers it asked for, and the
//! peers it named — and the lifetime of all three.
//!
//! `node.zig` holds this by value and drives it; it does not own it. The topic
//! itself holds no heap, the timer list is taken from an allocator the caller
//! named and given back in `deinit`, and the named-peer ring is a fixed array
//! this file cuts for itself.
//!
//! **Nothing here counts, and that is the design rather than an omission.** What
//! an action asked for is counted by the caller, in the caller's own vocabulary,
//! through a `Tally` this file fills in: the counters a caller publishes are
//! `node_stats.Stats` and this file has no business knowing them. What it
//! does own is what *happened* — the event reached the machine, it scheduled
//! this timer at this instant, it named that peer — and the named-peer ring is
//! kept here precisely because it is a record of what happened rather than a
//! statistic of it.
//!
//! **This file performs nothing on a wire, and that is a split, not a gap.**
//! `feed` leaves every request the state machine made in a list the caller
//! owns, in the order the state machine made it: a `send_message` names a
//! node id, and turning that id into a connection, a stream and bytes is a
//! question about connections rather than about swarms. `topic_table` answers
//! where a topic writes and `conn_index` answers which connection a peer is
//! on; `node_gossip` asks both. What this file keeps is the timers, because a
//! timer belongs to the topic and no other module knows when it was asked for.

const std = @import("std");

const base_key = @import("../base/key.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");

const NodeId = base_key.NodeId;
const Allocator = std.mem.Allocator;
const Nanos = hyparview.Nanos;

/// The caller's list of requests, which `feed` fills and the caller performs.
const Actions = hyparview.Actions;

/// What this file refuses: exactly what the topic's own `handle` returns, and
/// nothing of its own.
pub const Error = hyparview.Error || plumtree.Error || Allocator.Error;

/// A timer the gossip layers asked for, and the instant it comes due.
const Pending = struct {
    due: Nanos,
    timer: hyparview.Timer,
};

/// What one event's actions were counted as, in this file's own words.
///
/// **Nine arms, and none of them is a decision.** Every field moves because an
/// action asked for something and something answered it; the caller decides what
/// those answers mean to it and publishes them under its own names. Keeping the
/// two apart is what lets this file hold the state machine without holding the
/// node's counters.
pub const Tally = struct {
    /// Events the layer handled, which is one per `feed`.
    events: u64 = 0,
    /// Timers it asked to be scheduled.
    timers_scheduled: u64 = 0,
    /// Messages membership asked to be sent.
    membership_asked: u64 = 0,
    /// Messages broadcast asked to be sent.
    broadcast_asked: u64 = 0,
    /// Peers membership asked to be disconnected.
    disconnects_asked: u64 = 0,
    /// What membership reported upwards.
    neighbor_up: u64 = 0,
    neighbor_down: u64 = 0,
    broadcasts_received: u64 = 0,
    /// Contact data the layer was handed.
    peer_data_seen: u64 = 0,
};

/// One node's one topic: its state machine, the timers it asked for, and the
/// peers it named.
///
/// `ring_depth` is how many names are kept, and it is comptime because the ring
/// is a fixed array rather than something that grows: a reader wants the most
/// recent names, and a list that grew would be unbounded on a node whose gossip
/// layer names a peer for every message it asks to be sent.
pub fn State(comptime ring_depth: usize) type {
    return struct {
        const Self = @This();

        /// The state machine itself, built once and terminal from then on.
        topic: hyparview.TopicState,
        /// The timers it asked for, in the order it asked for them. A node that
        /// has been idle therefore wakes on the same schedule every time.
        timers: std.ArrayList(Pending),
        /// The peers the state machine named for its most recent actions,
        /// oldest first, and how many of them are live.
        named: [ring_depth]NodeId,
        named_len: usize,

        /// Build the topic, its timers and its ring.
        ///
        /// The generator is a parameter rather than a draw from the caller's
        /// runtime because this file owns no clock and no entropy source: the
        /// caller's node draws the seed from the generator it owns and passes
        /// the result, which is what keeps a simulation run reproducible.
        pub fn init(
            me: NodeId,
            me_data: ?hyparview.PeerData,
            config: hyparview.TopicConfig,
            rng: hyparview.Rng,
        ) Error!Self {
            return .{
                .topic = try hyparview.TopicState.init(me, me_data, config, rng),
                .timers = .empty,
                .named = undefined,
                .named_len = 0,
            };
        }

        /// Give back the timer list. The topic itself holds no heap and the ring
        /// is inline, so this is the whole of it.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.timers.deinit(gpa);
        }

        /// The peers the gossip layer named in its most recent actions, oldest
        /// first. The slice borrows this struct and changes when later actions
        /// name peers.
        pub fn namedPeers(self: *const Self) []const NodeId {
            return self.named[0..self.named_len];
        }

        /// Forget every timer still pending, keeping the list's room.
        ///
        /// **Dropped at the handler's own shutdown rather than at teardown**,
        /// because that is the point upstream's ordering is about: a handler is
        /// given its shutdown while the accepts that might still be using it are
        /// still running, and never after.
        pub fn clearTimers(self: *Self) void {
            self.timers.clearRetainingCapacity();
        }

        /// Hand one event to the topic, keep what belongs to the topic, and
        /// leave the rest in `out` for the caller to perform.
        ///
        /// **`out` is the caller's list and it is empty on entry**, which the
        /// assertion proves rather than trusts: a caller that reused one would
        /// find every entry below counted again for an event it never saw, and
        /// `TopicState.handle` appends rather than replaces, so the tally
        /// would be wrong without anything raising.
        ///
        /// **The sends and the disconnects stay in the list, in order.** The
        /// state machine's ordering is load-bearing — see `TopicState.handle`
        /// for the three passes — and a caller that re-sorted or filtered them
        /// would change which peers a message reaches. So the walk below only
        /// reads, and the caller walks the same list again to act.
        ///
        /// The tally is filled rather than owned, so this file never reads the
        /// node's counters; see the module doc for why that is the design.
        pub fn feed(
            self: *Self,
            event: hyparview.InEvent,
            now: Nanos,
            tally: *Tally,
            out: *Actions(hyparview.OutEvent),
        ) Error!void {
            std.debug.assert(out.count() == 0);
            try self.topic.handle(event, now, out);
            tally.events += 1;
            for (out.slice()) |produced| switch (produced) {
                .send_message => |send| {
                    self.note(send.to);
                    switch (send.message) {
                        .swarm => tally.membership_asked += 1,
                        .gossip => tally.broadcast_asked += 1,
                    }
                },
                // The one request this file performs: a timer is the topic's
                // own, and its due instant is `now` plus what was asked for.
                .schedule_timer => |schedule| {
                    tally.timers_scheduled += 1;
                    try self.timers.append(out.gpa, .{
                        .due = now + schedule.after,
                        .timer = schedule.timer,
                    });
                },
                // Counted, named, and left for the caller, which is the only
                // module that can tell which connection a node id is on.
                .disconnect_peer => |peer| {
                    tally.disconnects_asked += 1;
                    self.note(peer);
                },
                .emit_event => switch (produced.emit_event) {
                    .neighbor_up => tally.neighbor_up += 1,
                    .neighbor_down => tally.neighbor_down += 1,
                    .received => tally.broadcasts_received += 1,
                },
                // Contact data the caller stores against the topic; the bytes
                // borrow the state, so it must copy before this call returns.
                .peer_data => tally.peer_data_seen += 1,
            };
        }

        /// Keep the peer an action named, for the report and for nothing else.
        fn note(self: *Self, peer: NodeId) void {
            if (self.named_len == ring_depth) {
                @memmove(self.named[0 .. ring_depth - 1], self.named[1..]);
                self.named_len -= 1;
            }
            self.named[self.named_len] = peer;
            self.named_len += 1;
        }

        /// A walk over the timers that are due at one instant.
        ///
        /// **The cursor is the caller's and the list is this struct's.** A timer
        /// fired between two calls may ask for another, and this walk resumes
        /// where the removal left it — so an action that lands at the end of the
        /// list is reached in this same walk, exactly as it was when the loop was
        /// the node's own.
        pub const Due = struct {
            state: *Self,
            now: Nanos,
            position: usize = 0,

            /// The next timer due at `now`, or null when the walk is spent.
            pub fn next(self: *Due) ?hyparview.Timer {
                while (self.position < self.state.timers.items.len) {
                    if (self.state.timers.items[self.position].due > self.now) {
                        self.position += 1;
                        continue;
                    }
                    // Removal moves whatever was last into the hole, so the
                    // cursor stays where it is and does not step past it.
                    return self.state.timers.orderedRemove(self.position).timer;
                }
                return null;
            }
        };
    };
}
