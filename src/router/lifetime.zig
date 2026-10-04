//! One configured protocol's own close, independent of every other protocol's:
//! `Lifetime` is the machine and `Lanes` is the bounded set of them, addressed
//! by the index a `Claim` carries.
//!
//! **Why this is its own file.** `Shutdown` in `shutdown.zig` is the endpoint's
//! close and is all-or-nothing by construction — upstream awaits one future per
//! registered handler at once, because its `Router::shutdown` is the one thing
//! that ends a router. A caller that wants one protocol retired while the
//! endpoint keeps serving the rest cannot use that, and adding a flag to it
//! would make every phase of it mean two things. `Lifetime` is the same three
//! steps scoped to one protocol, and it is a separate file because it has a
//! different owner, a different caller, and a different test.
//!
//! The two machines do not know about each other and the endpoint's close does
//! not go through here: nothing here waits for the endpoint and the endpoint
//! waits for nothing here, which is what "independent" means.
//!
//! **Nothing here performs anything.** A handler call is *named* by a
//! `Lifetime.Action` and the caller makes it, and the one thing a close reaches
//! outside this file is the offer list — `Lanes.offers` withdraws a retired
//! protocol's ALPN, so the next handshake cannot negotiate it.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: the three steps are upstream's
//! `protocols.shutdown().await`, `handler_cancel_token.cancel()` and the
//! handler's own close (`protocol.rs:404-407`, `:609-611`); the lane-per-
//! registration count is this project's, because upstream's map holds one
//! handler per ALPN and no per-registration entry to address.

const std = @import("std");
const router = @import("router.zig");

/// One configured protocol's own close, independent of every other protocol's.
///
/// `Shutdown` is upstream's close: one machine over *every* registered handler,
/// awaited together, because upstream's `Router::shutdown` is the one thing
/// that ends a router (`protocol.rs:435-452`, `:609-611`). This is the same
/// three steps — shut the handler down, cancel what it still owns, report it
/// closed — scoped to a single protocol, for the endpoint that keeps serving
/// the others while one of them is retired.
///
/// **The endpoint's close does not go through here, and the two machines do not
/// know about each other.** `Shutdown` is what `endpoint.Loop` drives when the
/// endpoint closes; a lane is for a caller that wants one protocol's lifetime
/// to end apart from the endpoint's. Nothing here waits for the endpoint and
/// the endpoint waits for nothing here, which is what "independent" means and
/// is the whole reason this is a second type rather than a flag on `Shutdown`.
///
/// It is a value and it holds no handler: which handler a lane belongs to is
/// `Router.dispatch`'s answer, and the call is the caller's to make, exactly as
/// `DispatchAction.on_accepting` names a call the router does not make. What is
/// running under the protocol is not counted here either — the accept table
/// owns that count (`endpoint.Loop.laneCount`), and a second count here would be
/// a second answer to the same question.
pub const Lifetime = struct {
    /// Which step is owed. The order is `Shutdown`'s, one protocol at a time,
    /// and it is the order the ordering bug lives in: a handler's state is
    /// released while the accepts that might still be using it are running,
    /// and never after.
    phase: Phase = .serving,

    pub const Phase = enum {
        /// The protocol is being served. Nothing waits here.
        serving,
        /// The protocol was retired and its handler is draining. Its accepts
        /// are still running and are owed their cancellation.
        draining_handlers,
        /// The handler has returned. What this protocol still owns is owed its
        /// cancellation, and only this protocol's.
        cancelling_accepts,
        /// Closed. Terminal, and this protocol's accepts can no longer be
        /// routed here.
        closed,
    };

    /// One thing that happened to this protocol's close.
    pub const Event = union(enum) {
        /// The application retired this protocol: no new connection is routed
        /// to it and its handler is told to stop.
        close_requested,
        /// This protocol's handler `shutdown` returned. Any other handler
        /// finishing is not this lane's business — that is the endpoint-wide
        /// `Shutdown`'s count.
        handler_finished,
        /// The accepts under this protocol are gone.
        accepts_cancelled,
    };

    /// The one thing this protocol's close owes.
    pub const Action = union(enum) {
        /// Call `shutdown` on this protocol's handler and await it.
        ///
        /// **No count, where `Shutdown.Action.shutdown_handlers` carries one**,
        /// and the difference is the point: upstream awaits one future per map
        /// value at once (`protocol.rs:404-407`), so its action says how many
        /// reports are owed. A lane names one handler, so one report is owed
        /// and there is no number to get wrong.
        shutdown_handler,
        /// Cancel the accepts running under this protocol. How many there are
        /// is the accept table's count, not this machine's.
        cancel_accepts,
        /// This protocol is closed and no longer claims its ALPN.
        closed,
        /// Nothing: this event is not this phase's business, or the step is
        /// already done.
        none,
    };

    pub const Step = struct {
        lifetime: Lifetime,
        action: Action,
    };

    /// A protocol being served, with nothing owed.
    pub fn init() Lifetime {
        return .{};
    }

    /// One step. Pure, and the whole of this protocol's close.
    ///
    /// Every event is named in every phase and nothing falls through, so a
    /// phase that could be left by the wrong event does not compile.
    pub fn step(self: Lifetime, event: Event) Step {
        return switch (self.phase) {
            .serving => switch (event) {
                .close_requested => .{
                    .lifetime = .{ .phase = .draining_handlers },
                    .action = .shutdown_handler,
                },
                .handler_finished, .accepts_cancelled => self.hold(),
            },
            .draining_handlers => switch (event) {
                .handler_finished => .{
                    .lifetime = .{ .phase = .cancelling_accepts },
                    .action = .cancel_accepts,
                },
                // The whole ordering of this arm: the cancel waits for this
                // protocol's handler, exactly as `Shutdown` waits for all of
                // them.
                .close_requested, .accepts_cancelled => self.hold(),
            },
            .cancelling_accepts => switch (event) {
                .accepts_cancelled => .{
                    .lifetime = .{ .phase = .closed },
                    .action = .closed,
                },
                .close_requested, .handler_finished => self.hold(),
            },
            .closed => self.hold(),
        };
    }

    /// Whether this protocol still claims its ALPN. `Lanes.offers` reads it,
    /// and it is the only place a retired protocol stops being offered.
    pub fn serving(self: *const Lifetime) bool {
        return self.phase == .serving;
    }

    /// No step. Absorbing an event that does not apply here is the point: the
    /// ordering lives in which event advances which phase, and an event that
    /// advances nothing is the ordering holding.
    fn hold(self: Lifetime) Step {
        return .{ .lifetime = self, .action = .none };
    }
};

/// The bounded set of protocol lifetimes, one lane per registration.
///
/// A lane is addressed by the index `Claim` carries, so dispatching an ALPN and
/// retiring the protocol it claimed are the same number: the caller never
/// compares ALPN bytes a second time to find out which lane is which, and
/// `endpoint` routes its accept tasks by the same number.
///
/// **One lane per registration, not per distinct ALPN**, because a lane is
/// addressed by an entry index and the newest registration is the one
/// `dispatch` returns. The displaced entry's lane is unreachable, exactly as
/// its entry is (`Builder.push`), and a caller that wants its handler's
/// shutdown count reads `Router.protocolCount`, which counts distinct ALPNs
/// rather than lanes.
///
/// The slots are the caller's and are never grown, like every other store in
/// this project: `init` takes the array and writes it, and an index outside it
/// is a caller's bounds error, which every function here refuses rather than
/// reading past.
pub const Lanes = struct {
    /// One lane per configured registration, in registration order.
    slots: []Lifetime,
    /// The table the lanes belong to, borrowed. It must outlive the lanes,
    /// which is the same rule a handler's context lives under.
    table: *const router.Router,

    /// Over storage the caller owns, which must outlive every step taken here
    /// and every read of the table it names.
    ///
    /// **Every lane starts serving, and this is what makes that so.** A lane has
    /// no admission step — `step` is the only thing that writes one after this —
    /// so storage nobody filled would be what `serving` and `offers` read.
    pub fn init(slots: []Lifetime, table: *const router.Router) Lanes {
        for (slots) |*slot| slot.* = Lifetime.init();
        return .{ .slots = slots, .table = table };
    }

    /// How many lanes exist, which is the number of configured registrations
    /// and therefore the highest `Claim.index` a dispatch can produce. A slots
    /// array shorter than the table has lanes that cannot be reached, and the
    /// refusal that earns is a null lane rather than a lane read out of range.
    ///
    /// Bounded by the storage and by the table, like `serving` and `offers`:
    /// iterating `0..count()` and reading an entry per lane is the shape this
    /// number exists for, and storage longer than the table must not put that
    /// loop past the last registration.
    pub fn count(self: *const Lanes) usize {
        return @min(self.slots.len, self.table.entries.len);
    }

    /// The lane at `index`, or null when there is none.
    pub fn at(self: *Lanes, index: usize) ?*Lifetime {
        if (index >= self.slots.len) return null;
        return &self.slots[index];
    }

    /// The lane the named ALPN claims, or null when no configured protocol
    /// claims it — the same refusal `Router.dispatch` gives, resolved to a
    /// lane.
    pub fn claiming(self: *Lanes, alpn: []const u8) ?*Lifetime {
        return self.at(claimIndex(self.table, alpn) orelse return null);
    }

    /// One step of one lane's own close, written back into the lane. Null when
    /// `index` is not a lane, which is the same answer `at` gives and for the
    /// same reason.
    ///
    /// The write is into the caller's slots, which is the same discipline the
    /// accept loop's own task table follows: the machine decides, the caller's
    /// storage holds.
    pub fn step(self: *Lanes, index: usize, event: Lifetime.Event) ?Lifetime.Step {
        const lane = self.at(index) orelse return null;
        const stepped = lane.step(event);
        lane.* = stepped.lifetime;
        return stepped;
    }

    /// The same, for the lane an ALPN claims.
    pub fn stepClaiming(
        self: *Lanes,
        alpn: []const u8,
        event: Lifetime.Event,
    ) ?Lifetime.Step {
        const index = claimIndex(self.table, alpn) orelse return null;
        return self.step(index, event);
    }

    /// The ALPNs to offer a peer: every configured protocol whose own lane is
    /// still serving, in registration order, into storage the caller sizes.
    ///
    /// This is `Router.offers` with retirement applied, and it is what makes a
    /// lane's close reach the wire: a protocol that is closed is withdrawn, so
    /// the next handshake cannot negotiate it and a peer asking for it is
    /// refused by the handshake rather than arriving at a closed lane.
    pub fn offers(self: *const Lanes, out: [][]const u8) usize {
        var written: usize = 0;
        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            // A slots array longer than the table has lanes past its last
            // registration, and those are not protocols: the loop stops there
            // rather than reading an entry that is not there.
            if (index >= self.table.entries.len) break;
            if (!self.slots[index].serving()) continue;
            if (written == out.len) break;
            out[written] = self.table.entries[index].alpn;
            written += 1;
        }
        return written;
    }

    /// How many protocols are still serving, which is the length of the offer
    /// list `offers` would write.
    ///
    /// Bounded by the table for the reason `offers` is: lanes past its last
    /// registration are not protocols, and counting them would make this and
    /// the offer list two answers to one question.
    pub fn serving(self: *const Lanes) usize {
        var still: usize = 0;
        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            if (index >= self.table.entries.len) break;
            if (self.slots[index].serving()) still += 1;
        }
        return still;
    }
};

/// The lane an ALPN dispatches to, or null when nothing claims it. One place to
/// ask, so `Lanes` and the accept task table cannot disagree about which
/// registration a connection landed on.
fn claimIndex(table: *const router.Router, alpn: []const u8) ?usize {
    return switch (table.dispatch(alpn)) {
        .protocol => |found| found.index,
        .refused => null,
    };
}

const t = std.testing;

/// A handler that answers `shutdown` and counts the call. Every test here owns
/// one: the whole claim of a lane is that closing one protocol touches no
/// handler, so the only call worth observing is the one that must not happen.
const Recorder = struct {
    shutdown_calls: usize = 0,

    /// `accept` is the one field of `ProtocolHandler` with no default, so a
    /// recorder that answers only `shutdown` still needs a body for it. No lane
    /// test calls it — the machine names handler calls and the caller makes
    /// them — and none of them counts it.
    fn accept(ctx: *anyopaque, connection: router.Connection) router.AcceptError!void {
        _ = ctx;
        _ = connection;
    }

    fn shutdown(ctx: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.shutdown_calls += 1;
    }

    fn handler(self: *Recorder) router.ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = null,
            .accept = Recorder.accept,
            .shutdown = Recorder.shutdown,
        };
    }
};

test "one protocol's close is its own, and the others keep serving" {
    var gossip: Recorder = .{};
    var blobs: Recorder = .{};
    var relay: Recorder = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/iroh-gossip/1", gossip.handler());
    _ = try builder.accept("/iroh-bytes/4", blobs.handler());
    _ = try builder.accept("/iroh-relay/1", relay.handler());
    const table = builder.build();

    var slots: [3]Lifetime = undefined;
    var lanes = Lanes.init(&slots, &table);
    try t.expectEqual(@as(usize, 3), lanes.count());
    try t.expectEqual(@as(usize, 3), lanes.serving());

    // Retiring one protocol: the same three steps `Shutdown` enforces, in the
    // same order, and none of them waits on the other two lanes.
    const close = lanes.stepClaiming("/iroh-bytes/4", .close_requested).?;
    try t.expectEqual(Lifetime.Action.shutdown_handler, close.action);
    try t.expectEqual(Lifetime.Phase.draining_handlers, close.lifetime.phase);
    // Nothing else moved: the two protocols that were serving are still
    // serving, and this is the independence the endpoint-wide machine does not
    // have — it is all-or-nothing by construction.
    try t.expectEqual(@as(usize, 2), lanes.serving());
    try t.expectEqual(
        Lifetime.Phase.serving,
        lanes.claiming("/iroh-gossip/1").?.phase,
    );
    try t.expectEqual(
        Lifetime.Phase.serving,
        lanes.claiming("/iroh-relay/1").?.phase,
    );

    // The ordering inside the one lane: the cancel cannot be emitted while its
    // handler is still draining, and neither report can be fed early.
    for ([_]Lifetime.Event{ .close_requested, .accepts_cancelled }) |early| {
        const held = lanes.stepClaiming("/iroh-bytes/4", early).?;
        try t.expectEqual(Lifetime.Action.none, held.action);
        try t.expectEqual(Lifetime.Phase.draining_handlers, held.lifetime.phase);
    }
    const cancel = lanes.stepClaiming("/iroh-bytes/4", .handler_finished).?;
    try t.expectEqual(Lifetime.Action.cancel_accepts, cancel.action);
    try t.expectEqual(Lifetime.Phase.cancelling_accepts, cancel.lifetime.phase);

    // A handler finishing for a *different* protocol is not this lane's
    // business, which is the endpoint-wide `Shutdown`'s count and not a lane's.
    const stranger = lanes.stepClaiming("/iroh-gossip/1", .handler_finished).?;
    try t.expectEqual(Lifetime.Action.none, stranger.action);
    try t.expectEqual(Lifetime.Phase.serving, stranger.lifetime.phase);

    // And the lane finishes on its own reports, without the endpoint closing.
    const closed = lanes.stepClaiming("/iroh-bytes/4", .accepts_cancelled).?;
    try t.expectEqual(Lifetime.Action.closed, closed.action);
    try t.expectEqual(Lifetime.Phase.closed, closed.lifetime.phase);
    try t.expectEqual(@as(usize, 2), lanes.serving());
    // A closed protocol absorbs every later event, including a second close.
    const again = lanes.stepClaiming("/iroh-bytes/4", .close_requested).?;
    try t.expectEqual(Lifetime.Action.none, again.action);
    try t.expectEqual(Lifetime.Phase.closed, again.lifetime.phase);

    // The handler call itself is still the caller's, and one close touched one
    // handler: the machine named the call and did not make it.
    try t.expectEqual(@as(usize, 0), blobs.shutdown_calls);
    try t.expectEqual(@as(usize, 0), gossip.shutdown_calls);
    try t.expectEqual(@as(usize, 0), relay.shutdown_calls);
}

test "a retired protocol is withdrawn from the offer list" {
    var gossip: Recorder = .{};
    var blobs: Recorder = .{};
    var entries: [2]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/iroh-gossip/1", gossip.handler());
    _ = try builder.accept("/iroh-bytes/4", blobs.handler());
    const table = builder.build();

    var slots: [2]Lifetime = undefined;
    var lanes = Lanes.init(&slots, &table);
    var list: [2][]const u8 = undefined;

    // Both protocols are served, so both are offered — which is what makes a
    // wrong-protocol peer fail in the handshake instead of reaching a table
    // that cannot claim it.
    try t.expectEqual(@as(usize, 2), lanes.offers(&list));
    try t.expectEqualStrings("/iroh-gossip/1", list[0]);
    try t.expectEqualStrings("/iroh-bytes/4", list[1]);
    // And the static list agrees while nothing has been retired.
    try t.expectEqual(@as(usize, 2), table.offers(&list));

    // Retire one, and the offer list shrinks to what is still served: the
    // closed protocol's ALPN is gone, and the survivor keeps its registration
    // order position among those left.
    _ = lanes.stepClaiming("/iroh-gossip/1", .close_requested);
    try t.expectEqual(@as(usize, 1), lanes.offers(&list));
    try t.expectEqualStrings("/iroh-bytes/4", list[0]);
    // The table still holds it — retiring a protocol withdraws it from the
    // wire, it does not unregister it.
    try t.expectEqual(@as(usize, 2), table.offers(&list));
    try t.expectEqual(@as(usize, 2), table.configured());
    try t.expect(std.meta.activeTag(table.dispatch("/iroh-gossip/1")) == .protocol);

    // A lane the slots do not have is refused rather than read past, and an
    // ALPN nothing claims has no lane to step at all.
    try t.expectEqual(@as(?*Lifetime, null), lanes.at(2));
    try t.expectEqual(@as(?Lifetime.Step, null), lanes.step(2, .close_requested));
    try t.expectEqual(@as(?*Lifetime, null), lanes.claiming("/iroh-docs/1"));
    try t.expectEqual(
        @as(?Lifetime.Step, null),
        lanes.stepClaiming("/iroh-docs/1", .close_requested),
    );
}

test "each retirement withdraws only its own protocol" {
    var gossip: Recorder = .{};
    var blobs: Recorder = .{};
    var relay: Recorder = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/iroh-gossip/1", gossip.handler());
    _ = try builder.accept("/iroh-bytes/4", blobs.handler());
    _ = try builder.accept("/iroh-relay/1", relay.handler());
    const table = builder.build();

    // Storage the caller never wrote: `Lanes.init` fills the lanes, so every
    // configured protocol starts serving and every one of them is offered.
    var slots: [3]Lifetime = undefined;
    var lanes = Lanes.init(&slots, &table);
    var list: [3][]const u8 = undefined;
    try t.expectEqual(@as(usize, 3), lanes.serving());
    try t.expectEqual(@as(usize, 3), lanes.offers(&list));
    try t.expectEqual(@as(usize, 3), table.configured());

    // One protocol taken all the way to closed. The other two lanes did not
    // move, and the proof is their phases rather than a count, which could
    // agree by accident.
    const close_order = [_]Lifetime.Event{
        .close_requested,
        .handler_finished,
        .accepts_cancelled,
    };
    for (close_order) |event| _ = lanes.stepClaiming("/iroh-bytes/4", event);
    try t.expectEqual(Lifetime.Phase.closed, lanes.claiming("/iroh-bytes/4").?.phase);
    try t.expectEqual(Lifetime.Phase.serving, lanes.claiming("/iroh-gossip/1").?.phase);
    try t.expectEqual(Lifetime.Phase.serving, lanes.claiming("/iroh-relay/1").?.phase);

    // The withdrawal is the one thing a close reaches on the wire: the retired
    // ALPN is gone, the survivors keep their registration order among those
    // left, and the table still claims all three.
    try t.expectEqual(@as(usize, 2), lanes.serving());
    try t.expectEqual(@as(usize, 2), lanes.offers(&list));
    try t.expectEqualStrings("/iroh-gossip/1", list[0]);
    try t.expectEqualStrings("/iroh-relay/1", list[1]);
    try t.expectEqual(@as(usize, 3), table.offers(&list));

    // A protocol that is retiring is already withdrawn: `close_requested` is
    // the first step and its ALPN is gone from the same moment, so a peer
    // cannot negotiate its way into a lane that is being closed.
    _ = lanes.stepClaiming("/iroh-gossip/1", .close_requested);
    try t.expectEqual(
        Lifetime.Phase.draining_handlers,
        lanes.claiming("/iroh-gossip/1").?.phase,
    );
    try t.expectEqual(@as(usize, 1), lanes.serving());
    try t.expectEqual(@as(usize, 1), lanes.offers(&list));
    try t.expectEqualStrings("/iroh-relay/1", list[0]);
    // The last protocol was moved by neither retirement.
    try t.expectEqual(Lifetime.Phase.serving, lanes.claiming("/iroh-relay/1").?.phase);
    try t.expectEqual(@as(usize, 0), gossip.shutdown_calls);
    try t.expectEqual(@as(usize, 0), blobs.shutdown_calls);
    try t.expectEqual(@as(usize, 0), relay.shutdown_calls);
}

test "lane storage longer than the table holds no phantom protocol" {
    var gossip: Recorder = .{};
    var blobs: Recorder = .{};
    var entries: [2]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/iroh-gossip/1", gossip.handler());
    _ = try builder.accept("/iroh-bytes/4", blobs.handler());
    const table = builder.build();

    // More lane storage than registrations is the caller's choice and is
    // allowed. The lanes past the last registration are not protocols: they
    // are neither counted as serving nor read as an entry, which is what keeps
    // `serving` the length of the offer list instead of the length of the
    // storage.
    var slots: [4]Lifetime = undefined;
    var lanes = Lanes.init(&slots, &table);
    var list: [4][]const u8 = undefined;
    try t.expectEqual(@as(usize, 2), lanes.serving());
    try t.expectEqual(@as(usize, 2), lanes.offers(&list));
    try t.expectEqualStrings("/iroh-gossip/1", list[0]);
    try t.expectEqualStrings("/iroh-bytes/4", list[1]);
    // `count` is the number of protocols and not the length of the storage, so
    // a caller that iterates it reads an entry per lane and cannot walk past
    // the last registration.
    try t.expectEqual(@as(usize, 2), lanes.count());
    // A lane that is not a protocol is still storage, so it can be stepped,
    // and doing so reaches neither the offer list nor the count: there is no
    // entry at that index to withdraw and no protocol to withdraw.
    _ = lanes.step(3, .close_requested);
    _ = lanes.step(3, .handler_finished);
    _ = lanes.step(3, .accepts_cancelled);
    try t.expectEqual(Lifetime.Phase.closed, lanes.at(3).?.phase);
    try t.expectEqual(@as(usize, 2), lanes.serving());
    try t.expectEqual(@as(usize, 2), lanes.offers(&list));
}
