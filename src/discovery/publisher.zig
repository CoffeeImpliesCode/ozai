//! When a record goes out again, what goes out, and whose key may sign it.
//!
//! Upstream's publisher is a `watchable.set` plus a background task
//! (`iroh/src/address_lookup/pkarr.rs`, `PkarrPublisher` at :357 and
//! `update_endpoint_data`'s `self.watchable.set(Some(info))`): the endpoint
//! hands over an `EndpointData` whenever it changes, and a timer republishes it
//! so the relay's copy does not age out. Three things live here that upstream
//! spreads across a channel and a `tokio` interval, kept as values because
//! `AGENTS.md` §2 says a state machine takes decoded input plus state and
//! returns new state plus actions, with no clock and no runtime inside it.
//!
//! # How often a record is republished
//!
//! **Upstream's interval is 30 seconds and this file does not claim it.** The
//! constant lives in `iroh/src/address_lookup/pkarr.rs` and no copy of that file
//! is on this machine — the reference checkout `~/projects/github-n0-computer-iroh*`
//! that `AGENTS.md` names is not present, and a value quoted from memory is not
//! evidence. So `republish_interval_ms` is a **caller-supplied parameter with a
//! documented default**, and the default is stated as this project's choice:
//!
//! * `default_republish_interval_ms` is 60 000 ms. A pkarr relay stores a
//!   packet for an hour at most — that figure is likewise unverified here — so a
//!   minute is a compromise: sixteen republishes per record per hour against a
//!   relay that would hold one for sixty.
//! * **What closes the gap** is one line of the pinned upstream file. A caller
//!   that knows the figure passes it; nothing here reads it from anywhere.
//!
//! The interval is a *deadline from the last attempt*, not from the last
//! confirmation, and `tick`'s doc says why. A confirmation that never arrives
//! must not turn into a tighter loop, or a relay that accepts connections and
//! drops the body would be asked sixty times a minute for ever.
//!
//! # What happens when the timer fires and the previous publish is unconfirmed
//!
//! **The tick is skipped and the publisher is told so.** This is the decision
//! this module exists to make, and it is `Action.deferred` rather than
//! `Action.publish`.
//!
//! * **Not published.** A pkarr relay's write is last-writer-wins on one key.
//!   Two `PUT`s in flight for the same node can land in either order, so a
//!   republish over an unconfirmed one publishes *a value nobody chose* — the
//!   older of the two, which is exactly the stale record the republish exists to
//!   replace. Upstream has no answer here because `publish` is fire-and-forget
//!   and "the Endpoint can not wait for successful publishing"
//!   (`iroh/src/address_lookup.rs:337`): it never learns whether the last one
//!   landed. This module is told, because `tick` takes the confirmation as an
//!   argument.
//! * **Not confirmed, either.** `Action.deferred` is a distinct arm and not an
//!   error: the record may well be stored. Nothing here knows, and
//!   `docs/ARCHITECTURE.md`'s rule about unverified claims is the reason — the
//!   publisher must not report a record as published when the relay has not said
//!   so.
//! * **Not retried forever.** `skip_unconfirmed` bounds how many consecutive
//!   deferred ticks a publisher will accept before it reports the record as
//!   `stale`. Without a bound, a relay that is down produces a
//!   publisher that is permanently busy and permanently silent, which is the
//!   same failure as a timer that never fires and harder to see.
//! * **Recoverable.** A later tick with the confirmation in hand publishes. And
//!   `abandon` puts the publisher back to idle explicitly, for a caller that has
//!   decided the relay is gone and wants to try again from scratch.
//!
//! # How answers from several sources are merged
//!
//! A node's addresses arrive from more than one place — its own configuration,
//! a peer that told it, a direct observation — and every one of them is a
//! `resolve.Published`. `mergePublished` unions them into one `NodeAddr`, and
//! the union is `addr.NodeAddr.insert`'s rather than a second rule:
//! `docs/ARCHITECTURE.md` invariant 2 makes an address list a set, and `insert`
//! is the one function in this tree that keeps one sorted and duplicate-free.
//!
//! Two things are refused rather than merged, and both are refusals because a
//! merge would publish something nobody said:
//!
//! * `error.MixedNodeIds` — sources that are about different nodes. Publishing
//!   node B's addresses under node A's key makes every resolver believe A is
//!   reachable at B, which is `error.UnexpectedSigner` on the reading side and
//!   the same fault seen from the other side.
//! * `error.NoAddresses` — nothing to publish. A packet with no records says a
//!   name and nothing about the node behind it.
//!
//! `Published` is a **transfer**: the caller's allocator comes with it and each
//! source is released with its own, because a publisher holds no allocator of
//! its own (`discovery/lookup.zig`'s `releaseTransfer` is where that rule is
//! argued). So `mergePublished` does not take ownership: it copies the addresses
//! into a list the caller owns with `alloc`, and releases every source on the
//! way out including the error paths.
//!
//! # Purity
//!
//! No clock, no socket, no global, no thread. `tick` takes `now_ms` as an
//! argument, the interval is a field rather than a constant read, and `SecretKey`
//! is reached through a pointer so a caller's key is never copied.

const std = @import("std");

const lookup = @import("lookup.zig");
const resolve = @import("resolve.zig");

const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");

const item = @import("item.zig");

/// How often a publisher republishes when the caller names no interval.
///
/// **This project's value and not upstream's.** The upstream constant is in
/// `iroh/src/address_lookup/pkarr.rs` and no copy of that file is on this
/// machine, so quoting it would be a claim with nothing behind it. Sixty seconds
/// against a relay that holds a packet for at most an hour is sixteen
/// republishes per record per hour; see the module doc for what closes the gap.
pub const default_republish_interval_ms: u64 = 60_000;

/// How many consecutive deferred ticks a publisher accepts before it reports
/// the record as stale.
///
/// A bound and not a policy: without it a relay that accepts connections and
/// drops the body produces a publisher that is permanently busy and permanently
/// silent, which is the same failure as a timer that never fires and much harder
/// to see. Four is arbitrary and small — long enough that one lost `PUT` is not
/// a stale record, short enough that a relay which is down is noticed in about a
/// minute at the default interval.
pub const skip_unconfirmed: u32 = 4;

/// What one publication is, and the allocator it came with.
///
/// `resolve.Published` unchanged, because that type is the tree's transfer
/// contract and a second one would be a second set of rules about who owns an
/// address list.
pub const Published = resolve.Published;

/// What one tick of the timer decided.
///
/// Three arms and no error, because every one of these is a fact about the
/// publisher's state rather than a failure: a caller that cannot tell "not due
/// yet" from "due and refused to run" cannot write the loop that drives it.
pub const Action = union(enum) {
    /// Not yet. The instant, in the caller's `now_ms` scale, the next tick is
    /// due.
    wait_until: u64,
    /// Publish now. The record is in the publisher's slot and the caller signs
    /// it and puts it.
    publish,
    /// Due, and skipped: the previous publish has not been confirmed, so a
    /// second one could land first and publish the older of the two.
    ///
    /// Not an error and not a confirmation either. The record may be stored;
    /// nothing here knows, and saying so would be claiming a fact the relay has
    /// not given.
    deferred,
    /// Due, and skipped too many times in a row. The record is treated as not
    /// published, which is what a caller needs to hear so it can stop trusting
    /// it and say so.
    stale,
};

/// What one publisher knows, and when it last tried.
///
/// A value rather than a service, because the whole of it is state a caller
/// drives: a `tokio` interval upstream is a runtime and a clock, and this is the
/// same decision with both taken out.
///
/// Copy freely: there is nothing here that owns a descriptor or borrows a
/// buffer. The `Published` in the slot is the exception and is stated there.
pub const State = struct {
    /// The address to publish, owned by the caller's allocator, or null when
    /// nothing has been published yet.
    ///
    /// A slot rather than a queue because a publisher's job is to say what this
    /// node is reachable at *now*: an address the endpoint has since stopped
    /// using is not a second opinion, it is stale. That is upstream's
    /// `watchable.set` (`iroh/src/address_lookup/pkarr.rs`,
    /// `update_endpoint_data`).
    slot: ?Published,
    /// How long after a publish attempt the next one is due, in the same scale
    /// as `now_ms`.
    interval_ms: u64,
    /// When the last attempt went out, or null when none has.
    ///
    /// The clock starts here and **not** at the last confirmation. A
    /// confirmation that never arrives must not shorten the interval into a
    /// loop, and a relay that accepts and drops the body would otherwise be
    /// asked once per millisecond for ever.
    last_attempt_ms: ?u64,
    /// Whether the last attempt was confirmed. Null when nothing has been
    /// attempted, which is not the same as false: a publisher that has never
    /// published has nothing to be stale about.
    was_confirmed: ?bool,
    /// Consecutive deferred ticks, which is what `skip_unconfirmed` counts.
    deferred_run: u32,

    /// A publisher with nothing published and the default interval.
    pub fn init() State {
        return .{
            .slot = null,
            .interval_ms = default_republish_interval_ms,
            .last_attempt_ms = null,
            .was_confirmed = null,
            .deferred_run = 0,
        };
    }

    /// Take `data` as the thing to publish, replacing whatever was there.
    ///
    /// **The previous slot is released, with the allocator it arrived with.**
    /// The caller gave up ownership of `data` on the way in, so a publisher
    /// that dropped the old one would leak it and a publisher that released it
    /// with its own allocator would be a double free or a leak depending on
    /// which that was — which is why `Published` carries an allocator at all
    /// (`discovery/lookup.zig`).
    ///
    /// A replacement is *not* a republish: `last_attempt_ms` is left alone, so
    /// the next tick still waits out the interval. The relay's copy of the old
    /// value is stale from the moment this is called, and the timer is what
    /// fixes that; publishing immediately here would be a second mechanism for
    /// one decision.
    pub fn set(self: *State, data: Published) void {
        self.releaseSlot();
        self.slot = data;
    }

    /// Release the slot, if there is one, and leave the publisher empty.
    ///
    /// Separate from `set` because a caller that stops publishing has to release
    /// what it handed over, and `set` alone would leave the last record alive
    /// for ever.
    pub fn releaseSlot(self: *State) void {
        if (self.slot) |held| lookup.releaseTransfer(held);
        self.slot = null;
    }

    /// What one tick at `now_ms` decides.
    ///
    /// Pure over this state and the instant, which is the whole of
    /// `AGENTS.md` §2's rule for this kind of decision: no clock, no socket, no
    /// allocator. A caller drives it at whatever times it likes and can replay a
    /// timeline exactly.
    ///
    /// The order is what the arms are for, and it is the order of the questions:
    ///
    /// 1. **Is there anything to publish?** No slot is `Action.wait_until` of
    ///    `now_ms`, which is never — a publisher with nothing to say has nothing
    ///    to say on any tick. It is a wait rather than `publish` because `publish`
    ///    would mean putting an empty packet on the wire.
    /// 2. **Has the interval run out?** No is `Action.wait_until` of the instant
    ///    it runs out at. Saturating at `maxInt`, because a clock that went
    ///    backwards must not produce an instant in the past and a caller that
    ///    obeys it would then be told to publish in the past for ever.
    /// 3. **Was the last attempt confirmed?** No is `Action.deferred` for the
    ///    first `skip_unconfirmed` such ticks and `Action.stale` after that. See
    ///    the module doc: this is the decision the file is for.
    /// 4. Otherwise `Action.publish`.
    ///
    /// A tick does not change the state. Recording an attempt or a confirmation
    /// is `attempted` and `recordConfirmed`, so a caller that crashes between
    /// and sending has not recorded a send that never happened.
    pub fn tick(self: *const State, now_ms: u64) Action {
        if (self.slot == null) return .{ .wait_until = now_ms };
        const last = self.last_attempt_ms orelse return .publish;
        const due = std.math.add(u64, last, self.interval_ms) catch std.math.maxInt(u64);
        if (now_ms < due) return .{ .wait_until = due };
        // An attempt that was never confirmed, or was confirmed and then the
        // relay stopped answering, is the same arm: this tick does not put a
        // second packet on the wire over one whose fate is unknown.
        if (self.was_confirmed != true) {
            return if (self.deferred_run >= skip_unconfirmed)
                .stale
            else
                .deferred;
        }
        return .publish;
    }

    /// Record that a publish attempt went out at `now_ms`.
    ///
    /// `was_confirmed` is set to null rather than false: the attempt is not yet
    /// known either way, and a publisher that recorded false would immediately
    /// defer every tick that followed, including the one for the publish it is
    /// still waiting to hear about.
    pub fn attempted(self: *State, now_ms: u64) void {
        self.last_attempt_ms = now_ms;
        self.was_confirmed = null;
        self.deferred_run = 0;
    }

    /// Record that the relay confirmed the last attempt.
    ///
    /// Only legal after `attempted`, and asserted rather than checked: a
    /// confirmation with no attempt behind it is a caller's bug, and treating it
    /// as a confirmation would make a publisher believe a record is published
    /// when nothing was ever sent.
    pub fn recordConfirmed(self: *State) void {
        std.debug.assert(self.last_attempt_ms != null);
        self.was_confirmed = true;
        self.deferred_run = 0;
    }

    /// Record that the relay refused or did not answer the last attempt.
    ///
    /// The same value as `attempted` followed by nothing: the attempt is known
    /// to have failed, so the next tick defers. The distinction from a lost
    /// confirmation is that this is a fact and the other is not — and neither
    /// leads to a second publish this tick, which is the module's decision.
    pub fn refused(self: *State) void {
        std.debug.assert(self.last_attempt_ms != null);
        self.was_confirmed = false;
    }

    /// Record a deferred tick, so `skip_unconfirmed` has something to count.
    pub fn deferred(self: *State) void {
        self.deferred_run += 1;
    }

    /// Put the publisher back to idle: no attempt on record, nothing deferred.
    ///
    /// For a caller that has decided the relay is gone and wants to try again
    /// from scratch rather than wait out the stale bound. The slot is kept —
    /// abandoning a *timer* is not abandoning the record — and this is explicit
    /// so a caller cannot do it by accident.
    pub fn abandon(self: *State) void {
        self.last_attempt_ms = null;
        self.was_confirmed = null;
        self.deferred_run = 0;
    }

    /// What was published last, or null when nothing has been.
    ///
    /// Borrows the publisher's own storage, so the address list is dead after
    /// the next `set` or `releaseSlot`.
    pub fn published(self: *const State) ?item.Item {
        const data = self.slot orelse return null;
        return item.Item.init(data.endpoint, .pkarr, data.last_updated);
    }
};

/// What a fan-in refuses.
pub const MergeError = error{
    /// Two sources are about different nodes. Publishing node B's addresses
    /// under node A's key makes every resolver believe A is reachable at B.
    MixedNodeIds,
    /// No source carried an address. A packet with no records says a name and
    /// nothing about the node behind it.
    NoAddresses,
    /// The union did not fit in `alloc`. The sources are still released, so a
    /// failed merge leaves the caller with nothing to clean up and no partial
    /// list to mistake for a complete one.
    OutOfMemory,
};

/// Union several sources' addresses into one list, owned by `alloc`.
///
/// The union is `addr.NodeAddr.insert` and not a second rule:
/// `docs/ARCHITECTURE.md` invariant 2 makes an address list a set, `insert` is
/// the one function in this tree that keeps one sorted and duplicate-free, and a
/// second rule would be a list that sorts differently from every other list in
/// ozai — which invariant 2's own reasoning says is how a merge starts picking
/// a relay nobody else would.
///
/// **No ownership is taken.** Every source is released with its own allocator
/// before this returns, on the error paths too, because `Published` is a
/// transfer and a caller that handed four sources over expects four
/// releases. The returned list is a fresh allocation the caller frees with
/// `alloc` and hands to `State.set` as a `Published`.
///
/// Sources are unioned in the order given and the result does not depend on
/// that order: `insert` sorts, so the same set in any order is the same list.
/// That is a claim a test makes rather than an assurance.
pub fn mergePublished(
    alloc: std.mem.Allocator,
    sources: []const Published,
) MergeError!addr.NodeAddr {
    // Released on every path out, and released with each source's own
    // allocator: the caller gave up ownership of all of them on the way in.
    defer for (sources) |held| lookup.releaseTransfer(held);

    var node_id: ?addr.NodeId = null;
    for (sources) |held| {
        const id = held.endpoint.node_id;
        const known = node_id orelse {
            node_id = id;
            continue;
        };
        if (known.order(id) != .eq) return error.MixedNodeIds;
    }
    const id = node_id orelse return error.NoAddresses;

    var merged = addr.NodeAddr.init(id);
    errdefer merged.deinit(alloc);
    for (sources) |held| {
        for (held.endpoint.addrs) |value| {
            // A duplicate is not a failure: `insert` answers null and upstream
            // dedups too, in `EndpointData::new`. Only the allocator's answer is
            // an error.
            merged = (try merged.insert(alloc, value)) orelse merged;
        }
    }
    if (merged.addrs.len == 0) return error.NoAddresses;
    return merged;
}

/// Whether `signer` may sign a record about `node_id`.
///
/// The check `discovery/pkarr_live.zig`'s `publish` makes before it signs,
/// factored out so a caller can ask without building a packet, and so a test
/// can state the rule without a socket and a relay.
///
/// Null means the signer may sign. `error.UnexpectedSigner` otherwise, and it
/// is that arm and not a parse failure: the packet would be well formed and
/// correctly signed by the wrong node, which is the same fault
/// `discovery/pkarr_services.zig`'s resolver reports on the reading side.
pub fn signerRefusal(
    signer: addr.NodeId,
    node_id: addr.NodeId,
) ?error{UnexpectedSigner} {
    if (signer.order(node_id) != .eq) return error.UnexpectedSigner;
    return null;
}

/// Whether `secret` may sign a record about `node_id`, through the key rather
/// than its public half.
///
/// The same rule as `signerRefusal` and named separately because the caller has
/// a `SecretKey` and not a `NodeId`, and reading `secret.nodeId()` into the
/// other function at each call site is a line that can be forgotten.
pub fn signerRefused(
    secret: *const key.SecretKey,
    node_id: addr.NodeId,
) bool {
    return signerRefusal(secret.nodeId(), node_id) != null;
}

const t = std.testing;

fn nodeIdOf(seed: u8) !addr.NodeId {
    return (try key.SecretKey.fromSeed([_]u8{seed} ** key.SecretKey.seed_length)).nodeId();
}

test "the first tick publishes, the next waits out the interval" {
    var state = State.init();
    // Nothing published: not even a publish, because a packet with no records
    // says a name and nothing about the node behind it. The wait is at `now_ms`
    // itself, because "never due" has to be an instant a caller can hold.
    try t.expect(waitOf(state.tick(1_000)) == 1_000);

    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = try nodeIdOf(1);
    state.set(.{
        .alloc = alloc,
        .endpoint = try addr.NodeAddr.withRelay(
            alloc,
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 5,
    });

    // Never attempted, so due immediately.
    try t.expect(isPublish(state.tick(1_000)));
    state.attempted(1_000);
    try t.expect(isWait(state.tick(1_000)));

    // The deadline runs from the attempt, so a millisecond short of it is a wait
    // and the instant itself publishes.
    try t.expect(isWait(state.tick(1_000 + default_republish_interval_ms - 1)));
    state.recordConfirmed();
    try t.expect(isPublish(state.tick(1_000 + default_republish_interval_ms)));
}

test "an unconfirmed publish defers the tick, and does not publish over it" {
    // The module's decision. A pkarr relay's write is last-writer-wins on one
    // key, so a republish over an unconfirmed one can land first and publish
    // the older of the two — which is exactly the stale record the republish
    // exists to replace.
    var state = State.init();
    state.interval_ms = 1_000;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const id = try nodeIdOf(2);
    state.set(.{
        .alloc = arena.allocator(),
        .endpoint = try addr.NodeAddr.withRelay(
            arena.allocator(),
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = null,
    });

    state.attempted(0);
    // Attempted but not yet answered: the tick defers rather than putting a
    // second packet on the wire, and each deferral a caller is told about is
    // one it records.
    try t.expect(isDeferred(state.tick(1_000)));
    state.deferred();
    // And again until the bound: `skip_unconfirmed` is four, so four
    // consecutive deferred ticks are accepted and the tick after them is the
    // one that gives up.
    try t.expect(isDeferred(state.tick(1_000)));
    state.deferred();
    try t.expect(isDeferred(state.tick(1_000)));
    state.deferred();
    try t.expect(isDeferred(state.tick(1_000)));
    state.deferred();
    // Past `skip_unconfirmed` the record is reported as not published, which is
    // what a caller needs to hear so it stops trusting it.
    try t.expect(isStale(state.tick(1_000)));

    // A refusal is the same arm as a lost confirmation: this tick still does not
    // publish.
    state.refused();
    state.deferred_run = 0;
    try t.expect(isDeferred(state.tick(1_000)));

    // Recoverable two ways: a confirmation arrives, or the caller abandons.
    state.recordConfirmed();
    try t.expect(isPublish(state.tick(1_000)));
    state.attempted(1_000);
    state.abandon();
    try t.expect(isPublish(state.tick(1_000)));
}

test "a clock that went backwards waits rather than publishing" {
    var state = State.init();
    state.interval_ms = 1_000;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const id = try nodeIdOf(3);
    state.set(.{
        .alloc = arena.allocator(),
        .endpoint = try addr.NodeAddr.withRelay(
            arena.allocator(),
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = null,
    });
    state.attempted(10_000);
    state.recordConfirmed();
    // `last + interval` cannot be expressed in a `u64` past the maximum, so the
    // deadline saturates and the answer is a wait rather than an instant in the
    // past a caller would obey for ever.
    state.interval_ms = std.math.maxInt(u64);
    try t.expect(isWait(state.tick(10_001)));
    try t.expect(waitOf(state.tick(0)) == std.math.maxInt(u64));
}

test "a replacement is not a republish, and the old slot is released" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = try nodeIdOf(4);

    var state = State.init();
    const published = state.published();
    try t.expect(published == null);

    state.set(.{
        .alloc = alloc,
        .endpoint = try addr.NodeAddr.withRelay(
            alloc,
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 7,
    });
    const held = state.published() orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), held.endpoint.addrs.len);
    try t.expectEqual(@as(?u64, 7), held.last_updated);

    // The timer is untouched by a replacement: the relay's copy of the old value
    // went stale when `set` was called, and the interval is what fixes that.
    state.attempted(1_000);
    state.recordConfirmed();
    state.set(.{
        .alloc = alloc,
        .endpoint = try addr.NodeAddr.withRelay(
            alloc,
            id,
            try addr.RelayUrl.parse("https://two.example./"),
        ),
        .last_updated = 8,
    });
    try t.expect(isWait(state.tick(1_000 + default_republish_interval_ms - 1)));
}

test "several sources merge into one sorted unique list" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = try nodeIdOf(5);
    const relay_one = try addr.RelayUrl.parse("https://one.example./");
    const relay_two = try addr.RelayUrl.parse("https://two.example./");

    // Three sources, overlapping, with a direct address and a duplicate — and
    // the same three in the other order, because the order the sources were
    // given in does not change the answer, which is what makes the fan-in
    // usable at all: a resolve asks its services concurrently and they answer in
    // whatever order they answer in. Each order is built fresh, since a merge
    // consumes the sources it is handed: it releases every one of them.
    var merged: [2]addr.NodeAddr = undefined;
    for (&merged, 0..) |*slot, index| {
        const backwards = index == 1;
        var direct = addr.NodeAddr.init(id);
        direct = (try direct.insert(alloc, .{ .relay = relay_one })) orelse direct;
        direct = (try direct.insert(alloc, .{
            .ip = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4433 },
        })) orelse direct;
        const relay_two_only: Published = .{
            .alloc = alloc,
            .endpoint = try addr.NodeAddr.withRelay(alloc, id, relay_two),
            .last_updated = 1,
        };
        const relay_one_only: Published = .{
            .alloc = alloc,
            .endpoint = try addr.NodeAddr.withRelay(alloc, id, relay_one),
            .last_updated = 2,
        };
        const relay_and_direct: Published = .{
            .alloc = alloc,
            .endpoint = direct,
            .last_updated = 3,
        };
        const sources: [3]Published = if (backwards)
            .{ relay_and_direct, relay_one_only, relay_two_only }
        else
            .{ relay_two_only, relay_one_only, relay_and_direct };
        slot.* = try mergePublished(alloc, &sources);
    }

    // Three distinct addresses from four entries, because the relay was in two
    // sources and `insert` is what deduplicated it.
    try t.expectEqual(@as(usize, 3), merged[0].addrs.len);
    try t.expectEqual(id, merged[0].node_id);
    for (merged[0].addrs, 0..) |value, index| {
        if (index == 0) continue;
        try t.expectEqual(std.math.Order.lt, merged[0].addrs[index - 1].order(value));
    }
    try t.expectEqual(merged[0].addrs.len, merged[1].addrs.len);
    for (merged[0].addrs, merged[1].addrs) |left, right|
        try t.expectEqual(std.math.Order.eq, left.order(right));
}

test "a fan-in refuses mixed nodes and refuses nothing to publish" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const first = try nodeIdOf(6);
    const second = try nodeIdOf(7);

    // Two nodes: publishing B's addresses under A's key makes every resolver
    // believe A is reachable at B, which is the same fault the reading side
    // calls `UnexpectedSigner`.
    const mixed = [_]Published{
        .{
            .alloc = alloc,
            .endpoint = try addr.NodeAddr.withRelay(
                alloc,
                first,
                try addr.RelayUrl.parse("https://one.example./"),
            ),
            .last_updated = null,
        },
        .{
            .alloc = alloc,
            .endpoint = try addr.NodeAddr.withRelay(
                alloc,
                second,
                try addr.RelayUrl.parse("https://two.example./"),
            ),
            .last_updated = null,
        },
    };
    try t.expectError(error.MixedNodeIds, mergePublished(alloc, &mixed));

    // And an empty set has nothing to publish.
    try t.expectError(error.NoAddresses, mergePublished(alloc, &.{}));
    const empty = [_]Published{.{
        .alloc = alloc,
        .endpoint = addr.NodeAddr.init(first),
        .last_updated = null,
    }};
    try t.expectError(error.NoAddresses, mergePublished(alloc, &empty));
}

test "a signer that is not the node's own key is refused" {
    var signer = try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length);
    defer signer.deinit();
    var other = try key.SecretKey.fromSeed([_]u8{2} ** key.SecretKey.seed_length);
    defer other.deinit();

    // The right key signs for its own node.
    try t.expectEqual(
        @as(?error{UnexpectedSigner}, null),
        signerRefusal(signer.nodeId(), signer.nodeId()),
    );
    try t.expect(!signerRefused(&signer, signer.nodeId()));

    // Another node's key is refused, and refused as its own arm rather than as a
    // parse failure: the packet would be well formed and correctly signed.
    try t.expectEqual(
        error.UnexpectedSigner,
        signerRefusal(signer.nodeId(), other.nodeId()).?,
    );
    try t.expect(signerRefused(&signer, other.nodeId()));
}

/// The instant an `Action.wait_until` names, or null for any other arm.
///
/// `Action` is a tagged union with a payload on one arm, so the arms are read
/// through these rather than through `expectEqual` on a bare tag: a tag-only
/// comparison would not check the instant, and a whole-value comparison needs a
/// value that is not a tag.
fn waitOf(action: Action) ?u64 {
    return switch (action) {
        .wait_until => |at| at,
        else => null,
    };
}

/// Whether one tick said "not yet". See `waitOf`.
fn isWait(action: Action) bool {
    return action == .wait_until;
}

/// Whether one tick said "publish now". See `waitOf`.
fn isPublish(action: Action) bool {
    return action == .publish;
}

/// Whether one tick deferred because the last attempt is unconfirmed. See
/// `waitOf`.
fn isDeferred(action: Action) bool {
    return action == .deferred;
}

/// Whether one tick gave up on the record. See `waitOf`.
fn isStale(action: Action) bool {
    return action == .stale;
}
