//! One address claim per peer, held in a bounded cache.
//!
//! A ticket is a claim about how to reach a node, and it is the only thing in
//! this tree that names a node the node has never spoken to: a peer hands one
//! over instead of a connection — `net/holepunch_run_peer.zig` records a
//! `NodeAddr` as what discovery, a ticket and a peer's own announcement all
//! produce — and there is nowhere to put one until this file.
//!
//! **`conn_index.zig` is the other half, and the two answer different
//! questions.** That directory answers "which socket carries this peer" for a
//! peer this node is speaking to; this answers "where might this peer be" for
//! one it is not, and for one it was. A node holding only the first has
//! nothing to dial when the connection ends.
//!
//! **Nothing here is reproduced from the Rust tree, so no upstream line is
//! cited and no interoperability claim is made.** What upstream does is read
//! out of the file this tree has already ported: `ticket/endpoint_ticket.zig`
//! variant 1 is a node id and a list of `TransportAddr` and nothing else, so
//! a ticket carries no sequence, no issue time and no expiry. Every rule
//! below is therefore this tree's rule and not a port — including the two a
//! reader would expect to find upstream and cannot: *which* offer of two is
//! the newer one, and *how long* a claim stays good. Both are decided here by
//! name, on `Put.replaced` and on `ticket_lifetime_s`.
//!
//! **It owns what it holds, so it does take an allocator**, and that is the
//! one place this file departs from `conn_index.zig`'s "allocates nothing": a
//! `NodeAddr` owns one heap list (`base/addr.zig`), so a cache of claims
//! cannot be a value with nothing behind it. The allocator is a parameter of
//! the two calls that release and of no other — `deinit`, and the aged-out
//! drop inside `take`, which frees a claim there is no caller left to hand it
//! to. `put` allocates nothing at all, and `forget` hands the caller what it
//! removed rather than freeing it.

const std = @import("std");
const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");

const Allocator = std.mem.Allocator;

pub const NodeId = base_key.NodeId;
pub const NodeAddr = base_addr.NodeAddr;
pub const RelayUrl = base_addr.RelayUrl;

/// How many claims this node holds at once.
///
/// **A bound is a refusal, and an unbounded cache is a cache whose size a
/// remote peer picks.** Any peer may name any node as reachable, so every new
/// name would be a new slot; `error.NoFreeTicket` is what a node past this
/// sees, and the caller is the only thing that may choose which claim to drop.
///
/// Sixty-four is not this file's number to invent. `gossip/hyparview/bounds.zig`
/// caps the passive view at `max_passive = 64` — the peers a node knows of and
/// is not speaking to — and a claim is exactly a passive peer, held for the
/// moment the node dials it. `conn_index.max_peers` is that file's `max_active`
/// (32) over the same bounds, so the two tables together are a node's active
/// and passive views and nothing wider.
///
/// It is also the memory. A `TransportAddr.relay` inlines a `RelayUrl`, whose
/// `host` is a 253-byte array, so one claim carrying one relay is about 260
/// bytes of heap; sixty-four of them is a fixed 17 KB, and each is an
/// allocation the node made for an address a peer chose. The bound is what
/// caps how many of those a peer can cause, which is why it is a constant and
/// not a growth policy.
pub const max_tickets: usize = 64;

/// How long a claim is offered after the moment it was filed, in seconds on the
/// caller's own clock.
///
/// **A bound and not a field read out of the ticket**, because the ticket has
/// no such field: variant 1 is a node id and an address list. There is no
/// upstream number to copy, and this is the operator's.
///
/// Thirty minutes is reasoned from both ends rather than picked. It must
/// outlast any attempt this tree makes, and the longest scheduled thing here
/// is `net/probe_plan.full_report_interval` at five minutes, so a claim cannot
/// expire inside a dial sequence that was going to succeed. It must not
/// outlast the thing that makes a claim false — a relay whose server has been
/// reassigned, a NAT mapping that has lapsed — and nothing in this tree
/// observes either, so the only sound end is a wall clock an operator can read
/// in a log line and argue with.
///
/// `now_s` is a second on the caller's clock, differenced and never compared
/// against an epoch: `transport/session_store.zig` and
/// `transport/resumption.zig` state that same contract for the same kind of
/// question, and this file adds no clock read of its own.
pub const ticket_lifetime_s: i64 = 30 * 60;

/// Every way the cache refuses an offer.
pub const PutError = error{
    /// The cache holds its bound already and the offer names a peer it does not
    /// hold.
    ///
    /// **Nothing is evicted.** A claim leaves only through `forget`, through
    /// `take` dropping one that has aged out, or through `deinit`, and all
    /// three say which peer. A silent eviction here would drop the address
    /// this node would have dialled for a peer somebody is relying on, and
    /// nothing would report the loss — so the caller gets a refusal it can
    /// count and decide against instead.
    NoFreeTicket,
    /// The offer carries a peer and an address list of zero entries.
    ///
    /// **Refused rather than cached, and the caller keeps the list it
    /// offered.** Both shapes below reach here and neither is invented: a
    /// `NodeAddr.init` is the empty list, and an `EndpointTicket` decoded from
    /// a zero-length variant 1 produces one. Caching it would spend one of
    /// `max_tickets` on a peer there is no way to dial and would then answer
    /// `claim` for it, and it would do that by *replacing* a claim the peer
    /// did have — a downgrade reached by the one input that carries nothing.
    NoPaths,
};

/// What one `put` did.
pub const Put = union(enum) {
    /// The peer had no claim here and owns this one now.
    stored,
    /// The peer's claim was replaced, and this is the address list that was in
    /// it.
    ///
    /// **The newest offer does not win, because nothing here can say which of
    /// two offers is newer.** A ticket is a node id and an address list, so
    /// there is no sequence to compare and no issue time to compare: an offer
    /// that took a slow path arrives after a fresh one and is
    /// indistinguishable from it. The rule is last-offer-wins, and it is
    /// acceptable only because of the two things built around it — the
    /// displaced list is *handed back* rather than freed, so the caller can
    /// see and re-encode what it lost and nothing is dropped in silence, and a
    /// replacement needs no slot, so it is never what refuses a newcomer.
    ///
    /// The other two rules are worse in both directions. Refusing to replace
    /// freezes the one claim a peer has just contradicted, and the only way out
    /// of a frozen claim is `forget`, which needs the caller to already know
    /// the claim was wrong — which is exactly what a stale claim cannot
    /// report. Keeping both is not available at one slot per peer: a second
    /// entry is a second heap list to own and free, and a dialer handed two
    /// claims for one peer has no rule here for choosing between them.
    replaced: NodeAddr,
};

/// A peer's claim, borrowed out of the cache.
pub const Claim = struct {
    /// The peer's addresses. Borrowed from the cache, so it is valid until the
    /// next `put`, `forget` or `deinit` on it — the obligation
    /// `transport/session_store.zig`'s `take` pointer already spells out.
    addr: *const NodeAddr,
    /// How many times this claim had been taken when this one was handed back.
    ///
    /// **Counted and not acted on.** Nothing in this file changes behaviour
    /// on it; it is here so that two callers reaching for one peer leave a
    /// number behind instead of a coincidence of two identical answers. See
    /// `node/ticket_lifecycle.zig` on why a claim is reusable.
    uses: u32,
};

/// What one `take` found.
pub const Taken = union(enum) {
    /// Nothing has ever been filed for this peer. Not the same answer as
    /// `.expired`: one peer was never known to be reachable and the other was
    /// and stopped being reachable, and a caller counting cold dials wants
    /// them apart. `transport/resumption.zig` separates `NoTicket` from
    /// `Expired` for this reason.
    unknown,
    /// The claim was older than `ticket_lifetime_s` and has been dropped, so
    /// its slot is free and this is not a refused lookup.
    expired,
    /// The claim is in the cache and is fresh. Borrowed, and marked used: see
    /// `take`.
    claim: Claim,
};

/// One peer's claim and the two facts this file keeps about it.
pub const Entry = struct {
    /// The peer, which is also the key. It is `addr.node_id`, read off the
    /// address rather than passed beside it: an entry filed under one identity
    /// while holding another's addresses is a cache that dials the wrong node,
    /// and a key argument beside the value is a mistake waiting to be made
    /// once per call site.
    node: NodeId,
    /// The claim: the peer's addresses, and this cache's to release.
    addr: NodeAddr,
    /// The second this claim was filed, on the caller's clock. Freshness is
    /// measured from here and from nowhere else — see `ticket_lifetime_s`.
    stored_s: i64,
    /// How many times the claim has been taken. Saturating rather than
    /// wrapping, because a counter that has wrapped reads low and "taken fewer
    /// times than it was" is a number no caller could act on.
    uses: u32 = 0,
};

/// A bounded map from peer to the last claim filed for it.
///
/// `capacity` is how many peers this one holds, and `TicketCache(max_tickets)`
/// is the one a node builds. Nothing grows: an offer past the bound is
/// `error.NoFreeTicket`, and a peer leaves only through `forget`, through
/// `take` dropping an aged-out claim, or through `deinit`.
///
/// **A peer's position is not its identity.** Entries are held in the order
/// they were first filed and `forget` moves the last entry into the gap, so
/// two caches holding the same peers need not list them the same way.
///
/// **A full cache refuses only peers it does not hold.** A replacement is an
/// update of an entry that exists and needs no slot, so `NoFreeTicket` means
/// exactly what it says and never turns into an eviction.
///
/// **The three ways out are the three ways a claim stops being good**, and
/// each names the peer: a fresher offer replaces it, an age past
/// `ticket_lifetime_s` drops it, and a caller that has proved it false calls
/// `forget`. A claim is never made good by being used, and nothing else is
/// silent.
pub fn TicketCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        // A zero-capacity cache holds nothing and can never hold anything,
        // which is a caller mistake rather than a state to represent, refused
        // here where the mistake is — the reason `conn_index.zig` gives.
        comptime {
            std.debug.assert(capacity > 0);
        }

        /// The claims held, first filed first. Only `[0..len]` is ever read, so
        /// an entry past `len` is `undefined` rather than empty.
        entries: [capacity]Entry = undefined,
        /// How many of `entries` are in use, never a capacity.
        len: usize = 0,

        /// An empty cache. Its storage is inline, so there is nothing to
        /// release here; `deinit` is for the claims it was given.
        pub fn init() Self {
            return .{};
        }

        /// Free every claim still held, and nothing else.
        ///
        /// **This is one of the two calls that free**, the other being the
        /// aged-out drop inside `take`. `forget` and `Put.replaced` hand the
        /// list back instead, so an address leaves on this cache's behalf only
        /// when there is no caller left who might still want to read it. It is
        /// `NodeAddr.deinit` per entry: the outer list and nothing else,
        /// because a `.custom` payload inside it is a borrow whoever parsed it
        /// and `base/addr.zig` is where that obligation is stated.
        ///
        /// `len` goes to zero, so a second call frees nothing rather than
        /// freeing twice. Everything borrowed from the cache — a `Claim`, and
        /// any slice taken from one — is invalid afterward.
        pub fn deinit(self: *Self, alloc: Allocator) void {
            for (self.entries[0..self.len]) |*entry| entry.addr.deinit(alloc);
            self.len = 0;
        }

        /// How many peers have a claim here.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The claim for `peer`, whether it is fresh, and mark it used.
        ///
        /// `alloc` releases a claim this call drops — an aged-out one — and is
        /// reached on no other answer.
        ///
        /// **Used is not consumed.** The claim stays in the cache and stays
        /// answerable however many times it is taken; this counts rather than
        /// removes. The address of a peer does not change because this node
        /// dialled it, and a one-shot claim would leave the *retry* of a dial
        /// with nothing to retry with — while the retry is the normal case,
        /// since `net/holepunch_gate.retry_interval` exists to repeat a round
        /// this stack refused. Consuming on use is also what makes two callers
        /// racing for one peer disagree for no reason: the second would get
        /// `unknown` and could not tell "this peer is unreachable" from "I
        /// lost a race", which is a hole in the cache with nothing behind it.
        /// The count is what makes that race visible instead.
        ///
        /// **An aged-out claim is dropped, not answered.** It is freed and the
        /// slot goes with it, so the next offer for that peer is a `stored`
        /// rather than a refusal at a bound this node had already reached.
        /// That is `transport/session_store.zig`'s rule for an expired session
        /// ticket, and the reason is the same: handing a stale claim back
        /// spends a dial on an address that was already known not to work.
        /// Unlike `forget` there is no caller to hand it to instead — this
        /// answer learned nothing and was asked for a claim, so the list goes
        /// back to the allocator here rather than to the caller.
        pub fn take(self: *Self, peer: NodeId, now_s: i64, alloc: Allocator) Taken {
            const index = self.indexOf(peer) orelse return .unknown;
            if (!isFresh(self.entries[index], now_s)) {
                self.dropAt(index).deinit(alloc);
                return .expired;
            }
            self.entries[index].uses +|= 1;
            const entry = &self.entries[index];
            return .{ .claim = .{ .addr = &entry.addr, .uses = entry.uses } };
        }

        /// File `addr` as the claim for the peer it names.
        ///
        /// `addr` is taken over: on `stored` or on `replaced` this cache owns
        /// it, and releases it through `forget`, through `deinit`, or by being
        /// replaced again — exactly the contract `BlobTicket.new` states for the
        /// list it takes. On either refusal the caller still owns it and must
        /// free it; nothing was allocated and the cache is unchanged.
        ///
        /// Nothing is allocated here, which is why there is no allocator on
        /// this signature: the list was built by whoever decoded the ticket,
        /// and this file moves the handle.
        pub fn put(self: *Self, addr: NodeAddr, now_s: i64) PutError!Put {
            // Checked before the peer is looked up, so a replacement cannot
            // trade a working claim for an empty one.
            if (addr.addrs.len == 0) return error.NoPaths;
            const node = addr.node_id;
            if (self.indexOf(node)) |index| {
                const displaced = self.entries[index].addr;
                self.entries[index] = .{
                    .node = node,
                    .addr = addr,
                    .stored_s = now_s,
                };
                return .{ .replaced = displaced };
            }
            if (self.len == capacity) return error.NoFreeTicket;
            self.entries[self.len] = .{ .node = node, .addr = addr, .stored_s = now_s };
            self.len += 1;
            return .stored;
        }

        /// Drop `peer`'s claim and hand the address list back, whether it was
        /// there.
        ///
        /// **This does not free.** The caller owns what comes out of it and
        /// releases it with `NodeAddr.deinit(alloc)`, which keeps the one
        /// freeing call in this file to `deinit` and lets a caller that
        /// discards a falsified claim re-encode it before it goes.
        ///
        /// A peer that had no claim is null and drops nothing, which is what
        /// makes a path that discards twice — once on a failed dial, once on
        /// the disconnect — harmless.
        pub fn forget(self: *Self, peer: NodeId) ?NodeAddr {
            const index = self.indexOf(peer) orelse return null;
            return self.dropAt(index);
        }

        /// Where `peer` is, or null for a peer this cache does not hold.
        ///
        /// A scan and not a hash, for `conn_index.zig`'s reason: the cache is
        /// `capacity` entries and a node id is 32 bytes, so a lookup costs far
        /// less than the dial its answer decides, and the loop is bounded by
        /// the storage it walks. There is no tombstone either, for the reason
        /// `topic_table.zig` gives: the bound on probing iterations is this
        /// table's `len`.
        fn indexOf(self: *const Self, peer: NodeId) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.node.order(peer) == .eq) return index;
            }
            return null;
        }

        /// Take the entry at `index` out and answer with the claim it held.
        /// `index` must be in `[0..len)`, and the slot it frees is closed with
        /// the last entry, so this is the only place a gap is made.
        fn dropAt(self: *Self, index: usize) NodeAddr {
            const gone = self.entries[index].addr;
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return gone;
        }
    };
}

/// Whether `entry`'s claim is still offered, on a clock reading `now_s`.
///
/// **Fail closed on a clock that moved back.** `now_s - stored_s` is
/// negative then, and read as an age that is the freshest claim in the table;
/// nothing downstream could tell. A claim this node cannot age is a claim it
/// does not offer. After this check the subtraction cannot overflow, because
/// `now_s` is the larger of the two.
fn isFresh(entry: Entry, now_s: i64) bool {
    if (now_s < entry.stored_s) return false;
    return now_s - entry.stored_s <= ticket_lifetime_s;
}

// --- tests

const t = std.testing;
const node_test_ids = @import("node_test_ids.zig");

/// The host each claim's relay is filed under, in the canonical form
/// `base/relay.zig` requires of a name that is not an IP literal.
const host_a = "relay-a.example.";
const host_b = "relay-b.example.";
/// The URLs those hosts are dialled at. Two of them, so an offer can move a
/// peer from one relay to another and a test can tell which it did.
const relay_a = "https://" ++ host_a;
const relay_b = "https://" ++ host_b;

/// A node id and one relay: the smallest claim that can be dialled.
fn claimAddress(alloc: Allocator, seed: u8, url: []const u8) !NodeAddr {
    const node = try node_test_ids.testNodeId(seed);
    return NodeAddr.withRelay(alloc, node, try RelayUrl.parse(url));
}

/// The host of the one relay in `node`'s list, borrowed from `node` itself.
///
/// Switched through a pointer and captured by pointer: a payload captured out
/// of a value copy is a local, and the slice into it would be dead the moment
/// this returned.
fn relayHost(node: *const NodeAddr) ![]const u8 {
    try t.expectEqual(@as(usize, 1), node.addrs.len);
    const one = &node.addrs[0];
    return switch (one.*) {
        .relay => |*url| url.hostSlice(),
        else => error.NotARelay,
    };
}

test "a filed claim is found by the peer it names and an unfiled peer has none" {
    // `TicketCache` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    // An unknown peer and an empty cache both answer `unknown`, and neither
    // spends a slot.
    try t.expectEqual(@as(usize, 0), cache.count());
    const stranger = try node_test_ids.testNodeId(1);
    try t.expectEqual(Taken.unknown, cache.take(stranger, 0, t.allocator));

    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 1, relay_a),
        0,
    ));
    try t.expectEqual(@as(usize, 1), cache.count());

    // The claim answers under the peer its own `node_id` names, and carries the
    // address that was offered rather than a neighbour's.
    const taken = switch (cache.take(stranger, 10, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    try t.expectEqualStrings(host_a, try relayHost(taken.addr));
    // A claim is marked used, not consumed: the second take is the same claim.
    try t.expectEqual(@as(u32, 1), taken.uses);
    const again = switch (cache.take(stranger, 11, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    try t.expectEqual(@as(u32, 2), again.uses);
    try t.expectEqual(@as(usize, 1), cache.count());
}

test "a second offer for one peer replaces its claim and hands the old one back" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(2);
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 2, relay_a),
        0,
    ));

    // The peer's address legitimately changes, so the offer replaces rather
    // than refuses — and what it replaced comes back to the caller instead of
    // being freed in silence, which is the whole of "last offer wins".
    const put = try cache.put(try claimAddress(t.allocator, 2, relay_b), 60);
    const displaced = switch (put) {
        .replaced => |addr| addr,
        .stored => return error.NotAReplacement,
    };
    defer displaced.deinit(t.allocator);
    try t.expectEqualStrings(host_a, try relayHost(&displaced));

    // One entry, the new address, and a claim counted from the new offer.
    try t.expectEqual(@as(usize, 1), cache.count());
    const taken = switch (cache.take(peer, 61, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    try t.expectEqualStrings(host_b, try relayHost(taken.addr));
    try t.expectEqual(@as(u32, 1), taken.uses);
}

test "an offer naming no address is refused and the claim it would have replaced stands" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(3);
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 3, relay_a),
        0,
    ));

    // The empty list is what `NodeAddr.init` produces and what a zero-length
    // variant 1 ticket decodes to, so it is an input and not a shape. A peer
    // that had a claim cannot trade it for one that says nothing.
    try t.expectError(error.NoPaths, cache.put(NodeAddr.init(peer), 10));
    // The caller still owns what it offered: the refusal allocated nothing.
    const taken = switch (cache.take(peer, 11, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    try t.expectEqualStrings(host_a, try relayHost(taken.addr));
    try t.expectEqual(@as(usize, 1), cache.count());
}

test "a claim ages out from the moment it was filed and a use does not renew it" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(4);
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 4, relay_a),
        100,
    ));

    // Fresh just inside the lifetime, and the use does not move the filing
    // time: a claim this node just dialled and failed on is as old as it was.
    const used = switch (cache.take(peer, 100 + ticket_lifetime_s, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    try t.expectEqual(@as(u32, 1), used.uses);

    // One second later it is gone, and gone means gone: the slot is free, so
    // the next ask is a cold one rather than a second expiry.
    try t.expectEqual(Taken.expired, cache.take(peer, 101 + ticket_lifetime_s, t.allocator));
    try t.expectEqual(@as(usize, 0), cache.count());
    try t.expectEqual(Taken.unknown, cache.take(peer, 102 + ticket_lifetime_s, t.allocator));

    // The slot the drop freed is one the next offer can take.
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 4, relay_b),
        200,
    ));
    try t.expectEqual(@as(usize, 1), cache.count());
}

test "a claim stamped in the future is not a fresh one" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(5);
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 5, relay_a),
        10_000,
    ));

    // A clock that moved back leaves the age negative, and a negative age read
    // as fresh would make this the youngest claim in the cache. Fail closed
    // instead: the node cannot say how old it is, so it does not offer it.
    try t.expectEqual(Taken.expired, cache.take(peer, 0, t.allocator));
    try t.expectEqual(@as(usize, 0), cache.count());
}

test "a full cache refuses a peer it does not hold and keeps every claim it had" {
    // The production bound, so the number the operator picks is the one under
    // test, and it is pinned because it is the answer to "how many claims does
    // this node hold" and that answer must not drift silently.
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(max_tickets);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);
    try t.expectEqual(@as(usize, 64), max_tickets);

    for (0..max_tickets) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expectEqual(Put.stored, try cache.put(
            try claimAddress(t.allocator, seed, relay_a),
            0,
        ));
    }
    try t.expectEqual(@as(usize, max_tickets), cache.count());

    // One peer past the bound is refused, and the refusal is an error the
    // caller can count rather than an eviction it has to detect.
    const stranger = try node_test_ids.testNodeId(200);
    // A refusal takes nothing and allocates nothing, so the offer is still the
    // caller's: `put` takes the list over on a filing and on nothing else.
    const refused = try claimAddress(t.allocator, 200, relay_b);
    defer refused.deinit(t.allocator);
    try t.expectError(error.NoFreeTicket, cache.put(refused, 10));
    try t.expectEqual(@as(usize, max_tickets), cache.count());
    try t.expectEqual(Taken.unknown, cache.take(stranger, 10, t.allocator));

    // Every peer already held still answers with its own claim.
    for (0..max_tickets) |offset| {
        const seed: u8 = @intCast(offset + 1);
        switch (cache.take(try node_test_ids.testNodeId(seed), 10, t.allocator)) {
            .claim => |claim| {
                try t.expectEqualStrings(host_a, try relayHost(claim.addr));
            },
            else => return error.NotAClaim,
        }
    }

    // A replacement needs no slot, so a full cache refuses only peers it does
    // not hold: the claim moves and the count does not change.
    const held = try node_test_ids.testNodeId(1);
    const replaced = switch (try cache.put(
        try claimAddress(t.allocator, 1, relay_b),
        10,
    )) {
        .replaced => |addr| addr,
        .stored => return error.NotAReplacement,
    };
    replaced.deinit(t.allocator);
    try t.expectEqual(@as(usize, max_tickets), cache.count());

    // One departure frees exactly one slot, for exactly one arrival: the
    // refusal above was not a queue.
    const gone = (cache.forget(held) orelse return error.NotForgotten);
    gone.deinit(t.allocator);
    try t.expectEqual(Put.stored, try cache.put(
        try claimAddress(t.allocator, 200, relay_b),
        10,
    ));
    try t.expectEqual(@as(usize, max_tickets), cache.count());
}

test "a forgotten claim is gone and the claims around it are not" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(3);
    var cache = Cache.init();
    defer cache.deinit(t.allocator);

    for (1..4) |offset| {
        const seed: u8 = @intCast(offset);
        try t.expectEqual(Put.stored, try cache.put(
            try claimAddress(t.allocator, seed, relay_a),
            0,
        ));
    }

    // The middle peer now claims a different relay, so the claim that leaves
    // below is one the test can name rather than one of three alike.
    const replaced = switch (try cache.put(
        try claimAddress(t.allocator, 2, relay_b),
        0,
    )) {
        .replaced => |addr| addr,
        .stored => return error.NotAReplacement,
    };
    replaced.deinit(t.allocator);

    // The removed claim comes back to the caller rather than being freed here,
    // so a caller that proved a claim false can still read it before it goes.
    const gone = cache.forget(try node_test_ids.testNodeId(2)) orelse
        return error.NotForgotten;
    defer gone.deinit(t.allocator);
    try t.expectEqualStrings(host_b, try relayHost(&gone));
    try t.expectEqual(@as(usize, 2), cache.count());

    // Both of the others still answer with their own claim, whichever slot
    // each of them sits in: `forget` closes the gap with the last entry and
    // drops nothing else.
    for ([_]u8{ 1, 3 }) |seed| {
        switch (cache.take(try node_test_ids.testNodeId(seed), 1, t.allocator)) {
            .claim => |claim| try t.expectEqualStrings(host_a, try relayHost(claim.addr)),
            else => return error.NotAClaim,
        }
    }

    // A peer that was never held drops nothing, which is what makes a path
    // that discards twice harmless.
    try t.expectEqual(@as(?NodeAddr, null), cache.forget(try node_test_ids.testNodeId(2)));
    try t.expectEqual(@as(usize, 2), cache.count());
}

test "deinit frees every claim held and a second call frees nothing" {
    // zwanzig-disable-next-line: identifier-style
    const Cache = TicketCache(4);
    var cache = Cache.init();

    for (1..3) |offset| {
        const seed: u8 = @intCast(offset);
        try t.expectEqual(Put.stored, try cache.put(
            try claimAddress(t.allocator, seed, relay_a),
            0,
        ));
    }

    // `t.allocator` fails the test for any list this did not release, and the
    // second call is the half that proves the first did not over-release: `len`
    // is zero, so there is nothing left to walk.
    cache.deinit(t.allocator);
    cache.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), cache.count());
}
