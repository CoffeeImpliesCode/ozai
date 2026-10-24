//! What a caller does with a claim: use it, or drop it once it is proved false.
//! Refresh is `ticket_cache.put`, and this file says why it is not a method.
//!
//! `ticket_cache.zig` owns a claim and every rule about a claim's own state —
//! what replaces one, what ages one out, what refuses one. What it cannot know
//! is whether this node is already speaking to the peer a claim is about, so
//! it has no answer to the question that comes before all of them: is a claim
//! needed at all? That question is asked here against `conn_index.zig`, and
//! this file is the seam between the two.
//!
//!
//! **Nothing here opens a socket, reads a clock or allocates.** `now_s` is a
//! second on the caller's own clock and is only ever differenced inside the
//! cache; the connection directory is borrowed read-only and never written
//! through, because a connection belongs to the transport and not to a claim.
//! The one allocator this file carries is the one `use` hands the cache to
//! release a claim that has aged out, and it is the allocator `deinit` takes:
//! releasing is not allocating, and there is no third owner here.
const std = @import("std");
const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");
const conn_index = @import("conn_index.zig");
const ticket_cache = @import("ticket_cache.zig");

const Allocator = std.mem.Allocator;

pub const NodeId = base_key.NodeId;
pub const NodeAddr = base_addr.NodeAddr;
pub const RelayUrl = base_addr.RelayUrl;

/// The core's number for the connection a peer is spoken on. Re-exported so a
/// caller of this file names one module for the plan it acts on.
pub const ConnId = conn_index.ConnId;

/// A peer's claim, borrowed out of the cache. `ticket_cache.Claim` under this
/// file's own name: the same decl, not a wrapper.
pub const Claim = ticket_cache.Claim;
/// What a refresh did. `ticket_cache.Put`, for the same reason.
pub const Put = ticket_cache.Put;
/// Every way filing a claim refuses an offer. `ticket_cache.PutError`.
pub const PutError = ticket_cache.PutError;

/// What one `use` found.
pub const Plan = union(enum) {
    /// This node is already speaking to the peer: dial this connection.
    ///
    /// **The cache was not asked.** A claim is a guess about a socket, and a
    /// node holding the socket is not guessing; more to the point, asking
    /// would have spent the claim, and a borrowed answer would have a lifetime
    /// the connection does not have. The other three arms are what the cache
    /// says; this one leaves the cache exactly as it was, counted and unspent.
    connected: ConnId,
    /// The peer's claim is fresh and is borrowed here. Marked used, not
    /// consumed: see `Lifecycle.use` and `ticket_cache.take`.
    claim: Claim,
    /// Nothing has ever been filed for this peer and it is not connected.
    ///
    /// Not the same answer as `.expired`: this peer was never known to be
    /// reachable and that one was and stopped being reachable, and a caller
    /// counting cold dials wants them apart. `transport/resumption.zig`
    /// separates `NoTicket` from `Expired` for the same reason.
    unknown,
    /// The claim aged past `ticket_cache.ticket_lifetime_s`, was dropped, and
    /// freed its slot. This is a lookup that found nothing *after having found
    /// something*, and the peer has to be rediscovered.
    expired,
};

/// What one `discard` did.
pub const Discarded = union(enum) {
    /// The claim was dropped and this is what was in it. The caller owns it
    /// now and releases it with `NodeAddr.deinit(alloc)`.
    ///
    /// The list comes back rather than being freed, for the reason
    /// `ticket_cache.forget` gives: a caller that has just proved a claim
    /// false usually wants to read it once more — to log it, or to hand it to
    /// the layer that asks its peer where it went.
    dropped: NodeAddr,
    /// This node is speaking to the peer, so the claim was left alone.
    ///
    /// **A live connection is evidence *against* the claim being false**, not
    /// for it: nothing falsified a claim about a peer this node is reaching
    /// right now. Refusing here is what stops a failed send on a healthy
    /// connection from deleting the address that connection would be re-dialled
    /// on — a deletion nothing would report, because the caller that made it
    /// believed it had proved something.
    connected: ConnId,
    /// There was no claim to drop. A discard that runs twice — once on a failed
    /// dial, once on the disconnect — costs nothing the second time.
    unknown,
};

/// A node's claims, beside the connections it already holds.
///
/// `peers` is the connection bound and `Lifecycle(conn_index.max_peers)` is
/// the one a node builds. The two are separate numbers on purpose: `use` reads
/// the directory and the cache, and a node with thirty-two connections still
/// wants claims for peers it has never dialled.
///
/// **The claim cache is held by value.** Its storage is inline and sized by
/// `ticket_cache.max_tickets`, so there is no second owner, no allocator to
/// construct one, and a copied `Lifecycle` is an independent snapshot of the
/// same shape rather than an alias. Only the claims themselves are on the
/// heap, which is what `deinit` is for.
///
/// **The connection directory is borrowed and never written through.** A
/// connection is the transport's, this file asks it one question, and a
/// lifecycle that could remove a connection would be a second thing that can
/// close a socket.
pub fn Lifecycle(comptime peers: usize) type {
    return struct {
        const Self = @This();

        /// The claims this lifecycle holds. Named so a caller can build the
        /// cache type without naming `ticket_cache`, and so `Self.Cache` reads
        /// as the type of the `cache` field rather than as a second cache.
        pub const Cache: type = ticket_cache.TicketCache(ticket_cache.max_tickets);
        /// How many peers the connection directory this lifecycle reads holds.
        /// Named because it is the bound the caller passed, and a caller
        /// building a lifecycle wants to read it back rather than repeat it.
        pub const peers_max = peers;

        /// The claims. Inline and sized by `ticket_cache.max_tickets`, so a
        /// lifecycle owns its own storage and there is no allocator to
        /// construct one with.
        cache: Cache,

        /// The node's connections, borrowed.
        conns: *const conn_index.ConnIndex(peers),

        /// A lifecycle over `conns`, holding no claims yet.
        pub fn init(conns: *const conn_index.ConnIndex(peers)) Self {
            return .{ .cache = Cache.init(), .conns = conns };
        }

        /// Free every claim still held, and nothing else. See
        /// `ticket_cache.deinit`: this is one of the two calls that free on the
        /// cache's behalf, the other being the aged-out drop `use` asks for,
        /// and it is safe to run twice.
        ///
        /// The borrowed connection directory is untouched, and this lifecycle
        /// must not be used afterward.
        pub fn deinit(self: *Self, alloc: Allocator) void {
            self.cache.deinit(alloc);
        }

        /// How the peer at `peer` should be reached now.
        ///
        /// **The connection is asked first, and it is the whole of this
        /// method's reason to exist.** A ticket is a claim about how to reach a
        /// node, and a claim is not needed when the node is already reached; a
        /// connection is strictly better evidence than an address, because it
        /// is the thing itself rather than a description of it. So a peer with
        /// a live connection never reaches the cache, and the cache learns
        /// nothing from such a peer — no use counted, no slot spent.
        ///
        /// **Using a claim marks it and does not consume it, and the two
        /// designs differ exactly where two callers meet.** A one-shot claim
        /// hands the first caller the address and the second caller nothing,
        /// so the second cannot tell "this peer is unreachable" from "I lost a
        /// race" — a hole with nothing behind it, and a node that
        /// rediscovers a peer it was told about a moment ago. The cache answers
        /// both callers with the same borrowed claim and counts the takes, so
        /// the race shows up as `Claim.uses == 2` rather than as two
        /// disagreeing dials. Consuming would also be wrong on the retry,
        /// which is the ordinary case: `net/holepunch_gate.retry_interval`
        /// exists to repeat a round the stack refused, and a second round with
        /// no claim left is a round that has to start over.
        ///
        /// `alloc` releases a claim the cache drops on the way through — an
        /// aged-out one — and is reached on no other answer, so it is the same
        /// allocator `deinit` takes rather than a third one.
        ///
        /// An aged-out claim is dropped by the cache on the way through, so
        /// `.expired` frees a slot and a second ask is `.unknown`.
        pub fn use(self: *Self, peer: NodeId, now_s: i64, alloc: Allocator) Plan {
            if (self.conns.connFor(peer)) |conn| return .{ .connected = conn };
            return switch (self.cache.take(peer, now_s, alloc)) {
                .unknown => .unknown,
                .expired => .expired,
                .claim => |claim| .{ .claim = claim },
            };
        }

        /// Drop `peer`'s claim because it has been proved false, and answer
        /// what became of it.
        ///
        /// **A connected peer's claim is not dropped**, and the reason is on
        /// `Discarded.connected`: the only evidence this file has that a claim
        /// is false is a dial on it that failed, and a node holding a live
        /// connection to that peer has just contradicted it.
        ///
        /// This is the only way a caller retires a claim ahead of its lifetime,
        /// and it is explicit and named for the reason `conn_index.remove` is:
        /// a claim that quietly left would be a peer this node can no longer
        /// dial, with nothing having said so.
        pub fn discard(self: *Self, peer: NodeId) Discarded {
            if (self.conns.connFor(peer)) |conn| return .{ .connected = conn };
            return if (self.cache.forget(peer)) |addr| .{ .dropped = addr } else .unknown;
        }
    };
}

// --- tests

const t = std.testing;
const node_test_ids = @import("node_test_ids.zig");

/// The host a claim is filed under, in the canonical form `base/relay.zig`
/// requires of a name that is not an IP literal.
const host_a = "relay-a.example.";
/// The URL it is dialled at.
const relay_a = "https://" ++ host_a;

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

test "a peer this node is speaking to is dialed and its claim is not touched" {
    // Both factories are generic: a binding that holds the struct type they
    // return is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(2);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(2);
    var index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(1);
    _ = try index.bind(peer, 10);
    try t.expectEqual(Put.stored, try life.cache.put(
        try claimAddress(t.allocator, 1, relay_a),
        0,
    ));

    const conn = switch (life.use(peer, 10, t.allocator)) {
        .connected => |answer| answer,
        else => return error.NotConnected,
    };
    try t.expectEqual(@as(ConnId, 10), conn);

    // The claim is untouched: still filed, and not yet counted as used. The
    // connection answered the question, so the cache was never reached — which
    // is the whole of what a connected peer costs the cache.
    try t.expectEqual(@as(usize, 1), life.cache.count());
    _ = index.remove(peer);
    switch (life.use(peer, 11, t.allocator)) {
        .claim => |claim| try t.expectEqual(@as(u32, 1), claim.uses),
        else => return error.NotAClaim,
    }
}

test "a peer that was never filed and a peer whose claim aged out are two answers" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(2);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(2);
    const index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(2);
    try t.expectEqual(Plan.unknown, life.use(peer, 0, t.allocator));
    try t.expectEqual(Put.stored, try life.cache.put(
        try claimAddress(t.allocator, 2, relay_a),
        100,
    ));

    // Fresh inside the lifetime: the claim and the connection between them.
    switch (life.use(peer, 100 + ticket_cache.ticket_lifetime_s, t.allocator)) {
        .claim => |claim| try t.expectEqualStrings(host_a, try relayHost(claim.addr)),
        else => return error.NotAClaim,
    }

    // One second later the claim is gone, and gone means the slot went with it:
    // the next ask is a cold one rather than a second expiry of nothing.
    try t.expectEqual(
        Plan.expired,
        life.use(peer, 101 + ticket_cache.ticket_lifetime_s, t.allocator),
    );
    try t.expectEqual(@as(usize, 0), life.cache.count());
    try t.expectEqual(
        Plan.unknown,
        life.use(peer, 102 + ticket_cache.ticket_lifetime_s, t.allocator),
    );
}

test "two callers reaching for one peer both get it and the second use is counted" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(2);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(2);
    const index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(3);
    try t.expectEqual(Put.stored, try life.cache.put(
        try claimAddress(t.allocator, 3, relay_a),
        0,
    ));

    const first = switch (life.use(peer, 10, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };
    const second = switch (life.use(peer, 11, t.allocator)) {
        .claim => |claim| claim,
        else => return error.NotAClaim,
    };

    // Both callers hold the same borrowed address, and the second is told it
    // was the second. A one-shot claim would have given the first the address
    // and the second nothing at all, with no way for the second to tell that
    // apart from the peer being unreachable.
    try t.expectEqual(@as(u32, 1), first.uses);
    try t.expectEqual(@as(u32, 2), second.uses);
    try t.expectEqualStrings(host_a, try relayHost(first.addr));
    try t.expectEqualStrings(host_a, try relayHost(second.addr));
    try t.expectEqual(@as(usize, 1), life.cache.count());
}

test "a claim is dropped by discard and the claims around it are not" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(4);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(4);
    const index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    for (1..4) |offset| {
        const seed: u8 = @intCast(offset);
        try t.expectEqual(Put.stored, try life.cache.put(
            try claimAddress(t.allocator, seed, relay_a),
            0,
        ));
    }

    // The claim comes back to the caller, which frees it here: `discard` does
    // not free on the caller's behalf, so a falsified claim can be read once
    // more before it goes.
    const gone = switch (life.discard(try node_test_ids.testNodeId(2))) {
        .dropped => |addr| addr,
        else => return error.NotDiscarded,
    };
    try t.expectEqualStrings(host_a, try relayHost(&gone));
    gone.deinit(t.allocator);
    try t.expectEqual(@as(usize, 2), life.cache.count());

    // The peers on either side of the gap still answer with their own claims,
    // and the discarded one answers as a peer that was never filed.
    for ([_]u8{ 1, 3 }) |seed| {
        switch (life.use(try node_test_ids.testNodeId(seed), 1, t.allocator)) {
            .claim => |claim| try t.expectEqualStrings(host_a, try relayHost(claim.addr)),
            else => return error.NotAClaim,
        }
    }
    try t.expectEqual(Plan.unknown, life.use(try node_test_ids.testNodeId(2), 1, t.allocator));

    // A second discard of the same peer costs nothing, which is what makes a
    // path that discards on a failed dial and again on the disconnect safe.
    try t.expectEqual(Discarded.unknown, life.discard(try node_test_ids.testNodeId(2)));
    try t.expectEqual(@as(usize, 2), life.cache.count());
}

test "discard leaves a peer's claim alone while this node is speaking to it" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(2);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(2);
    var index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(4);
    try t.expectEqual(Put.stored, try life.cache.put(
        try claimAddress(t.allocator, 4, relay_a),
        0,
    ));
    _ = try index.bind(peer, 20);

    // Nothing falsified this claim: the peer is being reached right now. The
    // discard is refused and names the connection that is the better evidence.
    const refused = switch (life.discard(peer)) {
        .connected => |conn| conn,
        else => return error.NotRefused,
    };
    try t.expectEqual(@as(ConnId, 20), refused);

    // The refused discard dropped nothing: once the connection is gone the
    // claim is still there, unchanged and still dialled at the same relay.
    _ = index.remove(peer);
    const gone = switch (life.discard(peer)) {
        .dropped => |addr| addr,
        else => return error.NotDiscarded,
    };
    try t.expectEqualStrings(host_a, try relayHost(&gone));
    gone.deinit(t.allocator);
}

test "an offer for a connected peer is kept, because the connection ends first" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(2);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(2);
    var index = Index.init();
    var life = Life.init(&index);
    defer life.deinit(t.allocator);

    const peer = try node_test_ids.testNodeId(5);
    _ = try index.bind(peer, 30);

    // `use` skips the cache for a connected peer; `put` does not, and that is
    // the other half of the answer. A claim filed now is the one the next dial
    // uses, and the connection that made it worth filing is temporary while the
    // claim is not. Refusing it would spend the offer on nothing.
    try t.expectEqual(Put.stored, try life.cache.put(
        try claimAddress(t.allocator, 5, relay_a),
        0,
    ));
    try t.expectEqual(@as(usize, 1), life.cache.count());

    _ = index.remove(peer);
    switch (life.use(peer, 10, t.allocator)) {
        .claim => |claim| try t.expectEqualStrings(host_a, try relayHost(claim.addr)),
        else => return error.NotAClaim,
    }
}

test "a lifecycle frees every claim it still holds and a second call frees nothing" {
    // zwanzig-disable-next-line: identifier-style
    const Index = conn_index.ConnIndex(4);
    // zwanzig-disable-next-line: identifier-style
    const Life = Lifecycle(4);
    const index = Index.init();
    var life = Life.init(&index);

    for (1..3) |offset| {
        const seed: u8 = @intCast(offset);
        try t.expectEqual(Put.stored, try life.cache.put(
            try claimAddress(t.allocator, seed, relay_a),
            0,
        ));
    }

    // `t.allocator` fails the test for any list left behind, and the second
    // call is the half that proves the first did not release one twice. The
    // borrowed connection directory is not this file's to free.
    life.deinit(t.allocator);
    life.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), life.cache.count());
}
