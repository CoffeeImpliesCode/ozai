//! Which peers a blob can be fetched from, and what a fetch may conclude from
//! that list.
//!
//! `blobs/blob_set.zig` answers "which blobs does this node know", and the
//! other half of a fetch is here: given a hash, which peers to ask. This is
//! the blobs-protocol twin of `node/topic_table.zig`, which answers the same
//! question for a topic — one bounded key maps to a bounded list of peers, a
//! join past either bound is refused rather than admitted by dropping a live
//! entry, and one call takes a departing peer out of every list at once. The
//! bound-and-refuse shape is the same on purpose; the difference is in what a
//! name in the list means, and that difference is the whole of this file.
//!
//! # An advertisement is not a promise, and it cannot become one
//!
//! **A peer here is somewhere to ask. It is never the source.** Nothing a
//! peer says about what it holds can be checked from what it says, because the
//! protocol has exactly one way to take a blob back: `provider.zig` writes
//! nothing and closes. Zero bytes carry exactly one meaning, and it is the
//! meaning `getter.zig` already reads as a refusal and never as a completion —
//! the same bytes are what a provider with no such blob sends and what an empty
//! blob is answered with.
//!
//! So a peer that named a blob and then does not serve it has contradicted
//! nothing. It has said nothing, in the only way the wire lets it say nothing.
//! Every consequence below follows from taking that seriously:
//!
//! 1. **Nothing here turns a claim into a fact.** There is no method that
//!    returns "the peer that has this blob", because no such peer has been
//!    identified. `holders` hands back a candidate list, and a caller that
//!    treats it as a guarantee has promoted a peer's word over a verifier —
//!    which is the mistake `getter.zig` refuses to make about bytes, promoted
//!    one layer up to a peer.
//! 2. **Nothing here drops a holder on its own.** `release` is the fetcher's
//!    and it is called by name, after the fetch observed the refusal — an
//!    answer `getter.Outcome` refused, which includes the empty answer. A
//!    table that guessed when to drop a peer would drop peers that were merely
//!    slow, and would drop them without saying so; a peer that advertised a
//!    blob and is asked again later is still worth asking, which is why the
//!    answer to a refusal is "ask the next one", not "stop asking anybody".
//! 3. **A disconnect is the one thing that removes a peer by itself.**
//!    `removePeer` is one call across every list, for `topic_table.zig`'s
//!    reason: a peer left in one route is a node that will still ask a closed
//!    connection, and a caller that has to remember which blobs a peer was in
//!    is a caller that will forget one.
//!
//! The fetcher's rule, then, in one line: ask each holder in turn, and on any
//! refusal call `release` for that peer and go to the next; when `holders` is
//! empty the blob is unobtainable from what this node knows, and the hash stays
//! `.seen` in a `BlobSet` — never `.verified`, because no bytes arrived.
//!
//! # No eviction, and not the narrow one either
//!
//! Both bounds refuse. `path_table.zig` takes one narrow exception, displacing
//! a path recorded as `.unusable`, and it can take it because a failure is a
//! field it reads off the path itself. **A failed fetch is not such a field:**
//! it is something one caller observed on one exchange and nobody else can see,
//! so this table has no way to evaluate it. Evicting on a rule it cannot
//! evaluate would shed a peer nobody said to shed, and a peer is exactly the
//! thing a fetch cannot replace — it is the other end of the only path to the
//! bytes.
//!
//! # The order of a list is not part of the contract
//!
//! `release` closes the gap with the last peer, so two nodes holding the same
//! peers in different orders hand them back in different orders. Which of them
//! to try first is a selection decision — `net/path_select.zig` is where one
//! lives — and this table stores what it is given and refuses the rest.
//!
//! **It allocates nothing, so there is no allocator to pass**, for
//! `topic_table.zig`'s reason: a route is a fixed array sized by a named
//! constant and the routes are a fixed array sized by another.

const std = @import("std");
const base_key = @import("../base/key.zig");
const blob_set = @import("../blobs/blob_set.zig");

const NodeId = base_key.NodeId;

/// The BLAKE3 hash a blob is named by, bound from `blobs/blob_set.zig` rather
/// than spelled again. `blobs/requests.zig` owns the type; `blob_set.zig`,
/// `store.zig` and `ticket/blob_ticket.zig` each say so where they need the
/// name, and a key that is one type under four names is a key whose halves can
/// drift apart in a comparison that then never matches.
pub const Hash = blob_set.Hash;

/// How many blobs this node routes for at once.
///
/// **The same number `blob_set.max_blobs` names, bound rather than written
/// twice.** A fetch is only ever started for a hash this node knows — a name
/// nobody here has heard of is not something this node goes and fetches — so
/// the set of hashes being fetched and the set of routes to peers are the same
/// set, and the second cannot be the larger. Two constants that have to agree
/// and are written twice are a way for them not to agree.
pub const max_blobs: usize = blob_set.max_blobs;

/// How many peers one blob's list may hold.
///
/// **A candidate list, not a replication factor.** Because no peer here is
/// trusted to hold anything, a fetch needs more than one candidate, and the
/// list has to be long enough to survive several of them turning out to have
/// been wrong. Eight is well under `gossip/hyparview`'s `max_active` of 32
/// active neighbours, so one blob's list can never be wider than the
/// neighbourhood it is drawn from, and it is a small multiple of what any
/// deployment actually replicates a blob to. Past it, `error.RouteFull`.
pub const blob_holders: usize = 8;

/// Every way the table refuses a claim.
pub const ClaimError = error{
    /// The table holds `max_blobs` blobs already and `hash` is not one of them.
    ///
    /// **Nothing is evicted.** A blob that is routed is dropped only by
    /// `release` or `removePeer`, and both name what went. Evicting here would
    /// drop a list of peers that are still being asked, and nothing anywhere
    /// would report the loss — so the caller gets an error it can count and
    /// decide against instead.
    NoFreeBlob,
    /// `hash` has `blob_holders` peers and `peer` is not one of them.
    ///
    /// **The list is unchanged**: the blob keeps every peer it had and keeps
    /// its slot, and the caller decides which peer to stop asking. A claim
    /// refused here has cost the blob nothing and the peer nothing but its
    /// claim.
    RouteFull,
};

/// What a claim did.
pub const Claim = union(enum) {
    /// The peer is in the blob's list now and was not before.
    claimed,
    /// It already was, and the table is exactly as it was. A claim that
    /// repeats a peer cannot grow the list, which is the duplicate request on
    /// every later fetch that a set has to refuse.
    already,
};

/// One blob's peers, in no order this module promises.
pub const Holders = struct {
    /// The peers. Only `[0..len]` is ever read, so the tail is `undefined`
    /// rather than empty and nothing walks past `len` to find it.
    ids: [blob_holders]NodeId = undefined,
    /// How many of them are in use, never a capacity: a list of two holding
    /// one is `len == 1`.
    len: usize = 0,
};

/// One blob and the peers this node may ask it of.
pub const Entry = struct {
    /// The blob, which is also the key. Compared across all 32 bytes and never
    /// interpreted: `blobs/store.zig` turns these bytes into a file name and
    /// nothing here reads them as anything else.
    hash: Hash,
    /// The peers it may be fetched from.
    holders: Holders,
};

/// A bounded map from blob hash to the peers that said they have it.
///
/// `BlobsRoute(max_blobs)` is the one a node builds. Nothing grows: a claim
/// past either bound is refused, and a blob leaves only through `release` or
/// `removePeer`.
///
/// **A blob with no peers has no route and no slot.** `release` and
/// `removePeer` free the slot when the last peer goes, so a node is never
/// holding a route it would ask nobody — and never answers `NoFreeBlob`
/// because of a blob with nobody in it.
pub fn BlobsRoute(comptime blobs: usize) type {
    return struct {
        const Self = @This();

        // Zero blobs is a node that fetches nothing, which is what a node with
        // no blob store expresses and not something a table should be built
        // as.
        comptime {
            std.debug.assert(blobs > 0);
        }

        /// The blobs held. Only `[0..len]` is ever read.
        entries: [blobs]Entry = undefined,
        /// How many of `entries` are in use, never a capacity.
        len: usize = 0,

        /// An empty table. Nothing to release — see the module doc — so there is
        /// no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many blobs are routed.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The peers `hash` may be fetched from, borrowed, or null for a blob
        /// this table does not hold.
        ///
        /// Borrowed from the table and no longer than it: the caller reads the
        /// list before the next `claim` or `release`, and the table owns the
        /// bytes. It is a slice rather than a copy because a list is read on
        /// every fetch and copying eight node ids per fetch to answer "who do I
        /// ask" is work nobody asked for.
        ///
        /// **A list of candidates and not a promise.** See the module doc for
        /// what a caller may conclude from what is in it.
        pub fn holders(self: *const Self, hash: Hash) ?[]const NodeId {
            const index = self.indexOf(hash) orelse return null;
            const list = &self.entries[index].holders;
            return list.ids[0..list.len];
        }

        /// Put `peer` in `hash`'s list, opening the blob if it is not held.
        ///
        /// A refused claim leaves the table exactly as it was: a blob opened by
        /// this call and then refused is not one this table holds.
        pub fn claim(self: *Self, hash: Hash, peer: NodeId) ClaimError!Claim {
            const index = self.indexOf(hash) orelse return self.open(hash, peer);
            const list = &self.entries[index].holders;
            if (holderAt(list, peer) != null) return Claim.already;
            if (list.len == blob_holders) return error.RouteFull;
            list.ids[list.len] = peer;
            list.len += 1;
            return Claim.claimed;
        }

        /// Take `peer` out of `hash`'s list. Whether it was there.
        ///
        /// This is what a fetch calls after a refused answer, and the only way
        /// a peer leaves a list without the peer leaving altogether. A peer
        /// that was not in the blob leaves nothing and frees nothing: the
        /// removal that matters is the one across every blob, which is
        /// `removePeer`.
        pub fn release(self: *Self, hash: Hash, peer: NodeId) bool {
            const index = self.indexOf(hash) orelse return false;
            if (!takeHolder(&self.entries[index].holders, peer)) return false;
            _ = self.dropEmpty(index);
            return true;
        }

        /// Take `peer` out of every blob it was in, and answer with how many
        /// lists it left.
        ///
        /// The cost is a scan of every blob, which at `max_blobs` is a handful
        /// of 32-byte comparisons each. A peer-to-blobs index would answer it
        /// without the scan, and would have to be kept in step with this table
        /// on every claim and every release: the two disagreeing is a peer still
        /// being asked about a blob it knows nothing of. One bounded table and
        /// one way to be wrong beats two tables and two.
        pub fn removePeer(self: *Self, peer: NodeId) usize {
            var removed: usize = 0;
            var index: usize = 0;
            while (index < self.len) {
                if (takeHolder(&self.entries[index].holders, peer)) removed += 1;
                // A blob that just emptied had the last entry moved into its
                // slot, so this index holds a blob nobody has looked at yet and
                // is still the one to look at. Otherwise it is a blob that kept
                // its peers, and this peer is out of it.
                if (self.dropEmpty(index)) continue;
                index += 1;
            }
            return removed;
        }

        /// Where `hash` is, or null for a blob this table does not hold.
        ///
        /// A scan and not a hash, for `conn_index.zig`'s reason: the whole table
        /// is `blobs` entries and a hash is 32 bytes, so a lookup costs less
        /// than the fetch the answer decides. The loop is bounded by the storage
        /// it walks.
        fn indexOf(self: *const Self, hash: Hash) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (std.mem.eql(u8, &entry.hash, &hash)) return index;
            }
            return null;
        }

        /// Give a peer the one list slot that is not taken, opening the blob.
        fn open(self: *Self, hash: Hash, peer: NodeId) ClaimError!Claim {
            if (self.len == blobs) return error.NoFreeBlob;
            var fresh: Entry = .{
                .hash = hash,
                .holders = .{ .ids = undefined, .len = 1 },
            };
            fresh.holders.ids[0] = peer;
            self.entries[self.len] = fresh;
            self.len += 1;
            return Claim.claimed;
        }

        /// Free the slot at `index` when its blob has no peers left. Whether
        /// the slot was freed, which is the one fact the caller's loop needs: a
        /// freed slot holds a different blob than it did.
        fn dropEmpty(self: *Self, index: usize) bool {
            if (self.entries[index].holders.len != 0) return false;
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return true;
        }
    };
}

/// Where `peer` is in `holders`, or null for a peer the list does not hold.
fn holderAt(holders: *const Holders, peer: NodeId) ?usize {
    for (holders.ids[0..holders.len], 0..) |holder, index| {
        if (holder.order(peer) == .eq) return index;
    }
    return null;
}

/// Take `peer` out of `holders`, closing the gap with the last peer. Whether it
/// was there.
fn takeHolder(holders: *Holders, peer: NodeId) bool {
    const index = holderAt(holders, peer) orelse return false;
    holders.ids[index] = holders.ids[holders.len - 1];
    holders.len -= 1;
    return true;
}

// --- tests

const t = std.testing;
const test_ids = @import("../node/node_test_ids.zig");

/// A blob named by one byte. A `Hash` is 32 bytes a peer chose and every one of
/// them is as good as any other, so the bytes only have to differ.
fn testHash(tag: u8) Hash {
    var bytes: Hash = @splat(0);
    bytes[0] = tag;
    return bytes;
}

/// Whether `list` holds `peer`.
fn holds(list: []const NodeId, peer: NodeId) bool {
    for (list) |holder| {
        if (holder.order(peer) == .eq) return true;
    }
    return false;
}

// The list is a place to ask, and a blob nobody can be asked about is not a
// blob this node routes. An empty table says so per blob, with null rather
// than an empty list, so a caller cannot mistake "no such blob" for "a blob
// nobody has".
test "a claimed peer is in that blob's list and an unclaimed blob has none" {
    // `BlobsRoute` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(2);
    var route = Route.init();

    try t.expectEqual(@as(usize, 0), route.count());
    try t.expectEqual(@as(?[]const NodeId, null), route.holders(testHash(1)));

    const blob = testHash(1);
    const peer = try test_ids.testNodeId(41);
    try t.expectEqual(Claim.claimed, try route.claim(blob, peer));
    try t.expectEqual(@as(usize, 1), route.count());
    const list = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), list.len);
    try t.expect(holds(list, peer));

    // A second blob is a second list and not a longer one: the peers of one
    // blob are not the peers of the other.
    const other = testHash(2);
    const second = try test_ids.testNodeId(42);
    try t.expectEqual(Claim.claimed, try route.claim(other, second));
    try t.expectEqual(@as(usize, 2), route.count());
    const other_list = route.holders(other) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), other_list.len);
    try t.expect(holds(other_list, second));
    try t.expect(!holds(other_list, peer));
}

// A peer that advertises the same blob twice is in it once, so a fetch asks it
// once. A list that grew on a repeat would ask the same peer twice and report
// two chances to succeed where there is one.
test "a peer that claims a blob twice is in it once" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(1);
    var route = Route.init();
    const blob = testHash(1);
    const peer = try test_ids.testNodeId(43);

    try t.expectEqual(Claim.claimed, try route.claim(blob, peer));
    try t.expectEqual(Claim.already, try route.claim(blob, peer));
    try t.expectEqual(Claim.already, try route.claim(blob, peer));

    const list = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), list.len);
    try t.expect(holds(list, peer));
    try t.expectEqual(@as(usize, 1), route.count());
}

// The refusal a fetch acts on. One peer gives a blob up, the rest of the table
// is untouched, and the blob itself is still routed because another peer is
// still to be asked — which is the difference between "this peer does not have
// it" and "nobody has it".
test "a released peer leaves the rest of the blob's list alone" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(2);
    var route = Route.init();
    const blob = testHash(1);
    const next_blob = testHash(2);
    const leaving = try test_ids.testNodeId(51);
    const staying = try test_ids.testNodeId(52);
    _ = try route.claim(blob, leaving);
    _ = try route.claim(blob, staying);
    _ = try route.claim(next_blob, staying);

    try t.expect(route.release(blob, leaving));
    const list = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), list.len);
    try t.expect(holds(list, staying));
    try t.expect(!holds(list, leaving));

    // A peer that was not in the blob, and a blob this table does not hold,
    // both release nothing: a removal that failed must not free a slot.
    try t.expect(!route.release(blob, leaving));
    try t.expect(!route.release(testHash(3), staying));
    try t.expectEqual(@as(usize, 2), route.count());

    // The last peer out frees the slot, because a blob this node would ask
    // nobody is not a blob this node routes.
    try t.expect(route.release(next_blob, staying));
    try t.expectEqual(@as(usize, 1), route.count());
    try t.expectEqual(@as(?[]const NodeId, null), route.holders(next_blob));
    // And the list it could not take with it is untouched: freeing one blob's
    // slot moved the last blob into the gap and dropped no peer.
    const kept = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), kept.len);
    try t.expect(holds(kept, staying));
}

// The production bound, so the number the operator picks is the one under test
// and not a smaller one that behaves the same way. The number itself is pinned
// because it is the answer to "how many blobs does this node fetch at once",
// and that answer must not drift silently.
test "a table full of blobs refuses a blob it has never routed" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(max_blobs);
    var route = Route.init();
    try t.expectEqual(@as(usize, 64), max_blobs);
    // The two bounds are one number for one reason, and the reason is checked
    // here rather than only in the module comment: the route table can never be
    // larger than the set of hashes a node knows it is fetching.
    try t.expectEqual(blob_set.max_blobs, max_blobs);

    const peer = try test_ids.testNodeId(61);
    for (0..max_blobs) |offset| {
        const blob = testHash(@intCast(offset + 1));
        try t.expectEqual(Claim.claimed, try route.claim(blob, peer));
    }
    try t.expectEqual(@as(usize, max_blobs), route.count());

    // One blob past the bound is refused, and refused rather than admitted by
    // dropping one of the sixty-four.
    const stranger = testHash(200);
    try t.expectError(error.NoFreeBlob, route.claim(stranger, peer));
    try t.expectEqual(@as(usize, max_blobs), route.count());
    try t.expectEqual(@as(?[]const NodeId, null), route.holders(stranger));

    // Every blob the table routed still routes the peer it was given: the
    // refusal cost the table nothing.
    for (0..max_blobs) |offset| {
        const blob = testHash(@intCast(offset + 1));
        const list = route.holders(blob) orelse return error.TestUnexpectedResult;
        try t.expectEqual(@as(usize, 1), list.len);
        try t.expect(holds(list, peer));
    }

    // One departure frees exactly one slot, for exactly one arrival.
    try t.expect(route.release(testHash(1), peer));
    try t.expectEqual(@as(usize, max_blobs) - 1, route.count());
    try t.expectEqual(Claim.claimed, try route.claim(stranger, peer));
    try t.expectEqual(@as(usize, max_blobs), route.count());
}

// The production fan-out, filled, so the refusal is proved at the number a node
// actually asks with rather than at a small one.
test "a blob at its holder bound refuses one more and keeps the holders it had" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(max_blobs);
    var route = Route.init();
    try t.expectEqual(@as(usize, 8), blob_holders);

    const blob = testHash(1);
    for (0..blob_holders) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expectEqual(Claim.claimed, try route.claim(blob, try test_ids.testNodeId(seed)));
    }
    const full = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, blob_holders), full.len);

    // One peer past the fan-out is refused, and the blob keeps every peer it
    // had: a table that shed a holder to admit a peer would drop a peer that is
    // still to be asked, with nobody told.
    const stranger = try test_ids.testNodeId(200);
    try t.expectError(error.RouteFull, route.claim(blob, stranger));

    const after = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, blob_holders), after.len);
    for (after) |holder| try t.expect(holder.order(stranger) != .eq);
    for (0..blob_holders) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expect(holds(after, try test_ids.testNodeId(seed)));
    }

    // One departure makes room for exactly one arrival, and the blob is full
    // again afterwards rather than one over. This is the fetch's own move: ask
    // a peer, get a refusal, release it, and the next candidate fits.
    try t.expect(route.release(blob, try test_ids.testNodeId(1)));
    try t.expectEqual(Claim.claimed, try route.claim(blob, stranger));
    const refilled = route.holders(blob) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, blob_holders), refilled.len);
    try t.expect(holds(refilled, stranger));
    try t.expectError(error.RouteFull, route.claim(blob, try test_ids.testNodeId(201)));
}

// A peer that disconnects goes out of every list in one call, and the count is
// what lets a caller notice a disconnect for a peer it thought was nowhere.
test "a peer that disconnects releases every blob it was in" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(4);
    var route = Route.init();
    const first = testHash(1);
    const second = testHash(2);
    const third = testHash(3);
    const fourth = testHash(4);
    const gone = try test_ids.testNodeId(71);
    const staying = try test_ids.testNodeId(72);

    // The departing peer is in three of the four blobs and the peer that stays
    // is in three of them too, so a removal that swept every blob is proved on
    // lists that are shared and on one that empties entirely.
    _ = try route.claim(first, gone);
    _ = try route.claim(first, staying);
    _ = try route.claim(second, gone);
    _ = try route.claim(second, staying);
    _ = try route.claim(third, gone);
    _ = try route.claim(fourth, staying);
    try t.expectEqual(@as(usize, 4), route.count());

    // Three lists, three removals.
    try t.expectEqual(@as(usize, 3), route.removePeer(gone));

    // Gone from every blob it was in, and still in none of the four.
    for ([_]Hash{ first, second, third, fourth }) |blob| {
        const list = route.holders(blob) orelse continue;
        for (list) |holder| try t.expect(holder.order(gone) != .eq);
    }
    // The three blobs that had another peer keep their list and lose only this
    // peer; the one that had only this peer is gone, because a blob this node
    // would ask nobody is not a blob this node routes.
    try t.expectEqual(@as(usize, 3), route.count());
    try t.expectEqual(@as(?[]const NodeId, null), route.holders(third));
    const first_list = route.holders(first) orelse return error.TestUnexpectedResult;
    const second_list = route.holders(second) orelse return error.TestUnexpectedResult;
    const fourth_list = route.holders(fourth) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), first_list.len);
    try t.expectEqual(@as(usize, 1), second_list.len);
    try t.expectEqual(@as(usize, 1), fourth_list.len);
    try t.expect(holds(first_list, staying));
    try t.expect(holds(second_list, staying));
    try t.expect(holds(fourth_list, staying));

    // A peer that was never routed removes nothing, twice over: a disconnect
    // path that runs again is not allowed to free somebody else's slot.
    try t.expectEqual(@as(usize, 0), route.removePeer(gone));
    try t.expectEqual(@as(usize, 3), route.count());

    // And the peer that stayed is in three blobs, and going takes all three.
    try t.expectEqual(@as(usize, 3), route.removePeer(staying));
    try t.expectEqual(@as(usize, 0), route.count());
    for ([_]Hash{ first, second, third, fourth }) |blob| {
        try t.expectEqual(@as(?[]const NodeId, null), route.holders(blob));
    }
    try t.expectEqual(@as(usize, 0), route.removePeer(staying));
    try t.expectEqual(@as(usize, 0), route.count());
}

// The key is all 32 bytes here too. Two hashes one byte apart are two lists,
// and confirming one of them in a `BlobSet` says nothing about the other, so a
// route cannot be filed against a hash the node does not know under that name.
test "two hashes one byte apart are two lists" {
    // zwanzig-disable-next-line: identifier-style
    const Route = BlobsRoute(4);
    var route = Route.init();
    // zwanzig-disable-next-line: identifier-style
    const Set = blob_set.BlobSet(4);
    var known = Set.init();

    var shifted = testHash(7);
    const plain = testHash(7);
    shifted[@sizeOf(Hash) - 1] = 1;

    const peer = try test_ids.testNodeId(81);
    try t.expectEqual(Claim.claimed, try route.claim(shifted, peer));
    try t.expectEqual(Claim.claimed, try route.claim(plain, peer));
    try t.expectEqual(@as(usize, 2), route.count());

    _ = try known.note(plain);
    _ = try known.note(shifted);
    try t.expectEqual(blob_set.Confirmed.verified, try known.confirm(plain));

    // The proved name is the one the node can serve; the neighbour shares 31
    // of its 32 bytes and is still a name it has only seen.
    try t.expectEqual(blob_set.Status.verified, known.statusOf(plain));
    try t.expectEqual(blob_set.Status.seen, known.statusOf(shifted));
    const proved = route.holders(plain) orelse return error.TestUnexpectedResult;
    const neighbour = route.holders(shifted) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), proved.len);
    try t.expectEqual(@as(usize, 1), neighbour.len);
}