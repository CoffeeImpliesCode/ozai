//! One claim on one blob: this node is fetching it, from that peer, and nobody
//! else is.
//!
//! `blob_set.zig` answers "which blobs does this node know of" and
//! `net/blobs_route.zig` answers "which peers may this blob be fetched from".
//! Neither answers the question a fetch loop asks on every iteration — *may I
//! start this fetch?* — because both are about what a peer said rather than
//! about what this node is already doing. This file is the third table: the
//! work this node has begun.
//!
//! # Why exclusivity is not a nicety here
//!
//! **Two callers fetching one blob into one store do not duplicate work; they
//! destroy each other's.** `store.zig` owns one data name and one outboard name
//! per blob, and `store.createPartial` **truncates** both when it opens them —
//! deliberately, so that a re-run over an abandoned partial starts it again. A
//! second fetch of a blob already in flight therefore truncates the first
//! fetch's prefix, writes a different prefix over it, and commits whichever
//! pair landed last. `resume.zig` discards that partial rather than trust it,
//! so the bytes are not silently wrong; they are silently *thrown away*, and
//! two units of work become one unit of work that keeps failing for as long as
//! both callers keep going.
//!
//! So a claim is exclusive per blob, and the exclusivity spans the **whole retry
//! ladder** rather than one attempt: the holder re-claiming with a different
//! peer re-aims the same claim — `attempts` goes up, the owner does not change
//! — and only the owner may give the blob up. A design that made exclusivity
//! per-attempt would hand out one writer per holder, and the ladder is exactly
//! where a second writer does the most damage.
//!
//! ## What a refusal looks like from the other side
//!
//! **The second caller is told who holds it, not merely told no.** `claim`
//! answers `.held` carrying the holder's own claim — owner, peer, attempt count
//! — so the refused caller can wait, go and do something else, or act on a peer
//! it was not handed. A bare error would leave it unable to tell "someone is
//! fetching this" from "this node will never fetch this", and the first is a
//! few seconds of waiting while the second is a different plan entirely.
//!
//! # What expires a claim
//!
//! Three ways out, and all three say what they dropped:
//!
//! * `release`, by the owner. The fetch ended: a refusal from `getter`, or bytes
//!   this node already holds.
//! * `claim` naming a blob whose entry has passed `claim_lifetime_s`. The aged
//!   entry is dropped and the newcomer takes the slot.
//! * `reap`, in bulk, for every entry past `claim_lifetime_s`.
//!
//! **An age bound is not decoration; without it the claim bound leaks.** This
//! is a fixed array and nothing else frees a slot, so a claim whose owner died
//! mid-fetch would hold its slot until the table filled, and then refuse every
//! blob for the rest of the process. A table whose size a dead transfer shrinks
//! is a table that stops fetching.
//!
//! `reap` exists because nothing here reads a clock. The caller decides when to
//! walk the table, so expiry is observed when somebody asks a question about a
//! blob — `claim` or `claimOf` — and swept when the caller says so. That is
//! `node/ticket_cache.zig`'s split: an aged-out claim is dropped by the lookup
//! that found it, and the caller owns the schedule.
//!
//! ## The clock is the caller's, and a claim ages against it
//!
//! `now_s` is a second on the caller's own clock, differenced and never compared
//! against an epoch, for `transport/session_store.zig`'s reason. **A clock that
//! moved back ages nothing and offers nothing:** `now_s - since_s` is negative
//! then, and read as an age that is the freshest claim in the table, which no
//! caller could act on. A backwards clock reads as stale, which sends the blob
//! to the next caller rather than holding it against one that may never come.
//!
//! # How this stays consistent with `blob_set.zig`'s one-way promotion
//!
//! **A claim holds no status, so there is no path from this file to a
//! downgrade.** `blob_set.Status` is a type this file never declares, `.seen`
//! and `.verified` are names it never writes, and every promotion in the blob
//! path goes through `blob_set.confirm`, which requires proof the caller
//! already holds. There is no `unverify` here to call, because there is nothing
//! here to un-verify: the strongest statement this table makes is "this node is
//! fetching this blob", and that is not a statement about the bytes. An expiring
//! claim therefore cannot contradict a proof — it can only stop blocking one,
//! which is the whole of what a claim is worth.
//!
//! Two consequences follow, and both are why the type is what it is:
//!
//! * **A claim cannot promote.** Claiming a hash nobody noted is granted, and
//!   grants nothing: it is a statement about this node's work, and
//!   `blob_set.note` remains the only way a name enters the set.
//! * **A claim cannot refuse a proved blob.** `blob_set` holds the only statuses
//!   in the blob path, so it is the only thing entitled to say a blob is not
//!   worth fetching. If `claim` refused here because the set said `.verified`,
//!   this file would hold a second opinion about bytes, and every caller would
//!   have to keep the two in step. They are not kept in step, and need not be:
//!   only `blob_set.forget` clears a proof, and this table is told about a proof
//!   in neither direction. A blob whose files the store lost is re-claimable,
//!   which is the correct answer — the store, not this table, decides whether
//!   the bytes are still there.
//!
//! # The bound refuses, and it cannot be different from the others
//!
//! `max_claims` is `blob_set.max_blobs` bound rather than written twice, for
//! `net/blobs_route.zig`'s reason: a fetch is started only for a hash this node
//! holds, so the blobs being fetched and the blobs being known are one set and
//! the second cannot be the larger.
//!
//! **Nothing is evicted, and eviction would be strictly worse here than in
//! either table this one sits beside.** `blob_set` will not drop a sighting
//! because a stranger arrived; `blobs_route` will not drop a peer because a
//! stranger arrived, because a peer is the other end of the only path to the
//! bytes. A claim can evict nothing for a third reason: the entry is the only
//! thing standing between the newcomer and the truncation described above.
//! Evicting it hands two callers the right to write the same two files, and the
//! loser finds out by having its transfer discarded. A refusal a caller can
//! count is strictly better than a collision it cannot.
//!
//! **It allocates nothing, so there is no allocator to pass**, for
//! `blob_set.zig`'s reason. A whole table is a value on the stack: `max_claims`
//! entries of a 32-byte hash, a 32-byte peer id and three small fields is a
//! little over five kilobytes.
//!
//! `Claim` is returned **by value** rather than borrowed, which is
//! `blobs_route`'s borrowed-holder-list rule inverted: a borrowed claim would
//! carry the obligation "valid until the next call", on the path of every fetch
//! iteration. Copying eighty-odd bytes once per lookup to answer "may I start"
//! is cheaper than a lifetime the caller has to remember.

const std = @import("std");
const blob_set = @import("blob_set.zig");
const base_key = @import("../base/key.zig");

/// The BLAKE3 hash a blob is named by, bound from `blob_set.zig` rather than
/// spelled again, for the reason `net/blobs_route.zig` gives: a key that is one
/// type under four names is a key whose halves can drift apart in a comparison
/// that then never matches.
pub const Hash = blob_set.Hash;

/// The peer a claim is aimed at. `base/key.zig` owns the type.
pub const NodeId = base_key.NodeId;

/// How many bytes of a `Hash` there are, which is the length the key is compared
/// across.
const hash_bytes = @sizeOf(Hash);

/// Which in-process caller holds a claim.
///
/// **An identity of code, not of a node.** An opaque `u32` the caller picks,
/// compared and carried, never put on the wire: who holds a claim on this
/// machine is a fact about this machine, and the only peer in a claim is the one
/// being asked. It is a number rather than a `NodeId` so that a caller cannot
/// pass a peer's identity here by mistake and have a claim released by whoever
/// that peer happens to be.
pub const Owner = u32;

/// How many blobs this node may be fetching at once.
///
/// **The same number `blob_set.max_blobs` names, bound rather than written
/// twice.** A fetch is started only for a hash this node holds, so the blobs
/// being fetched and the blobs being known are the same set.
pub const max_claims: usize = blob_set.max_blobs;

/// How long a claim is offered after the moment it was last claimed, in seconds
/// on the caller's own clock.
///
/// **A bound and not a field read off anything**, because there is no field to
/// read: a claim is this node's own work, begun by this node, and neither a peer
/// nor a message contributes a number to it. No upstream figure is copied here
/// either — `net/blobs_route.zig` already holds that no peer is a promise, so a
/// peer's advertisement cannot bound how long this node keeps trying its blob.
/// This is the operator's number.
///
/// Ten minutes is reasoned from both ends rather than picked. It must outlast any
/// attempt this tree makes: the longest scheduled thing here is
/// `net/probe_plan.full_report_interval` at five minutes, and a claim that could
/// expire inside a ladder which was going to succeed would hand the blob to a
/// second caller halfway through. It must not outlast what makes a claim worth
/// holding, which is some other caller of this node wanting the same blob, and
/// nothing here observes that — so the only sound end is a wall clock an
/// operator can read in a log line and argue with, exactly as
/// `node/ticket_cache.zig` argues for `ticket_lifetime_s`.
///
/// Deliberately not an attempt cap. A cap would need a number with no source in
/// this tree, and would cut a ladder that was about to succeed at a point no
/// caller can argue about. The age is a bound a caller can read, and it is what
/// stops a doomed claim from holding its slot.
pub const claim_lifetime_s: i64 = 10 * 60;

/// Every way the table refuses a claim.
pub const Error = error{
    /// The table holds `max_claims` claims already and `hash` is not one of
    /// them.
    ///
    /// **Nothing is evicted.** A claim leaves only through `release`, `reap`, or
    /// a `claim` that found the blob's own entry aged out, and all three say
    /// what went. Evicting here would hand the newcomer a second writer on the
    /// two files `store.createPartial` truncates, and the loser would find out
    /// by having its transfer discarded rather than by being told.
    NoFreeClaim,
};

/// One claim, as this table holds it.
pub const Claim = struct {
    /// The blob, which is also the key. Compared across all 32 bytes and never
    /// interpreted, for `blob_set.zig`'s reason: the bytes are a file name and
    /// nothing here reads them as anything else.
    hash: Hash,
    /// Which caller may re-aim or give up this blob. The only identity that can
    /// change the claim.
    owner: Owner,
    /// The peer this attempt is aimed at. **A place to ask and not a promise
    /// that it holds the blob**, for `net/blobs_route.zig`'s reason: a provider
    /// that does not have the blob writes nothing and closes, so a peer named
    /// here is contradicted by nothing.
    peer: NodeId,
    /// How many times the owner has re-aimed this claim at a peer.
    ///
    /// **Counted and not acted on.** No attempt count refuses anything: the
    /// bound that actually ends a doomed claim is `claim_lifetime_s`, which a
    /// caller can read off a clock. This is here so that two claimants of one
    /// blob leave a number behind rather than a coincidence of two identical
    /// answers — the same thing `ticket_cache.Claim.uses` is for.
    attempts: u32,
    /// The second this claim was last claimed or re-aimed, on the caller's
    /// clock. Freshness is measured from here and from nowhere else.
    since_s: i64,
};

/// What a claim did. Both arms carry the claim as it stands, so a caller never
/// has to ask a second question to learn what it now holds.
pub const Claimed = union(enum) {
    /// The blob is claimed by `owner` as of now. It was free, or its entry had
    /// aged out and was dropped to make room.
    claimed: Claim,
    /// The blob is claimed by somebody and the table is unchanged. Whether that
    /// somebody is the caller is `isFor`.
    ///
    /// **Handed back whole, because a refusal the caller cannot read is a
    /// refusal it cannot plan around.** Owner, peer and attempt count together
    /// say whether this node is working on the blob and how far it has got; a
    /// bare error would make "someone is fetching this" and "this node will
    /// never fetch this" the same answer.
    held: Claim,

    /// The claim as it stands, whoever holds it.
    pub fn current(self: Claimed) Claim {
        return switch (self) {
            .claimed => |claim| claim,
            .held => |claim| claim,
        };
    }

    /// Whether the claim is `owner`'s, whichever arm it arrived in.
    pub fn isFor(self: Claimed, owner: Owner) bool {
        return self.current().owner == owner;
    }

    /// Whether the blob was free and is now `owner`'s.
    ///
    /// **Read by switching, not by comparing the union.** This toolchain refuses
    /// `==` on an aggregate, and a `Claimed` carries a `Claim`, so the arm is
    /// named rather than matched. A caller that wants the arm's payload calls
    /// `current`, which is what the switch in here is already doing.
    pub fn isClaimed(self: Claimed) bool {
        return switch (self) {
            .claimed => true,
            .held => false,
        };
    }
};

/// A bounded map from blob hash to the one caller fetching it.
///
/// `BlobClaim(max_claims)` is the one a node builds. Nothing grows: a claim past
/// the bound is `error.NoFreeClaim`, and a claim leaves only through `release`,
/// `reap`, or a `claim` that found its own entry aged out.
///
/// **A peer's position is not its identity.** Entries are held in the order
/// they were first claimed and `release` and `reap` close the gap with the last
/// entry, so two tables holding the same blobs need not list them the same way.
pub fn BlobClaim(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        // Zero claims is a node that fetches nothing, which is a caller mistake
        // rather than a state to represent, refused here where the mistake is —
        // the reason `blob_set.zig` gives.
        comptime {
            std.debug.assert(capacity > 0);
        }

        /// The claims held. Only `[0..len]` is ever read, so the tail is
        /// `undefined` rather than empty and nothing walks past `len` to find
        /// it.
        entries: [capacity]Claim = undefined,
        /// How many of `entries` are in use, never a capacity: a table of two
        /// holding one is `len == 1`.
        len: usize = 0,

        /// An empty table. Nothing to release — see the module doc — so there is
        /// no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many blobs are being fetched.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The claim on `hash`, or null for a blob this table does not claim —
        /// which covers both a blob nobody claimed and a blob whose claim has
        /// aged out. Null is not a weaker `.held`: it is the one answer a caller
        /// may act on, meaning the blob is free.
        pub fn claimOf(self: *const Self, hash: Hash) ?Claim {
            const index = self.indexOf(hash) orelse return null;
            return self.entries[index];
        }

        /// Claim `hash` for `owner`, aimed at `peer`, as of `now_s`.
        ///
        /// Three answers, and which one arrives is the whole contract:
        ///
        /// * **Free, or aged out.** An entry past `claim_lifetime_s` is dropped
        ///   — the caller naming the blob is what noticed it had died, so
        ///   nothing is swept that nobody asked about — and its slot goes to
        ///   this claim as `.claimed`.
        /// * **Already this caller's.** The claim is re-aimed at `peer`,
        ///   `attempts` goes up, `since_s` becomes `now_s`, and the answer is
        ///   `.held`. **Re-claiming re-arms the age, and only the same owner can
        ///   do it**, so a caller still working its ladder keeps the blob and a
        ///   second task polling for it cannot hold it alive.
        /// * **Somebody else's.** `.held`, carrying that claim, and nothing
        ///   changes.
        ///
        /// At the bound a blob this table already claims is still re-aimable and
        /// still answerable: a full table freezes the arrival of new claims, not
        /// the work in the claims it has.
        pub fn claim(
            self: *Self,
            hash: Hash,
            peer: NodeId,
            owner: Owner,
            now_s: i64,
        ) Error!Claimed {
            const index = self.indexOf(hash) orelse return self.open(hash, peer, owner, now_s);
            if (!isFresh(self.entries[index], now_s)) {
                self.dropAt(index);
                return self.open(hash, peer, owner, now_s);
            }
            if (self.entries[index].owner != owner) return .{ .held = self.entries[index] };
            self.entries[index].peer = peer;
            self.entries[index].attempts +|= 1;
            self.entries[index].since_s = now_s;
            return .{ .held = self.entries[index] };
        }

        /// Give `hash` up on the owner's word and free its slot. Whether it was
        /// held by `owner` at all.
        ///
        /// **Only the holder's word releases it.** A caller that lost a race and
        /// finished late cannot take the blob away from the caller that won it,
        /// which would reach the collision this file exists to prevent through
        /// the exit instead of the entrance. A claim released for whatever reason
        /// is gone, and this table records no conclusion: a fetch that ended in
        /// a proof and a fetch that ended in a refusal leave the same thing here,
        /// and `blob_set` is where that difference is written down.
        ///
        /// A blob that was not claimed releases nothing, which is what makes a
        /// path that gives up twice — once on a refused answer, once on the
        /// reconnect — harmless.
        pub fn release(self: *Self, hash: Hash, owner: Owner) bool {
            const index = self.indexOf(hash) orelse return false;
            if (self.entries[index].owner != owner) return false;
            self.dropAt(index);
            return true;
        }

        /// Drop every claim past `claim_lifetime_s` and answer how many went.
        ///
        /// **The caller's schedule, not this file's.** Nothing here reads a
        /// clock, so an aged claim is otherwise noticed only by a lookup on the
        /// blob it holds, and a table full of claims for blobs nobody asks about
        /// again would sit at its bound refusing new work. This is the call that
        /// keeps the bound about claims rather than about claims that died.
        pub fn reap(self: *Self, now_s: i64) usize {
            var dropped: usize = 0;
            var index: usize = 0;
            while (index < self.len) {
                if (isFresh(self.entries[index], now_s)) {
                    index += 1;
                    continue;
                }
                self.dropAt(index);
                dropped += 1;
                // The last entry was moved into the gap, so this index holds a
                // claim nobody has looked at yet and is the one to look at.
            }
            return dropped;
        }

        /// Where `hash` is, or null for a blob this table does not claim.
        ///
        /// A scan and not a hash, for `blob_set.zig`'s reason: the whole table
        /// is `capacity` entries and a hash is 32 bytes, so a lookup costs less
        /// than the fetch its answer decides, and the loop is bounded by the
        /// storage it walks.
        fn indexOf(self: *const Self, hash: Hash) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (std.mem.eql(u8, &entry.hash, &hash)) return index;
            }
            return null;
        }

        /// Give `owner` the one slot that is not taken.
        fn open(self: *Self, hash: Hash, peer: NodeId, owner: Owner, now_s: i64) Error!Claimed {
            if (self.len == capacity) return error.NoFreeClaim;
            const fresh: Claim = .{
                .hash = hash,
                .owner = owner,
                .peer = peer,
                .attempts = 0,
                .since_s = now_s,
            };
            self.entries[self.len] = fresh;
            self.len += 1;
            return .{ .claimed = fresh };
        }

        /// Take the entry at `index` out. `index` must be in `[0..len)`, and the
        /// slot it frees is closed with the last entry, so this is the only
        /// place a gap is made.
        fn dropAt(self: *Self, index: usize) void {
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
        }
    };
}

/// Whether `claim` is still offered, on a clock reading `now_s`.
///
/// **Fail closed on a clock that moved back.** `now_s - since_s` is negative
/// then, and read as an age that is the freshest claim in the table; nothing
/// downstream could tell. A claim this node cannot age is a claim it does not
/// offer. After this check the subtraction cannot overflow, because `now_s` is
/// the larger of the two.
fn isFresh(claim: Claim, now_s: i64) bool {
    if (now_s < claim.since_s) return false;
    return now_s - claim.since_s <= claim_lifetime_s;
}

// --- tests

const t = std.testing;
const ids = @import("../node/node_test_ids.zig");

/// The two callers most tests here name. The whole file is about what happens
/// when there are two, and a table exercised by one caller cannot say anything
/// about exclusivity.
const owner_a: Owner = 1;
const owner_b: Owner = 2;

/// A blob named by one byte. A `Hash` is 32 bytes a peer chose and every one of
/// them is as good as any other, so the bytes only have to differ.
fn testHash(tag: u8) Hash {
    var bytes: Hash = @splat(0);
    bytes[0] = tag;
    return bytes;
}

/// A blob this table does not claim, whether nobody claimed it or its claim aged
/// out. `?Claim` spelled as a value rather than a bare `null`, for
/// `blob_set.zig`'s `expectStatus`: the answer a caller acts on is a value of the
/// same type as the ones it must not confuse itself with.
fn expectFree(table: anytype, hash: Hash) !void {
    try t.expectEqual(@as(?Claim, null), table.claimOf(hash));
}

// Exclusivity from the refused side: two callers, one blob, one peer. The second
// must not get the claim, and must be able to say who did have it, because a
// caller that cannot tell "being fetched" from "never fetched" has no second
// plan. Also pins that the refusal cost the table nothing and moved no peer.
test "a second caller is refused and is told who holds the blob" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);
    const peer_b = try ids.testNodeId(2);

    const first = try table.claim(testHash(1), peer_a, owner_a, 1_000);
    try t.expect(first.isClaimed());
    try t.expect(first.isFor(owner_a));
    try t.expectEqual(@as(usize, 1), table.count());

    // The second caller is refused and gets the holder's claim whole: owner,
    // peer, attempt count. That is enough to decide whether to wait, to give up
    // on the blob for now, or to ask a peer nobody claimed.
    const second = try table.claim(testHash(1), peer_b, owner_b, 1_000);
    try t.expect(!second.isClaimed());
    try t.expect(second.isFor(owner_a));
    try t.expect(!second.isFor(owner_b));
    const holders = second.current();
    try t.expect(peer_a.order(holders.peer) == .eq);
    try t.expectEqual(owner_a, holders.owner);
    try t.expectEqual(@as(u32, 0), holders.attempts);

    // And the refusal changed nothing: one claim, aimed at the first caller's
    // peer and not at the newcomer's — the collision that would truncate the
    // newcomer's own transfer.
    try t.expectEqual(@as(usize, 1), table.count());
    const seen = table.claimOf(testHash(1)).?;
    try t.expect(peer_a.order(seen.peer) == .eq);
    try t.expect(peer_b.order(seen.peer) != .eq);
    try t.expectEqual(owner_a, seen.owner);

    // A blob nobody has claimed is free — the answer a caller acts on, and the
    // one it cannot confuse with a refusal.
    try expectFree(&table, testHash(2));
    const other = try table.claim(testHash(2), peer_b, owner_b, 1_000);
    try t.expect(other.isClaimed());
    try t.expect(other.isFor(owner_b));
    try t.expectEqual(@as(usize, 2), table.count());
}

// The ladder. One owner re-aiming must not become two writers, and the attempt
// count has to move so a re-aim shows up as work rather than as a coincidence of
// two identical claims.
test "the holder re-aiming keeps the claim and moves the attempt count" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);
    const peer_b = try ids.testNodeId(2);
    const peer_c = try ids.testNodeId(3);

    _ = try table.claim(testHash(1), peer_a, owner_a, 1_000);
    const again = try table.claim(testHash(1), peer_b, owner_a, 1_010);
    try t.expect(!again.isClaimed());
    try t.expect(again.isFor(owner_a));
    const reaimed = again.current();
    try t.expect(peer_b.order(reaimed.peer) == .eq);
    try t.expect(peer_a.order(reaimed.peer) != .eq);
    try t.expectEqual(@as(u32, 1), reaimed.attempts);
    try t.expectEqual(@as(i64, 1_010), reaimed.since_s);
    try t.expectEqual(@as(usize, 1), table.count());

    // A different caller is refused mid-ladder, and the ladder it was refused
    // from is untouched: still one claim, still on the second peer, still one
    // attempt made.
    const other = try table.claim(testHash(1), peer_c, owner_b, 1_020);
    try t.expect(!other.isClaimed());
    try t.expect(other.isFor(owner_a));
    const seen = other.current();
    try t.expect(peer_b.order(seen.peer) == .eq);
    try t.expectEqual(@as(u32, 1), seen.attempts);
    try t.expectEqual(@as(usize, 1), table.count());
}

// Only the holder's word ends a claim. This is the exit half of exclusivity:
// without it, a caller that lost the race and finished late could take the blob
// away from the caller that won it.
test "a claim is given up by its holder and by nobody else" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);
    _ = try table.claim(testHash(1), peer_a, owner_a, 1_000);

    // The loser of a race, giving up late, touches nothing.
    try t.expect(!table.release(testHash(1), owner_b));
    try t.expectEqual(@as(usize, 1), table.count());
    try t.expect(table.claimOf(testHash(1)) != null);

    // The holder may, and the slot is free for the next caller — whose next
    // claim is `.claimed` rather than `.held`.
    try t.expect(table.release(testHash(1), owner_a));
    try expectFree(&table, testHash(1));
    const taken = try table.claim(testHash(1), peer_a, owner_b, 1_100);
    try t.expect(taken.isClaimed());
    try t.expect(taken.isFor(owner_b));

    // A blob nobody claimed gives up nothing, and giving up twice is harmless:
    // `owner_b` took the blob `owner_a` gave up, so its own word still frees the
    // slot, and a second word from the same owner frees nothing.
    try t.expect(!table.release(testHash(2), owner_a));
    try t.expect(table.release(testHash(1), owner_b));
    try t.expect(!table.release(testHash(1), owner_b));
    try t.expectEqual(@as(usize, 0), table.count());
}

// Expiry at both edges and on a backwards clock. A claim that outlived the fetch
// it stands for is worse than no claim, because the slot it holds is one fewer
// blob this node is willing to fetch.
test "a claim past its lifetime is dropped and never handed out" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);
    _ = try table.claim(testHash(1), peer_a, owner_a, 1_000);
    const last_fresh = 1_000 + claim_lifetime_s;

    // Inside the lifetime, including its last second, and a reap that finds
    // nothing drops nothing. The re-aim above re-arms the age, so the boundary
    // runs from the second it was taken rather than from the first claim.
    try t.expect(table.claimOf(testHash(1)) != null);
    _ = try table.claim(testHash(1), peer_a, owner_a, last_fresh);
    try t.expectEqual(@as(usize, 0), table.reap(last_fresh + claim_lifetime_s));
    try t.expectEqual(@as(usize, 1), table.count());

    // One second past it the entry is gone and `reap` says how many went.
    try t.expectEqual(@as(usize, 1), table.reap(last_fresh + claim_lifetime_s + 1));
    try expectFree(&table, testHash(1));
    try t.expectEqual(@as(usize, 0), table.count());

    // The same expiry on the path that matters: a different caller naming the
    // blob. The aged entry goes and the newcomer gets `.claimed`, so the second
    // caller is never told "held" by a transfer nobody is running any more.
    _ = try table.claim(testHash(1), peer_a, owner_a, 2_000);
    const late = try table.claim(testHash(1), peer_a, owner_b, 2_000 + claim_lifetime_s + 1);
    try t.expect(late.isClaimed());
    try t.expect(late.isFor(owner_b));
    try t.expectEqual(@as(usize, 1), table.count());

    // A clock that moved back ages nothing, so the claim reads as stale rather
    // than as the freshest thing in the table, and `reap` on that clock takes it
    // rather than keeping a claim nobody can age.
    const held = table.claimOf(testHash(1)).?;
    try t.expect(isFresh(held, held.since_s));
    try t.expect(!isFresh(held, held.since_s - 1));
    try t.expectEqual(@as(usize, 1), table.reap(held.since_s - 1));
    try expectFree(&table, testHash(1));
}

// `reap` is the caller's schedule and this file's only bulk exit, so it sweeps
// exactly the aged claims, reports the count, and leaves the fresh ones where
// they are. The first blob is re-aimed just before the sweep, which is what
// pushes it past the clock its two untouched neighbours are behind.
test "a reap drops the aged claims and keeps the fresh ones" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);

    for (1..4) |tag| _ = try table.claim(testHash(@intCast(tag)), peer_a, owner_a, 1_000);
    try t.expectEqual(@as(usize, 3), table.count());

    // Nothing is old yet, and a reap that drops nothing must not drop anything.
    try t.expectEqual(@as(usize, 0), table.reap(1_000 + claim_lifetime_s));
    try t.expectEqual(@as(usize, 3), table.count());

    // Blob one is re-aimed 590 seconds later, so at the sweep it is 11 seconds
    // old where its two neighbours are 601. Only the neighbours go, and the count
    // says two — re-arming is what saved blob one.
    _ = try table.claim(testHash(1), peer_a, owner_a, 1_000 + claim_lifetime_s - 10);
    const sweep = 1_000 + claim_lifetime_s + 1;
    try t.expectEqual(@as(usize, 2), table.reap(sweep));
    try expectFree(&table, testHash(2));
    try expectFree(&table, testHash(3));
    try t.expect(table.claimOf(testHash(1)) != null);
    try t.expectEqual(@as(usize, 1), table.count());

    // And a freed slot admits a newcomer, which is the whole reason to sweep.
    const fresh = try table.claim(testHash(4), peer_a, owner_b, sweep);
    try t.expect(fresh.isClaimed());
    try t.expect(fresh.isFor(owner_b));
}

// The bound, at the number the operator picks rather than a smaller one that
// behaves the same way. Eviction is refused here because the entry is the only
// thing between the newcomer and `store.createPartial`'s truncate.
test "a table at its bound refuses one more and keeps the claims it had" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(max_claims);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);
    try t.expectEqual(@as(usize, 64), max_claims);

    for (0..max_claims) |offset| {
        const claimed = try table.claim(testHash(@intCast(offset + 1)), peer_a, owner_a, 1_000);
        try t.expect(claimed.isClaimed());
    }
    try t.expectEqual(@as(usize, max_claims), table.count());

    // Being at the bound does not freeze the claims in it: the owner of a held
    // blob re-aims, and is refused by nobody.
    const reaimed = try table.claim(testHash(1), peer_a, owner_a, 1_001);
    try t.expect(reaimed.isFor(owner_a));
    try t.expectEqual(@as(u32, 1), reaimed.current().attempts);

    // One stranger past the bound is refused, and refused rather than admitted by
    // dropping one of the sixty-four.
    const stranger = testHash(200);
    try t.expectError(error.NoFreeClaim, table.claim(stranger, peer_a, owner_b, 1_000));
    try t.expectEqual(@as(usize, max_claims), table.count());
    try expectFree(&table, stranger);

    // Every claim the table held is still held by the owner that took it. A
    // refusal may not cost this node a fetch in progress, and a refused caller
    // may not find somebody else's transfer gone under it.
    for (0..max_claims) |offset| {
        try t.expectEqual(owner_a, table.claimOf(testHash(@intCast(offset + 1))).?.owner);
    }

    // One departure frees exactly one slot, for exactly one arrival — and one
    // slot, so the next stranger is refused again.
    try t.expect(table.release(testHash(2), owner_a));
    try t.expectEqual(@as(usize, max_claims) - 1, table.count());
    const taken = try table.claim(stranger, peer_a, owner_b, 1_000);
    try t.expect(taken.isClaimed());
    try t.expectError(error.NoFreeClaim, table.claim(testHash(201), peer_a, owner_b, 1_000));
}

// The key is all 32 bytes. Two hashes one byte apart are two claims, and the byte
// is the last one as well as the first, so a comparison reading only a prefix
// would refuse the second caller here for the wrong reason.
test "two hashes one byte apart are two claims" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    var table = Table.init();
    const peer_a = try ids.testNodeId(1);

    var shifted = testHash(7);
    const plain = testHash(7);
    shifted[hash_bytes - 1] = 1;

    const first = try table.claim(shifted, peer_a, owner_a, 1_000);
    const second = try table.claim(plain, peer_a, owner_b, 1_000);
    try t.expect(first.isClaimed());
    try t.expect(second.isClaimed());
    try t.expectEqual(@as(usize, 2), table.count());

    // Each caller holds exactly its own, and the other is refused: a collision
    // here would be a second writer on one pair of files.
    try t.expectEqual(owner_a, table.claimOf(shifted).?.owner);
    try t.expectEqual(owner_b, table.claimOf(plain).?.owner);
    const refused = try table.claim(shifted, peer_a, owner_b, 1_000);
    try t.expect(refused.isFor(owner_a));

    // And releasing one frees one slot and leaves the other alone.
    try t.expect(table.release(shifted, owner_a));
    try t.expectEqual(@as(usize, 1), table.count());
    try t.expect(table.claimOf(plain) != null);
}

// The claim table and the blob set, side by side, on every boundary between
// them: a claim cannot promote, a release cannot demote, and a proved blob is
// still claimable because only `blob_set` may rule on bytes.
test "a claim never promotes and never demotes the blob set" {
    // zwanzig-disable-next-line: identifier-style
    const Table = BlobClaim(4);
    // zwanzig-disable-next-line: identifier-style
    const Set = blob_set.BlobSet(4);
    var table = Table.init();
    var set = Set.init();
    const peer_a = try ids.testNodeId(1);
    const hash = testHash(1);

    // A sighting is all the set has, and claiming the blob promotes nothing: a
    // claim is a statement about this node's work, and the set still says what a
    // peer said and nothing more.
    try t.expectEqual(blob_set.Noted.added, try set.note(hash));
    try t.expectEqual(blob_set.Status.seen, set.statusOf(hash));
    const claimed = try table.claim(hash, peer_a, owner_a, 1_000);
    try t.expect(claimed.isClaimed());
    try t.expectEqual(blob_set.Status.seen, set.statusOf(hash));

    // Expiring the claim leaves the set exactly as it was: there is no path from
    // a dropped claim to a status, because a claim holds none.
    try t.expectEqual(@as(usize, 1), table.reap(1_000 + claim_lifetime_s + 1));
    try t.expectEqual(blob_set.Status.seen, set.statusOf(hash));
    try t.expectEqual(@as(usize, 1), set.count());

    // A claim on a hash nobody ever sighted is granted and records nothing.
    // `blob_set.note` stays the only writer of a name into the set, and this
    // file is not that writer.
    const unsighted = testHash(2);
    const unseen = try table.claim(unsighted, peer_a, owner_a, 1_000);
    try t.expect(unseen.isClaimed());
    try t.expectEqual(@as(?blob_set.Status, null), set.statusOf(unsighted));

    // Now the proof arrives, through the one writer that requires it. The claim
    // on `hash` went with the reap above, so it is taken again to have something
    // to give up: this table never rules on bytes, and a blob `blob_set` holds
    // as verified is claimable and releasable like any other. Releasing it is
    // not a demotion — the bytes stay proved, and the unsighted claim is the
    // only one left.
    try t.expectEqual(blob_set.Confirmed.verified, try set.confirm(hash));
    const held_again = try table.claim(hash, peer_a, owner_a, 1_050);
    try t.expect(held_again.isClaimed());
    try t.expect(table.release(hash, owner_a));
    try t.expectEqual(blob_set.Status.verified, set.statusOf(hash));
    try expectFree(&table, hash);
    try t.expectEqual(@as(usize, 1), table.count());

    // A proved blob is still claimable. `blob_set` holds the only statuses in the
    // blob path, so it is the only thing entitled to say a blob is not worth
    // fetching, and only `forget` clears a proof. A blob whose files the store
    // lost is re-fetchable, which is the correct answer — and it is the store's
    // to decide, not a second opinion kept here.
    const reclaimed = try table.claim(hash, peer_a, owner_b, 1_100);
    try t.expect(reclaimed.isClaimed());
    try t.expectEqual(blob_set.Status.verified, set.statusOf(hash));

    // And after `forget` — the caller's word that the bytes are gone — the claim
    // is still held by the caller that took it, and each of the two states is
    // read from the table that owns it.
    try t.expect(set.forget(hash));
    try t.expectEqual(@as(?blob_set.Status, null), set.statusOf(hash));
    try t.expectEqual(owner_b, table.claimOf(hash).?.owner);
    const refused = try table.claim(hash, peer_a, owner_a, 1_200);
    try t.expect(refused.isFor(owner_b));
}
