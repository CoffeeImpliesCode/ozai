//! Which blobs this node knows of, and which of them it has proved it has.
//!
//! A blob is named by its BLAKE3 root hash: `store.zig` writes those digits
//! into every one of the four file names it owns, so the hash *is* the
//! identity and nothing else names one. This file is the node's record of the
//! names it has met, and the record carries two fields per name because
//! "I have heard of this blob" and "I have bytes that hash to this name" are
//! two facts a peer can contradict at any moment, and a single flag over both
//! is how a node ends up serving bytes it never proved.
//!
//! # Seen and verified are two states, and that is the whole design
//!
//! **A hash that has been seen is a name worth spending a fetch on. A hash that
//! has been verified is bytes that hash to that name.** What a caller may
//! conclude from each is stated on `Status`, and the difference is not
//! bookkeeping — the rest of the tree already draws it in four places:
//!
//! * `getter.zig` defines "proved" once and precisely: `Outcome.isComplete` is
//!   `refused == null`, and null is reached only when the walk arrives at the
//!   trusted root the caller held out of band. Every other outcome is a
//!   refusal, including the empty answer, which is the same bytes for "this
//!   provider has no such blob" and "this blob is empty" and is therefore never
//!   a completion.
//! * `provider.zig` may answer a `get` from a store only by opening a committed
//!   pair. A `.seen` hash gives a provider nothing to open.
//! * `store.zig` makes the presence of the committed `.data` file the commit
//!   point, and reads the window between its two renames as a miss. So "there
//!   are files with this name" and "this blob is here" are already different
//!   facts one layer down.
//! * `resume.zig` draws the same line over bytes: a file's length is not a
//!   claim about which bytes are in it, so a partial is resumed only where it
//!   has been checked against a value the caller held out of band.
//!
//! So a caller reading `.seen` learns that a peer named this blob and may go
//! and ask for it; a caller reading `.verified` learns that the bytes are here
//! and that `provider.answer` will open a pair for them. Reading `.seen` as
//! the second is the mistake the two states exist to make impossible, and no
//! method below makes it possible: only `confirm` writes `.verified`, and it
//! takes a hash and nothing else.
//!
//! # Promotion is one-way, and only proof performs it
//!
//! `note` records a sighting and can never produce `.verified`; it returns
//! `Noted.verified` for a hash that already is, because a peer naming a blob
//! this node has proved does not un-prove it. `confirm` is the only writer of
//! `.verified`, and it requires the caller to have decided something this file
//! cannot see: a walk that reached the trusted root, or a root hash computed
//! over bytes this node committed itself. **The proof is the caller's and is
//! already in hand** — this table reads no directory, hashes no byte and calls
//! no verifier, so there is nothing here for a peer to talk into.
//!
//! A hash confirmed without ever being noted is added as `.verified`, rather
//! than refused: a blob this node wrote from a ticket was never sighted by a
//! peer, and refusing the proof because nobody mentioned it first would be the
//! one case where the stronger fact loses to the weaker one.
//!
//! # A bound is a refusal
//!
//! `max_blobs` is the number of hashes this node holds at once, and nothing is
//! evicted to make room. A hash leaves only through `forget`, which names it,
//! for the reasons `node/topic_table.zig` gives at length: a table whose size a
//! peer picks by naming blobs is a table with no bound, and a node that quietly
//! drops a verified hash to make room for a sighting has dropped the only fact
//! it had.
//!
//! **It allocates nothing, so there is no allocator to pass** — the same
//! property `topic_table.zig` states for the same reason. A whole set is a
//! value on the stack, and 64 entries of a 32-byte hash and a one-byte status
//! is a little over two kilobytes.

const std = @import("std");
const requests = @import("requests.zig");

/// The BLAKE3 hash a blob is named by. `requests.zig` owns the type and the
/// wire form; `store.zig` and `ticket/blob_ticket.zig` both spell it for
/// themselves, and this is the same 32 bytes again — one type, one owner.
pub const Hash = requests.Hash;

/// How many bytes of a `Hash` there are. The key is compared across all of
/// them, which is what the two-keys-one-byte-apart test below pins.
const hash_bytes = @sizeOf(Hash);

/// How many hashes this node holds at once.
///
/// **A bound is a refusal, and an unbounded set is a set whose size a remote
/// peer picks.** Every hash another node names is a hash this node could hold,
/// and 64 is the number of blobs a node will track names for at once — a
/// want-list and an index, not an archive. Past it, `error.NoFreeBlob` is what
/// a caller sees, and the caller is the only thing that may choose what to
/// forget.
pub const max_blobs: usize = 64;

/// Every way the set refuses a hash.
pub const Error = error{
    /// The set holds `max_blobs` hashes already and this one is not among them.
    ///
    /// **Nothing is evicted.** A hash leaves only through `forget`, which names
    /// it, and a sighting that quietly took a slot could take the slot of a
    /// blob whose bytes this node has proved it holds — dropping the one fact
    /// here that says the bytes are real.
    NoFreeBlob,
};

/// What a blob's contents are known to be.
pub const Status = enum {
    /// A peer named this blob, or this node was told to fetch it. The name is
    /// real enough to spend a fetch on and nothing more.
    ///
    /// A caller may ask for this blob and may plan on asking somebody else when
    /// the answer is a refusal. A caller may **not** serve it, skip the fetch
    /// because the name is known, or treat the existence of a `.data` file
    /// under this name as anything: `store.zig` makes that file's presence a
    /// commit point it reaches by renaming into place, and nothing about the
    /// bytes in it is checked here.
    seen,
    /// The bytes this node holds hash to this name.
    ///
    /// The only state a caller may act on as "this blob is mine": the state
    /// `provider.answer` may open a pair for, and the state that survives a
    /// peer contradicting it. `getter.zig` is where this state comes from, and
    /// `confirm` is the only way in.
    verified,
};

/// What a note did.
pub const Noted = union(enum) {
    /// The hash was not in the set and is in it now as `.seen`.
    added,
    /// It was in the set as `.seen` and still is, and the set is exactly as it
    /// was. A repeated sighting cannot grow the set, which is the duplicate
    /// record every later lookup would walk past.
    seen,
    /// It was in the set as `.verified` and still is. The set is unchanged and
    /// stays verified: a peer naming a blob this node has proved does not take
    /// the proof away.
    verified,
};

/// What a confirmation did.
pub const Confirmed = union(enum) {
    /// The hash was `.seen` and is `.verified` now.
    verified,
    /// It was already `.verified`, and the set is exactly as it was.
    already,
};

/// One known hash and what is known about its contents.
pub const Entry = struct {
    /// The blob's name, which is also the key. Compared across all 32 bytes
    /// and never interpreted: `store.zig` turns these bytes into a file name
    /// and nothing here reads them as anything else.
    hash: Hash,
    /// What the contents are known to be. See `Status`.
    status: Status,
};

/// A bounded set of known blob hashes, each with what is known about its
/// contents.
///
/// `BlobSet(max_blobs)` is the one a node builds. Nothing grows: a hash past
/// the bound is `error.NoFreeBlob`, and a hash leaves only through `forget`.
///
/// **The order of the set is not part of the contract.** `forget` closes the
/// gap with the last entry, so two nodes holding the same hashes in different
/// orders answer `statusOf` the same way and nothing else differs.
pub fn BlobSet(comptime hashes: usize) type {
    return struct {
        const Self = @This();

        // Zero hashes is a node that knows no blob at all, which is not
        // something a set should be able to be built as.
        comptime {
            std.debug.assert(hashes > 0);
        }

        /// The hashes held. Only `[0..len]` is ever read, so the tail is
        /// `undefined` rather than empty and nothing walks past `len` to find
        /// it.
        entries: [hashes]Entry = undefined,
        /// How many of `entries` are in use, never a capacity: a set of two
        /// holding one is `len == 1`.
        len: usize = 0,

        /// An empty set. Nothing to release — see the module doc — so there is
        /// no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many hashes are held.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// What is known about `hash`'s contents: null for a hash this set does
        /// not hold, which is a different answer from `.seen` and from
        /// `.verified` and is the one a caller must not read as either.
        pub fn statusOf(self: *const Self, hash: Hash) ?Status {
            const index = self.indexOf(hash) orelse return null;
            return self.entries[index].status;
        }

        /// Record that `hash` has been named, as `.seen` or as the status it
        /// already has.
        ///
        /// **Never `.verified`.** This is the one method a peer's word reaches,
        /// and it is why a sighting cannot promote: the strongest conclusion
        /// this file can be asked for by a name alone is that the name is worth
        /// a fetch. A refused note leaves the set exactly as it was, so a hash
        /// this set already holds is never dropped for a repeated sighting.
        pub fn note(self: *Self, hash: Hash) Error!Noted {
            const index = self.indexOf(hash) orelse return self.openSeen(hash);
            return switch (self.entries[index].status) {
                .seen => Noted.seen,
                .verified => Noted.verified,
            };
        }

        /// Record that the bytes this node holds hash to `hash`, adding the
        /// hash as `.verified` if nothing had named it.
        ///
        /// The caller has already established this, by a walk that reached the
        /// trusted root (`getter.Outcome.isComplete`) or over bytes it wrote
        /// itself. Promotion happens here and nowhere else, and it never goes
        /// backwards: there is no `unverify`, so the only way to lose a proof
        /// is `forget`, which names the hash and says the caller has decided.
        pub fn confirm(self: *Self, hash: Hash) Error!Confirmed {
            const index = self.indexOf(hash) orelse return self.openVerified(hash);
            if (self.entries[index].status == .verified) return Confirmed.already;
            self.entries[index].status = .verified;
            return Confirmed.verified;
        }

        /// Take `hash` out of the set, whether it was `.seen` or `.verified`.
        ///
        /// Removing a `.verified` hash says the bytes are gone — a store that
        /// lost a committed pair, which `store.zig` reads as a miss. Nothing
        /// here stats a directory, so the caller's word is the only evidence
        /// there is, and turning a proof back into `.seen` is deliberately not
        /// an option: a set that could un-prove a blob would leave the caller
        /// guessing which of the two facts it still holds.
        pub fn forget(self: *Self, hash: Hash) bool {
            const index = self.indexOf(hash) orelse return false;
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return true;
        }

        /// Open a slot for a hash nobody had named, as `.seen`.
        fn openSeen(self: *Self, hash: Hash) Error!Noted {
            try self.append(hash, .seen);
            return Noted.added;
        }

        /// Open a slot for a hash whose contents were proved without a
        /// sighting, as `.verified`.
        fn openVerified(self: *Self, hash: Hash) Error!Confirmed {
            try self.append(hash, .verified);
            return Confirmed.verified;
        }

        /// Claim the one slot that is not taken, refusing when there is none.
        fn append(self: *Self, hash: Hash, status: Status) Error!void {
            if (self.len == hashes) return error.NoFreeBlob;
            self.entries[self.len] = .{ .hash = hash, .status = status };
            self.len += 1;
        }

        /// Where `hash` is, or null for a hash this set does not hold.
        ///
        /// A scan and not a hash, for `conn_index.zig`'s reason: the whole set
        /// is `hashes` entries and a hash is 32 bytes, so a lookup costs less
        /// than the fetch its answer decides. The loop is bounded by the
        /// storage it walks.
        fn indexOf(self: *const Self, hash: Hash) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (std.mem.eql(u8, &entry.hash, &hash)) return index;
            }
            return null;
        }
    };
}

// --- tests

const t = std.testing;

/// A blob named by one byte. A `Hash` is 32 bytes a peer chose and every one of
/// them is as good as any other, so the bytes only have to differ.
fn testHash(tag: u8) Hash {
    var bytes: Hash = @splat(0);
    bytes[0] = tag;
    return bytes;
}

fn expectStatus(set: anytype, hash: Hash, want: ?Status) !void {
    try t.expectEqual(want, set.statusOf(hash));
}

// The two states are two states. A sighting is a name worth fetching and never
// more, and this is proved from the negative side first: a hash nobody has
// named reads as null, which is a third answer and not a weaker `.seen`.
test "a noted hash is seen, and a confirmed hash is verified" {
    // `BlobSet` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Set = BlobSet(4);
    var set = Set.init();

    try t.expectEqual(@as(usize, 0), set.count());
    try expectStatus(&set, testHash(1), null);

    try t.expectEqual(Noted.added, try set.note(testHash(1)));
    try t.expectEqual(@as(usize, 1), set.count());
    try expectStatus(&set, testHash(1), .seen);

    try t.expectEqual(Confirmed.verified, try set.confirm(testHash(1)));
    try t.expectEqual(@as(usize, 1), set.count());
    try expectStatus(&set, testHash(1), .verified);

    // A second hash is a second entry and not a longer one: the state is per
    // hash, and one blob being proved says nothing about another.
    try t.expectEqual(Noted.added, try set.note(testHash(2)));
    try expectStatus(&set, testHash(2), .seen);
    try expectStatus(&set, testHash(1), .verified);
}

// A peer's word never reaches the strong state, in either order and however
// often it is repeated: note, note again, then note under and after the proof.
// The set only ever grows in what it proves.
test "a sighting never promotes, and never un-promotes either" {
    // zwanzig-disable-next-line: identifier-style
    const Set = BlobSet(4);
    var set = Set.init();

    try t.expectEqual(Noted.added, try set.note(testHash(1)));
    try t.expectEqual(Noted.seen, try set.note(testHash(1)));
    try expectStatus(&set, testHash(1), .seen);
    try t.expectEqual(@as(usize, 1), set.count());

    try t.expectEqual(Confirmed.verified, try set.confirm(testHash(1)));
    // Confirmed twice is one promotion: a caller that verifies, stores, and
    // then verifies again is not a second blob becoming real.
    try t.expectEqual(Confirmed.already, try set.confirm(testHash(1)));
    try t.expectEqual(@as(usize, 1), set.count());

    // A peer naming a proved blob afterwards changes nothing and takes nothing.
    try t.expectEqual(Noted.verified, try set.note(testHash(1)));
    try t.expectEqual(Noted.verified, try set.note(testHash(1)));
    try expectStatus(&set, testHash(1), .verified);
    try t.expectEqual(@as(usize, 1), set.count());

    // And a hash proved without ever being sighted is proved, because a blob
    // written from a ticket was never named by a peer.
    try t.expectEqual(Confirmed.verified, try set.confirm(testHash(2)));
    try expectStatus(&set, testHash(2), .verified);
    try t.expectEqual(Noted.verified, try set.note(testHash(2)));
}

// A forgotten proof is not remembered. Forgetting is how a node learns its
// store lost the files, and a set that kept the flag would answer "this blob is
// mine" about bytes that are gone.
test "a forgotten hash is gone, and a second sighting starts it again at seen" {
    // zwanzig-disable-next-line: identifier-style
    const Set = BlobSet(4);
    var set = Set.init();

    _ = try set.note(testHash(1));
    try t.expectEqual(Confirmed.verified, try set.confirm(testHash(1)));
    try t.expectEqual(@as(usize, 1), set.count());

    try t.expect(set.forget(testHash(1)));
    try t.expectEqual(@as(usize, 0), set.count());
    try expectStatus(&set, testHash(1), null);

    // Noted again, it is a sighting and nothing more: there is no memory of the
    // proof that used to be here.
    try t.expectEqual(Noted.added, try set.note(testHash(1)));
    try expectStatus(&set, testHash(1), .seen);

    // A hash this set does not hold forgets nothing and frees no slot, and a
    // second removal of the same hash says so rather than shortening the set
    // a second time.
    try t.expect(!set.forget(testHash(200)));
    try t.expectEqual(@as(usize, 1), set.count());
    try t.expect(set.forget(testHash(1)));
    try t.expect(!set.forget(testHash(1)));
    try t.expectEqual(@as(usize, 0), set.count());
}

// The key is all 32 bytes. Two hashes one byte apart are two entries, and the
// byte is the last one as well as the first, so a comparison reading only a
// prefix would collide here.
test "two hashes one byte apart are two entries" {
    // zwanzig-disable-next-line: identifier-style
    const Set = BlobSet(4);
    var set = Set.init();

    var shifted = testHash(7);
    const plain = testHash(7);
    shifted[hash_bytes - 1] = 1;

    try t.expectEqual(Noted.added, try set.note(shifted));
    try t.expectEqual(Noted.added, try set.note(plain));
    try t.expectEqual(@as(usize, 2), set.count());
    try expectStatus(&set, shifted, .seen);
    try expectStatus(&set, plain, .seen);

    // And one hash confirmed does not confirm its neighbour.
    try t.expectEqual(Confirmed.verified, try set.confirm(shifted));
    try expectStatus(&set, shifted, .verified);
    try expectStatus(&set, plain, .seen);
}

// The production bound, so the number the operator picks is the one under test
// and not a smaller one that behaves the same way. The number itself is pinned
// because it is the answer to "how many blobs does this node track names for",
// and that answer must not drift silently.
test "a set full of hashes refuses one more and keeps the hashes it had" {
    // zwanzig-disable-next-line: identifier-style
    const Set = BlobSet(max_blobs);
    var set = Set.init();
    try t.expectEqual(@as(usize, 64), max_blobs);

    for (0..max_blobs) |offset| {
        try t.expectEqual(Noted.added, try set.note(testHash(@intCast(offset + 1))));
    }
    try t.expectEqual(@as(usize, max_blobs), set.count());

    // Promotion of a hash already held needs no slot, so a full set can still
    // prove what it holds — being at the bound does not freeze the state of
    // what is already in it.
    try t.expectEqual(Confirmed.verified, try set.confirm(testHash(1)));
    try expectStatus(&set, testHash(1), .verified);

    // One hash past the bound is refused, and refused rather than admitted by
    // dropping one of the sixty-four. Neither method has a slot to spare.
    const stranger = testHash(200);
    try t.expectError(error.NoFreeBlob, set.note(stranger));
    try t.expectError(error.NoFreeBlob, set.confirm(stranger));
    try t.expectEqual(@as(usize, max_blobs), set.count());
    try expectStatus(&set, stranger, null);

    // Every hash the set held is still held and still holds what it held: the
    // sixty-three sightings are sightings, and the one proof is a proof. A
    // refusal may not cost a node a fact it had, in either state.
    for (1..max_blobs) |offset| {
        try expectStatus(&set, testHash(@intCast(offset + 1)), .seen);
    }
    try expectStatus(&set, testHash(1), .verified);

    // One departure frees exactly one slot, for exactly one arrival — and one
    // slot, so the next stranger is refused again.
    try t.expect(set.forget(testHash(2)));
    try t.expectEqual(@as(usize, max_blobs) - 1, set.count());
    try t.expectEqual(Noted.added, try set.note(stranger));
    try t.expectEqual(@as(usize, max_blobs), set.count());
    try expectStatus(&set, stranger, .seen);
    try t.expectError(error.NoFreeBlob, set.note(testHash(201)));
}
