//! The Observe half: which of a set of hashes this node holds, and how much of
//! each.
//!
//! `blobs/protocol.zig` owns the wire — `ObserveRequest`, `ObserveItem` and the
//! run of length-prefixed items an answer is made of — and none of it is
//! policy. This file is the policy, and it is one rule: **an answer is a set of
//! disclosures, and a hash this node does not hold is disclosed by saying
//! nothing about it.** It has no `absent` value to return, and the reason is in
//! "Withheld, not absent" below.
//!
//! # Observe and Push do not share a policy
//!
//! Observe is a read and Push is a write, and the two powers are enforced
//! separately because they are separable: a caller may ask what a node has
//! without any power over it, and a caller with power to write has no need to
//! ask first. So this file has **no authority check at all** — no grant, no
//! callback, no seam — and `push.zig` has **no disclosure rule** and no bound.
//! Neither imports the other's types. Concretely:
//!
//! - The enforcement here is *disclosure* and a *bound*: which hashes may be
//!   named in the answer (`withheld`), and how many may be asked about at once
//!   (`error.TooManyObserved`).
//! - The enforcement there is *authority* and *ownership*: which peer may write
//!   which blob at all (`Grant`, `error.NotPermitted`), and that a write can
//!   never land on a blob this node already holds and serves
//!   (`error.AlreadyOwned`).
//!
//! Observe needing no authorization is not an oversight and it is not a
//! default. Every fact this file can disclose is already obtainable one hash at
//! a time from a `get`: a provider that does not have the blob writes nothing
//! and closes (`provider.zig`), which is the only refusal the wire has. A
//! per-hash observe policy could therefore only refuse what a batch of `get`s
//! would have disclosed anyway, and would be a second answer to a question the
//! protocol already answers one way. A Push cannot be argued the same way,
//! which is why it carries a grant and this file does not.
//!
//! # Withheld, not absent
//!
//! **An unheld hash produces no answer at all.** There is no `absent` arm, no
//! zero-length item, and no count of what was refused.
//!
//! The wire could not express one anyway. `ObserveItem` is `{ size, ranges }`
//! and a run ends at EOF, so a provider that wanted to report absence would
//! have to write an item with `size = 0` and no ranges — and `getter.zig` says
//! why that is not available: "a provider that does not have the blob writes
//! nothing, and a blob of zero bytes is answered with nothing — those are the
//! same bytes". An `absent` marker would be a second, distinguishable spelling
//! of a refusal this protocol spells one way, and every peer would have to
//! learn which spelling it got. `BaoResponse.isEof` exists precisely so that
//! nothing downstream has to.
//!
//! The second reason is that an absence would be a *false* claim here. A
//! committed pair is either both files or neither, and `store.zig` reads the
//! torn window as a miss — so "no committed pair" cannot be told apart from "a
//! pair whose outboard has not landed yet", and this store does not even serve
//! a zero-length blob (`getter.zig` refuses it by name). A provider asserting
//! `absent` would be asserting something about its own directory that its own
//! commit protocol does not support.
//!
//! What withholding does and does not hide, stated exactly: a caller learns
//! which of the hashes *it named* this node holds, and nothing else. It cannot
//! learn about a hash it did not name, and it cannot tell a withheld hash from
//! one it never asked about — the reply for an unheld hash and the reply for an
//! empty request are the same empty reply, which is the property the second test
//! below pins. A caller that needs a definite negative has `get`, where the
//! negative is a closed stream.
//!
//! # The bound is a refusal
//!
//! `max_observed` hashes at once, and a request naming more is
//! `error.TooManyObserved` with **nothing written**. A bound whose overrun
//! answers the prefix is not a bound: a caller names `max_observed` hashes,
//! learns which of those it holds, names the next `max_observed`, and walks the
//! inventory in slices — which is `blob_set.zig`'s argument against a
//! want-list that evicts, and `node/topic_table.zig`'s against a route table
//! that sheds a member to make room.
//!
//! The number is `blob_set.max_blobs` bound rather than written twice, for
//! `net/blobs_route.zig`'s reason: an observe names hashes the asker wants, the
//! set of hashes an asker wants is its `BlobSet`, and two constants that have
//! to agree and are written twice are a way for them not to agree. So a
//! conforming asker cannot build a request this refuses.
//!
//! # What "held" means here
//!
//! **Held means `store.openComplete` opened both descriptors.** The commit
//! point is the presence of `<hash>.data`, and the window between the two
//! renames of `store.commit` — outboard promoted, data still partial — is
//! refused on the *first* open by design, so it is withheld here too. There is
//! no partial availability to report: a committed pair is the whole blob, so
//! the answer's `ranges` is the intersection of what was asked about with the
//! whole blob, and `size` is the committed data file's length.
//!
//! # Purity
//!
//! `io: std.Io` and the directory are parameters and are stored nowhere; the
//! caller's `Storage` holds every buffer and is the only thing an answer
//! borrows. No clock, no environment, no global, no allocation: `answer`
//! allocates nothing and takes no allocator, for `blob_set.zig`'s reason. The
//! decision — which hashes are disclosed, and in what order — is a walk over
//! the asked list and a comparison against the store; the I/O is one open and
//! one length per asked hash.

const std = @import("std");

const blob_set = @import("blob_set.zig");
const range_spec = @import("range_spec.zig");
const ranges = @import("ranges.zig");
const store = @import("store.zig");
const tree_mod = @import("bao_tree.zig");

/// The BLAKE3 hash a blob is named by.
///
/// One type under several names in this tree — `requests.Hash`,
/// `blob_set.Hash` and `ticket/blob_ticket.Hash` are the same 32 bytes — and
/// `store.zig` says why a module may spell it for itself. This file asks the
/// store which names exist, so it spells the store's.
pub const Hash = store.Hash;

/// The chunk range set an answer carries, borrowed from the caller's storage.
pub const ChunkRangeSet = ranges.ChunkRangeSet;

/// How many hashes one observe request may name.
///
/// **A bound is a refusal.** See the module comment for why the overrun writes
/// nothing rather than answering the prefix.
pub const max_observed: usize = blob_set.max_blobs;

/// Everything that can stop an observe being answered.
pub const Error = std.Io.File.OpenError || std.Io.File.LengthError || error{
    /// The request named more than `max_observed` hashes. Nothing was written,
    /// and no store was touched: the check is the first statement in `answer`,
    /// so an over-long request costs no open and produces no partial reply.
    TooManyObserved,
    /// The caller's boundary buffer ran out while the answers were being
    /// written. The same condition `postcard.Writer` names `BufferFull` and
    /// `blobs/requests.zig` names for a decode — here there is no frame to
    /// check against, so the count is what the asked specs imply.
    NoRoom,
};

/// One hash an observer asked about, and the chunks of it.
///
/// `ranges` is a `RangeSpec` and not a sequence of blobs: an observe is about
/// one blob, which is upstream's own field type (`requests.ObserveRequest`) and
/// the reason it needs no per-child run-length encoding.
pub const Asked = struct {
    /// The blob being asked about.
    hash: Hash,
    /// The chunks of it the asker cares about. Borrowed; the widths must
    /// outlive the call.
    ranges: range_spec.RangeSpec,
};

/// What this node says about one hash it holds.
///
/// **There is no other value.** An unheld hash has no `Answer` at all; see the
/// module comment.
pub const Answer = struct {
    /// The blob this is about. Present *because* it is held: the answer's
    /// length is the disclosure, and a hash in an answer is a hash this node
    /// has a committed pair for.
    hash: Hash,
    /// The committed data file's length in bytes.
    size: u64,
    /// Which chunks were asked about and are held. Borrows
    /// `Storage.boundaries`, and only until the next `answer`.
    ranges: ChunkRangeSet,
};

/// Caller-owned storage one `answer` fills.
///
/// Nothing here is copied and nothing is owned: the answers borrow the
/// boundaries and the caller owns both, exactly as `blobs/requests.Storage`
/// documents for a decode. `boundaries` must have room for two entries per
/// selected span the asked specs resolve to, and a span per width an asked
/// spec holds — `asked.len * 2` is enough for `RangeSpec.all` and for the
/// `GetRequest.blob` sequence, and a spec with many widths needs more.
pub const Storage = struct {
    /// One slot per disclosed hash. Only `[0..Reply.len]` is written; the rest
    /// is left alone.
    answers: []Answer,
    /// The boundary lists, back to back. Only `[0..len)` is written.
    boundaries: []u64,
};

/// What an observe produced.
///
/// `answers.len` is the whole of the answer: the number of asked hashes this
/// node holds, and nothing else. The asked hashes it does not hold are absent
/// from it, and the reply for a request of one unheld hash is byte for byte
/// the reply for a request of no hashes.
pub const Reply = struct {
    /// The disclosed hashes, in the order they were asked about.
    answers: []const Answer,
    /// How many hashes were asked about, including the ones withheld. The
    /// asker knows this number already; it is here so a caller logging a
    /// refusal does not have to pass the request alongside the reply.
    asked: usize,
};

/// Answer which of `asked` this store holds whole.
///
/// `storage` is the caller's and must outlive the returned reply. Nothing is
/// allocated and no answer outlives the call it came from.
///
/// A request over `max_observed` is `error.TooManyObserved` before any store is
/// touched; a `boundaries` buffer too small is `error.NoRoom` part way through
/// the disclosures, so the caller holds the prefix that was written and no
/// reply — the same rule `blobs/requests.Storage` states for a decode that
/// ran out of room.
pub fn answer(
    io: std.Io,
    dir: std.Io.Dir,
    asked: []const Asked,
    storage: *Storage,
) Error!Reply {
    if (asked.len > max_observed) return error.TooManyObserved;

    var disclosed: usize = 0;
    var used: usize = 0;
    for (asked) |one| {
        const size = (try committedSize(io, dir, one.hash)) orelse continue;
        const tree = tree_mod.BaoTree.init(size);
        const written = try boundariesOf(one.ranges, tree.chunks(), storage.boundaries[used..]);
        storage.answers[disclosed] = .{
            .hash = one.hash,
            .size = size,
            .ranges = .{ .boundaries = storage.boundaries[used..][0..written] },
        };
        disclosed += 1;
        used += written;
    }
    return .{ .answers = storage.answers[0..disclosed], .asked = asked.len };
}

/// The committed data file's length for `hash`, or null for a hash this store
/// does not hold.
///
/// `openComplete` is the test, and not a stat of one name: it refuses the torn
/// window `store.zig` is built to make unreachable, it holds two descriptors
/// or none, and it refuses a directory standing where a half of a pair belongs.
/// A hash whose data file is here and whose outboard is not is therefore
/// withheld, which is the one honest answer — see the module comment.
fn committedSize(io: std.Io, dir: std.Io.Dir, hash: Hash) Error!?u64 {
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, hash);
    const opened = store.openComplete(io, dir, paths) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer opened.close(io);
    return try opened.data.length(io);
}

/// The boundary list of the chunks `spec` selects of a blob of `chunks` chunks,
/// written into `out` and deduplicated.
///
/// **Two rules, and both are load-bearing.**
///
/// *A whole-blob selection is the single boundary zero.* That is
/// `ChunkRangeSet.all`, the one spelling in this tree that means "every chunk,
/// whatever the blob's size", and it is what a provider holding a committed
/// pair says about one. Resolving `RangeSpec.all` against a 49-chunk blob
/// yields the span `[0, 49)` and the boundaries `[0, 49]`, which names the same
/// chunks and pins the chunk count into a field whose neighbour already carries
/// the size.
///
/// *A repeated boundary is dropped.* `resolve` hands out spans in increasing
/// offset order, but two spans can abut — a gap of width zero between two
/// selected runs resolves to `[2, 6)` and `[6, 8)` — and
/// `ChunkRangeSet.parse` drops a repeated boundary at a decode, so the wire
/// form of that set is `[2, 8]`. An answer written with the repeat would hold a
/// different boundary list from the one a peer reads back, and
/// `ChunkRangeSet.eql` compares the lists rather than the sets.
///
/// A blob of no chunks has no last chunk, so nothing is ever named as the whole
/// blob and the list stays empty: there are no chunks to claim.
fn boundariesOf(
    spec: range_spec.RangeSpec,
    chunks: u64,
    out: []u64,
) error{NoRoom}!usize {
    var walk = spec.resolve(chunks);
    var len: usize = 0;
    while (walk.next()) |span| {
        if (chunks != 0 and span.offset == 0 and span.size == chunks) {
            if (out.len < 1) return error.NoRoom;
            out[0] = 0;
            return 1;
        }
        const end = span.offset + span.size;
        if (len != 0 and out[len - 1] == span.offset) {
            out[len - 1] = end;
            continue;
        }
        if (out.len - len < 2) return error.NoRoom;
        out[len] = span.offset;
        out[len + 1] = end;
        len += 2;
    }
    return len;
}

// --- tests

const t = std.testing;
const outboard_mod = @import("bao_outboard.zig");
const postcard = @import("../wire/postcard.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

/// 49153 bytes is 49 chunks, 4 groups and 3 outboard pairs, so a held answer
/// has a range set that is not the whole blob by accident. Every blob in this
/// file's tests is this size, which is the boundary `provider.zig` and
/// `resume.zig` test at too.
const blob_size = 49153;

/// A blob over published BLAKE3 input and the root hash a caller could already
/// have held out of band.
fn blob() !struct { data: []u8, root: Hash } {
    const data = try published.blake3Input(blob_size);
    return .{ .data = data, .root = try tree_mod.BaoTree.init(data.len).rootHash(data) };
}

/// A blob committed into `dir` the way `store.zig` commits one: both partials
/// written whole, then promoted, outboard first.
fn commitBlob(dir: std.Io.Dir, data: []const u8, root: Hash) !void {
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, root);
    const tree = tree_mod.BaoTree.init(data.len);
    const outboard = try t.allocator.alloc(u8, @intCast(outboard_mod.bytes(tree)));
    defer t.allocator.free(outboard);
    const written = try outboard_mod.encode(tree, data, outboard);
    const partial = try store.createPartial(t.io, dir, paths);
    try partial.data.writeStreamingAll(t.io, data);
    try partial.outboard.writeStreamingAll(t.io, outboard[0..written]);
    partial.close(t.io);
    try store.commit(t.io, dir, paths);
}

/// A caller's `Storage` and the buffers behind it.
///
/// A value and not an allocator, for `blob_set.zig`'s reason: `answer`
/// allocates nothing, and these tests need the buffers to outlive every reply
/// read out of them, which a bare `Storage` does not promise.
const Room = struct {
    answers: [max_observed]Answer = undefined,
    boundaries: [4 * max_observed]u64 = undefined,

    /// Storage for a request of `asked_len` hashes: room for four boundaries
    /// per answer, which covers every spec in this file's tests.
    fn storage(self: *Room, asked_len: usize) Storage {
        std.debug.assert(asked_len <= max_observed);
        return .{ .answers = self.answers[0..asked_len], .boundaries = self.boundaries[0..] };
    }
};

// The honest case, and it is the only one with a value: a blob with a committed
// pair is disclosed whole, with the data file's length and a range set that
// says every chunk.
test "a committed blob is disclosed with its size and every chunk it has" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    var room: Room = .{};
    var storage = room.storage(1);
    const reply = try answer(t.io, tmp.dir, &.{
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.all },
    }, &storage);

    try t.expectEqual(@as(usize, 1), reply.answers.len);
    try t.expectEqual(@as(usize, 1), reply.asked);
    try t.expectEqual(b.root, reply.answers[0].hash);
    try t.expectEqual(@as(u64, blob_size), reply.answers[0].size);
    // Every chunk of a 49153-byte blob, which is the single boundary zero: the
    // spelling `ChunkRangeSet.isAll` recognises, and the one a peer reading
    // this answer back gets whatever the store's chunk count is.
    try t.expect(reply.answers[0].ranges.isAll());
    try t.expectEqual(@as(usize, 1), reply.answers[0].ranges.boundaries.len);
}

// The withholding rule, from both sides. An unheld hash contributes nothing to
// the answer, and the reply for a request naming only an unheld hash is the
// empty reply — the same value a request naming nothing gets, because nothing
// was written either way.
test "an unheld hash is withheld, and a reply of only withheld hashes is empty" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    const stranger: Hash = @splat(0x99);
    var room: Room = .{};
    var storage = room.storage(3);

    // A request naming three hashes, one of which is held and is named twice.
    // Two answers come back, both about the held hash: **the answer is
    // positional, so a repeated hash is disclosed as often as it is asked.**
    // That is deliberate — the reply lines up with the request, so a caller
    // pairing the two never has to guess which of its own entries an answer
    // belongs to, and a duplicate is the caller's business rather than a
    // deduplication this module performs on its behalf.
    const mixed = try answer(t.io, tmp.dir, &.{
        .{ .hash = stranger, .ranges = range_spec.RangeSpec.all },
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.all },
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.all },
    }, &storage);
    try t.expectEqual(@as(usize, 2), mixed.answers.len);
    try t.expectEqual(@as(usize, 3), mixed.asked);
    for (mixed.answers) |one| try t.expectEqual(b.root, one.hash);
    // The unheld hash is nowhere in the reply, in any form: no zero-length
    // item, no item about it at all. This is the negative space, and it is
    // what "withheld, not absent" means as a value rather than as prose.
    for (mixed.answers) |one| try t.expect(!std.mem.eql(u8, &one.hash, &stranger));

    // And the reply for the unheld hash alone is the empty reply, byte for
    // byte the one a request naming nothing gets. A caller cannot tell "you
    // asked and I hold none" from "you asked nothing".
    const alone = try answer(t.io, tmp.dir, &.{
        .{ .hash = stranger, .ranges = range_spec.RangeSpec.all },
    }, &storage);
    try t.expectEqual(@as(usize, 0), alone.answers.len);
    const nothing = try answer(t.io, tmp.dir, &.{}, &storage);
    try t.expectEqual(@as(usize, 0), nothing.answers.len);
    try t.expectEqualSlices(Answer, alone.answers, nothing.answers);
}

// A commit point of one file is not a commit point. The outboard at its
// committed name with the data still on its partial name is the window
// `store.zig` says `openComplete` must refuse on the *first* open, and the same
// state read the other way — data committed, outboard still partial — is
// refused on the *second*, after the first descriptor has been released.
// Both are withheld here, and neither is a blob this node holds.
test "a torn pair is withheld, in both orders" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();

    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, b.root);

    // Outboard promoted, data still on its partial name: the window between the
    // two renames of `store.commit`, which `openComplete` refuses on the first
    // open rather than taking a descriptor and then failing.
    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    partial.close(t.io);
    var outboard = try tmp.dir.createFile(t.io, paths.outboard, .{ .truncate = true });
    try outboard.writeStreamingAll(t.io, b.data[0 .. 3 * outboard_mod.pair_length]);
    outboard.close(t.io);
    try t.expectError(error.FileNotFound, store.openComplete(t.io, tmp.dir, paths));

    var room: Room = .{};
    var storage = room.storage(1);
    const torn = try answer(t.io, tmp.dir, &.{
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.all },
    }, &storage);
    try t.expectEqual(@as(usize, 0), torn.answers.len);

    // The other order: promote the data as well, so both committed names exist,
    // and then take the outboard away. The data file is still here and its
    // outboard is gone, which is the window `store.zig` reads the other way
    // round and refuses on the *second* open. It is withheld for the same
    // reason, which is what "held means `openComplete` opened both descriptors"
    // says as a rule rather than as a sentence.
    try std.Io.Dir.rename(tmp.dir, paths.data_partial, tmp.dir, paths.data, t.io);
    try tmp.dir.deleteFile(t.io, paths.outboard);
    const orphan = try answer(t.io, tmp.dir, &.{
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.all },
    }, &storage);
    try t.expectEqual(@as(usize, 0), orphan.answers.len);
}

// The bound refuses and writes nothing. The sentinels are how "nothing was
// written" is observed: a bound that answered the prefix would leave real hashes
// in the answer slots and real chunk numbers in the boundary slots.
test "a request over the bound is refused, and writes no answer" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    try t.expectEqual(@as(usize, 64), max_observed);

    // Two sentinels, one per buffer, so "nothing was written" is observed in
    // both: a bound that answered the prefix would leave real hashes in the
    // answer slots and real chunk numbers in the boundary slots.
    const no_hash: Hash = @splat(0xee);
    const no_boundary: u64 = 0xffff_ffff_ffff_ffff;
    var asked: [max_observed + 1]Asked = undefined;
    for (&asked, 0..) |*one, index| {
        one.* = .{
            .hash = if (index == 0) b.root else @splat(@intCast(index)),
            .ranges = range_spec.RangeSpec.all,
        };
    }

    var room: Room = .{};
    var storage = room.storage(max_observed);
    for (storage.answers) |*one| one.hash = no_hash;
    @memset(storage.boundaries, no_boundary);

    try t.expectError(error.TooManyObserved, answer(t.io, tmp.dir, &asked, &storage));
    for (storage.answers) |one| try t.expectEqual(no_hash, one.hash);
    for (storage.boundaries) |boundary| try t.expectEqual(no_boundary, boundary);

    // One hash fewer is answered in full, so the refusal is the bound and not a
    // shape of request refused for some other reason. Only the first of these
    // sixty-four is a blob this store holds, so the reply is one answer and
    // sixty-three withholdings — which is the bound's shape and not the bound's
    // absence: the request was read, in full, and the disclosure inside it is
    // what came back.
    const roomier = try answer(t.io, tmp.dir, asked[0..max_observed], &storage);
    try t.expectEqual(@as(usize, 1), roomier.answers.len);
    try t.expectEqual(b.root, roomier.answers[0].hash);
    try t.expectEqual(@as(u64, blob_size), roomier.answers[0].size);
}

// Two spans that abut are one boundary list, and the list the answer holds is
// the list a peer reads back. `resolve` yields `[2, 6)` and `[6, 8)` for a spec
// whose middle gap is zero chunks wide; the wire form of that set is `[2, 8]`,
// so an answer written with the repeat would not equal its own decode.
test "two spans that abut are one deduplicated boundary list" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    var room: Room = .{};
    var storage = room.storage(2);
    // A gap of two, four selected, a gap of *zero*, two more selected: the two
    // runs touch at chunk four.
    const abutting = [_]u64{ 2, 4, 0, 2 };
    const reply = try answer(t.io, tmp.dir, &.{
        .{ .hash = b.root, .ranges = .{ .widths = &abutting } },
        // The same set spelled without the zero gap, which resolves to one span.
        .{ .hash = b.root, .ranges = .{ .widths = &.{ 2, 6 } } },
    }, &storage);

    try t.expectEqual(@as(usize, 2), reply.answers.len);
    try t.expectEqualSlices(u64, &.{ 2, 8 }, reply.answers[0].ranges.boundaries);
    try t.expect(reply.answers[0].ranges.eql(reply.answers[1].ranges));

    // And the list round-trips through the codec as the same set, which is the
    // claim the deduplication exists to make: what this answer says, a peer
    // reading the wire form says too. `parse` sorts and deduplicates, so a
    // repeated boundary written here would come back as a different list.
    var frame: [64]u8 = undefined;
    var writer = postcard.Writer.init(&frame);
    try reply.answers[0].ranges.write(&writer);
    const wire = writer.finish();
    var reader = postcard.Reader.init(wire);
    var read_back: [8]u64 = undefined;
    const decoded = try ChunkRangeSet.parse(&reader, &read_back);
    try t.expect(reply.answers[0].ranges.eql(decoded));
}

// A spec is read against the blob, and `resolve`'s three rules about that are
// visible in what an answer reports. A span past the end of the blob is the
// last chunk, which is what makes `RangeSpec.verified_size` a way to ask for a
// size; a blob of no chunks selects nothing at all; and a spec past the end of
// a zero-length blob is still nothing, because such a blob has no last chunk.
test "the asked chunks are resolved against the blob, not against the request" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    var room: Room = .{};
    var storage = room.storage(4);
    const reply = try answer(t.io, tmp.dir, &.{
        // A gap of a thousand chunks and one selected: past the end of a
        // 49-chunk blob, so the last chunk and not chunk 1000.
        .{ .hash = b.root, .ranges = .{ .widths = &.{ 1000, 1 } } },
        // `verified_size` is that spec spelled as upstream spells it.
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.verified_size },
        // A spec that selects nothing, on a blob that is here. The blob is
        // still disclosed: it is held, and what was asked about is nothing.
        .{ .hash = b.root, .ranges = range_spec.RangeSpec.empty },
        // An in-range selection, reported as asked for.
        .{ .hash = b.root, .ranges = .{ .widths = &.{ 20, 2 } } },
    }, &storage);

    try t.expectEqual(@as(usize, 4), reply.answers.len);
    for (reply.answers) |one| try t.expectEqual(@as(u64, blob_size), one.size);
    try t.expectEqualSlices(u64, &.{ 48, 49 }, reply.answers[0].ranges.boundaries);
    try t.expectEqualSlices(u64, &.{ 48, 49 }, reply.answers[1].ranges.boundaries);
    try t.expect(reply.answers[2].ranges.isEmpty());
    try t.expectEqualSlices(u64, &.{ 20, 22 }, reply.answers[3].ranges.boundaries);
}

// A boundary buffer too small refuses rather than truncating: the answer that
// would have been written is not written, so a caller cannot hold a reply whose
// range set is a prefix of the truth. The spec names a span of two chunks, so
// it needs two boundaries and one slot is what it runs out of — a whole-blob
// spec would fit in the single boundary it is spelled with.
test "a boundary buffer too small refuses, and writes no answer for that hash" {
    const b = try blob();
    defer t.allocator.free(b.data);
    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.root);

    const no_hash: Hash = @splat(0xee);
    const no_boundary: u64 = 0xffff_ffff_ffff_ffff;
    var room: Room = .{};
    var storage: Storage = .{
        .answers = room.answers[0..1],
        .boundaries = room.boundaries[0..1],
    };
    storage.answers[0].hash = no_hash;
    @memset(storage.boundaries, no_boundary);

    try t.expectError(error.NoRoom, answer(t.io, tmp.dir, &.{
        .{ .hash = b.root, .ranges = .{ .widths = &.{ 20, 2 } } },
    }, &storage));
    try t.expectEqual(no_hash, storage.answers[0].hash);
    // The one boundary slot is untouched too: the check is before the write, so
    // a refusal leaves no half-written range set for a caller to read.
    try t.expectEqual(no_boundary, storage.boundaries[0]);
}

// A blob of no bytes has a committed pair like any other, so it is disclosed —
// and what it discloses is a size of zero and no chunks, which is a fact about
// this blob rather than the absence of an answer. A caller cannot read it as a
// refusal, because a refused hash produces no answer at all.
test "a committed blob of no bytes is disclosed with a size of zero" {
    const data = try published.blake3Input(0);
    defer t.allocator.free(data);
    const tree = tree_mod.BaoTree.init(0);
    const root: Hash = try tree.rootHash(data);
    try t.expectEqual(@as(u64, 0), tree.chunks());

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, data, root);

    var room: Room = .{};
    var storage = room.storage(1);
    const reply = try answer(t.io, tmp.dir, &.{
        .{ .hash = root, .ranges = range_spec.RangeSpec.all },
    }, &storage);

    try t.expectEqual(@as(usize, 1), reply.answers.len);
    try t.expectEqual(root, reply.answers[0].hash);
    try t.expectEqual(@as(u64, 0), reply.answers[0].size);
    try t.expect(reply.answers[0].ranges.isEmpty());
}
