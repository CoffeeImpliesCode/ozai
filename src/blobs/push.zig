//! The Push half: writing a blob into this node's storage, and what a caller
//! must hold to be allowed to.
//!
//! `blobs/protocol.zig` owns the wire — `PushRequest` is a `GetRequest` under a
//! different discriminant and a length-prefixed framing, and the payload is the
//! bao data that follows it on the same stream — and none of it is policy. This
//! file is the policy, and it is the half of the pair that needs one.
//!
//! # Observe and Push do not share a policy
//!
//! Observe is a read and Push is a write, and the enforcement is separate
//! because the powers are separable. `observe.zig` has **no authority check at
//! all**, and that is not an oversight: every fact it can disclose is already
//! obtainable one hash at a time from a `get`, because a provider that does not
//! have the blob writes nothing and closes (`provider.zig`), so a per-hash
//! observe policy could only refuse what a batch of `get`s would have disclosed
//! anyway. This file cannot be argued the same way — a refused `get` costs a
//! round trip, a refused push costs the pusher nothing and costs this node its
//! disk — so the grant lives here and only here.
//!
//! The two files share no type and neither imports the other. Concretely:
//!
//! - `observe.zig` enforces *disclosure* and a *bound*: which hashes may appear
//!   in an answer, and how many may be asked about at once.
//! - This file enforces *authority* (`Grant`) and *ownership* (the committed
//!   pair, below). There is no disclosure rule here, and no bound on how many
//!   blobs a caller may observe.
//!
//! # What authority a Push requires, and where it is checked
//!
//! **A grant naming the peer, the blob and the blob's size, compared against
//! the connection and the request at the top of `admit` before a single file is
//! opened.** Not "an authenticated peer": a Push that is merely authenticated
//! is a disk-fill primitive, because any peer that completed a handshake could
//! name any hash and any byte count and this node would take them. Every
//! mismatch is `error.NotPermitted` — one refusal for all three arms, so a
//! refused push reveals nothing about which of them failed.
//!
//! The check is where it is because of what is on the other side of it. `admit`
//! is the only path that reaches `store.createPartial`, and a file created is a
//! file a writer died on top of: `resume.zig` then finds a `.partial` on disk
//! and must decide whether to adopt or discard it. **Refusing after the open
//! would leave the refusal's evidence behind**, so the grant is compared first
//! and the directory is not touched until it passes. The tests at the bottom
//! pin that by pointing a refused push at a real directory and asserting the
//! directory is still empty afterwards.
//!
//! `Grant.size` is what makes the ceiling real. A grant for a hash with no
//! stated size is a grant to fill the disk: a pusher authorised to write one
//! blob is not thereby authorised to write a hundred gigabytes under its name.
//! The size is also what `resume.settle` needs to cut a tree for, so a grant
//! that carried only a ceiling would leave the resume decision with no size to
//! check the checkpoint's against.
//!
//! # Ownership: what a Push must not be able to do to a committed blob
//!
//! **A Push may not overwrite, truncate, or partially replace a blob this node
//! already holds.** It is refused `error.AlreadyOwned`, tested on
//! `store.openComplete` succeeding — the same test `provider.zig` uses to decide
//! it has a blob, so "owned" and "answerable" are one fact here and not two.
//!
//! Three reasons, each a corruption path rather than a preference:
//!
//! 1. **Bytes a peer pushed are not bytes this node proved.** `blob_set.zig`
//!    draws the line exactly: a hash a peer named is `.seen`, a name worth
//!    spending a fetch on, and only `confirm` — which takes a hash and nothing
//!    else, so there is nothing in it for a peer to talk into — promotes it. A
//!    push is a peer's word about bytes, so it cannot be a reason to replace
//!    bytes this node walked to a trusted root.
//! 2. **Overwriting is a rename, and `store.commit` renames the outboard
//!    first.** A push that renamed over a committed pair would tear it: a
//!    reader between the two renames sees the new outboard beside the old
//!    data. `store.zig` orders its renames so that window reads as a *miss*
//!    for a blob being written from nothing; it cannot also make it safe for a
//!    blob being replaced.
//! 3. **A peer can re-push at any time.** Without this rule the held set would
//!    be whatever the last peer to push happened to send, which makes the
//!    store's contents a function of traffic rather than of proof. With it, a
//!    held blob is held until this node decides otherwise, and `forget` is the
//!    only way out.
//!
//! A refusal costs the pusher nothing it can act on: the store's answer for a
//! blob it already holds is the same answer it gives for one it never had, and
//! that is `observe.zig`'s withheld answer as much as it is this file's
//! `AlreadyOwned`.
//!
//! # An interrupted Push, and why it does not adopt resume's rule
//!
//! **`resume.zig` settles an interrupted transfer, and a Push is settled the
//! same way — by discarding.** `admit` calls `resume.settle`, and a push whose
//! caller offers no verified prefix comes back with a fresh, empty pair. That is
//! the reuse, and the reuse *is* the decision rather than a shortcut.
//!
//! The difference from an interrupted **Get** is who the bytes came from, and
//! it is the whole of the difference:
//!
//! - On a **Get**, the partial holds bytes this node chose to receive from a
//!   peer, checked against a trusted root it already held out of band.
//!   `resume.zig`'s rule — resume only where the prefix re-hashes to a chaining
//!   value the caller holds — is checkable there, and it is the only reason a
//!   get may resume at all.
//! - On a **Push**, the partial holds bytes a peer sent to be stored here, and
//!   there is no trusted root in hand for them. The hash the request names is
//!   the pusher's own claim, which `blob_set.zig` says is `.seen` and never
//!   `.verified`. So no out-of-band value exists to verify a prefix against:
//!   `settle` finds a partial it cannot match and returns a restart.
//!
//! **So the answer to "does Push reuse the verified-resume rule" is: it reuses
//! the code and rejects the rule, deliberately, because the precondition that
//! rule exists to check cannot be met by a pusher's own word.** A `settle` that
//! adopted a pushed prefix would be adopting an unverified claim about bytes,
//! which is the one thing `blob_set.zig`'s promotion rule exists to prevent. A
//! push that died is a push that starts again, and that is the correct outcome
//! rather than a degraded one: the bytes are refetchable and a wrong blob is
//! not.
//!
//! # The commit point, and the window it closes
//!
//! `promote` is the only function here that calls `store.commit`, and it
//! re-checks `openComplete` first. **That re-check is load-bearing**: `admit`
//! and `promote` are two calls with a stream of bytes between them, and nothing
//! in this store locks, so a blob committed by something else in that window
//! would be renamed over. One open closes it.
//!
//! # Purity
//!
//! `io: std.Io` is a parameter of every call and is stored nowhere. Nothing
//! here reads a clock, the environment or a global, and nothing allocates: the
//! descriptors are `store.Handles` and the caller's scratch is borrowed. The
//! decisions — grant, ownership, size — are plain comparisons over values, and
//! the I/O is the store calls they gate.

const std = @import("std");

const base_key = @import("../base/key.zig");
const requests = @import("requests.zig");
// `resume` is a Zig keyword, so the module is reached under a name that is not.
const resume_mod = @import("resume.zig");
const store = @import("store.zig");
const tree_mod = @import("bao_tree.zig");

/// The node id a grant is issued to. `base/key.zig` owns it; this file spells it
/// for the reason `store.zig` spells `Hash`.
pub const NodeId = base_key.NodeId;

/// The BLAKE3 hash a blob is named by.
///
/// One type under several names in this tree — `requests.Hash`,
/// `blob_set.Hash` and `ticket/blob_ticket.Hash` are the same 32 bytes — and
/// this file asks the store which names exist, so it spells the store's.
pub const Hash = store.Hash;

/// The tree a pushed blob is cut for. `bao_tree.zig` owns it.
pub const BaoTree = tree_mod.BaoTree;

/// A `PushRequest` as the protocol hands one over, bound rather than re-spelled.
pub const PushRequest = requests.PushRequest;

/// What a pusher must hold to be allowed to write.
///
/// **This is the whole of the authority model, and it is a value rather than a
/// callback.** `relay/access_policy.zig` needs a function pointer because an
/// operator's rule about which clients to admit is not a value anybody can
/// state; a rule about which blob a peer may write is one, and making it a value
/// means the decision is inspectable, comparable and testable with no seam at
/// all. A caller wanting a policy computes one `Grant` per request from whatever
/// it already has — a ticket, a subscription, an allowlist — and this file only
/// checks that the value covers the request.
pub const Grant = struct {
    /// The node this grant was issued to. **A grant names one peer and one
    /// blob**, so a push from another node, or from this node for another hash,
    /// is refused; see the module comment for why one refusal covers both.
    peer: NodeId,
    /// The blob that peer may write.
    ///
    /// Compared against `request.get.hash` with `std.mem.eql` across all 32
    /// bytes and never with `==`, because this build forbids `==` on aggregates.
    /// It is a value comparison and not an order one: `net/node_relay_route.zig`'s
    /// `.order(x) != .eq` is for two-field values, while `blob_set.zig` compares
    /// hashes with `std.mem.eql` and this is that case.
    hash: Hash,
    /// The blob's size in bytes, which is also the grant's ceiling.
    ///
    /// **A grant for a hash with no stated size is a grant to fill the disk**: a
    /// pusher authorised to write one blob is not thereby authorised to write a
    /// hundred gigabytes under its name. Zero is a grant to write nothing, which
    /// is a refusal the caller can detect rather than a default. It is also the
    /// number `resume.zig`'s `settle` needs to cut a tree for, so a grant carrying
    /// only a ceiling would leave the resume decision with no size to check the
    /// checkpoint's size against.
    size: u64,
};

/// Everything that can stop a push being admitted, written, or promoted.
///
/// `resume.Error` is here rather than spelled out because `admit` is a thin
/// wrapper over `resume.settle`, and re-listing its arms would be a second
/// vocabulary for one set of refusals.
pub const Error = resume_mod.Error ||
    std.Io.File.OpenError ||
    std.Io.Dir.RenameError ||
    error{
        /// The request's hash is not the grant's, or the connection's node id is
        /// not the grant's peer, or the checkpoint's declared size is not the
        /// grant's.
        ///
        /// **Checked before the directory is touched**, so a refused push leaves
        /// no `.partial` behind for `resume.zig` to find on the next attempt.
        /// One arm for all three conditions because all three are "this grant
        /// does not cover this request", and a caller that could tell them apart
        /// could probe which grants exist.
        NotPermitted,
        /// This node already holds the blob: `store.openComplete` opened a
        /// committed pair. A push may not overwrite, truncate or partially
        /// replace what this node already holds and serves.
        AlreadyOwned,
        /// The verified prefix is not the whole blob, so the two halves of the
        /// pair would be renamed into place describing different amounts of one
        /// transfer. `resume.settle` already refuses a data partial shorter than
        /// the checkpoint's offset, so reaching this means the caller is
        /// promoting a transfer it has not finished.
        Incomplete,
    };

/// A push admitted and ready for bytes.
///
/// It carries the partial descriptors *and* the names they were opened under,
/// and both come from the grant: `admit` builds the names from `grant.hash`
/// itself, so a caller holding a `Writing` can reach no other blob's names than
/// the ones its grant named.
pub const Writing = struct {
    /// The four names, borrowing the caller's `NameStorage`, which must
    /// therefore outlive this value.
    paths: store.Names,
    /// The blob's size, which is the grant's size. `promote` needs it to tell a
    /// finished transfer from an unfinished one, and it is a value rather than
    /// something re-derived from a directory.
    size: u64,
    /// The two partial descriptors, open read/write. Release with `close`.
    handles: store.Handles,

    /// Release both descriptors. There is no way to release one, which is the
    /// point of `store.Handles`.
    pub fn close(self: Writing, io: std.Io) void {
        self.handles.close(io);
    }
};

/// Admit a push of `request` from `peer`, if `grant` covers it and this node
/// does not already hold the blob.
///
/// This is the only path to a writable pair in this module, and it is where the
/// grant is checked: the refusals precede every store call, so a refused push
/// leaves the directory exactly as it found it. The names are built from
/// `grant.hash` and not from `request.get.hash`, which by then are the same 32
/// bytes or the call has already returned — so a `Writing` cannot be pointed at
/// a blob its grant does not name.
///
/// `name_storage` and `scratch` are the caller's and must outlive `Writing`: the
/// names borrow the storage and the descriptors are open. `scratch` only has to
/// be one byte long; it is a throughput knob, and `resume.settle` refuses an
/// empty one wherever a prefix would be hashed.
///
/// `checkpoint` is the caller's resume point as `resume.settle` defines it: an
/// offset, the size it belongs to, and the chaining value of the bytes below it.
/// A caller with nothing to resume passes `nothing(grant.size)` — an offset of
/// zero and a chaining value no prefix has — which verifies nothing and so
/// discards whatever was there. See the module comment for why that is what a
/// push wants.
pub fn admit(
    io: std.Io,
    dir: std.Io.Dir,
    name_storage: *store.NameStorage,
    peer: NodeId,
    request: PushRequest,
    grant: Grant,
    checkpoint: resume_mod.Checkpoint,
    scratch: []u8,
) Error!Writing {
    if (peer.order(grant.peer) != .eq) return error.NotPermitted;
    if (!std.mem.eql(u8, &grant.hash, &request.get.hash)) return error.NotPermitted;
    if (grant.size == 0 or checkpoint.size != grant.size) return error.NotPermitted;

    const paths = store.names(name_storage, grant.hash);
    if (try owned(io, dir, paths)) return error.AlreadyOwned;

    const settled = try resume_mod.settle(
        io,
        dir,
        paths,
        BaoTree.init(grant.size),
        checkpoint,
        scratch,
    );
    return .{ .paths = paths, .size = grant.size, .handles = settled.handles };
}

/// Promote a push whose bytes are written and whose caller has verified them.
///
/// `at` is where the caller's own verification of the bytes reached, and it must
/// be the whole blob. A committed pair is two files renamed into place
/// together, and a data file shorter than the transfer it belongs to is exactly
/// what `store.openComplete` refuses as the torn window — so this catches it
/// before the rename instead of leaving it for the next reader.
///
/// **The committed pair is re-checked before the rename**, and that is
/// load-bearing: `admit` and `promote` are two calls with a stream of bytes
/// between them, and nothing in this store locks, so a blob committed by
/// something else in that window would be renamed over. One open closes it.
///
/// The descriptors are not closed here: `store.commit`'s own comment says the
/// pair is committed by name and not by an open file, so a caller closes its
/// `Writing` when it has finished writing and this function holds nothing.
pub fn promote(io: std.Io, dir: std.Io.Dir, writing: Writing, at: u64) Error!void {
    if (at != writing.size) return error.Incomplete;
    if (try owned(io, dir, writing.paths)) return error.AlreadyOwned;
    try store.commit(io, dir, writing.paths);
}

/// The checkpoint that verifies nothing, for a caller with nothing to resume.
///
/// Offset zero and a chaining value no prefix of a real blob hashes to, so
/// `settle` takes its restart path whatever is on disk. A pusher is the case
/// this exists for: the partial under a push is a peer's own unverified words,
/// and the module comment says why resuming one is refused.
pub fn nothing(size: u64) resume_mod.Checkpoint {
    return .{ .size = size, .at = 0, .cv = @splat(0) };
}

/// Whether a committed pair is already at `paths`.
///
/// `openComplete` and not a stat of the data name alone. The data file's
/// presence is the commit point, but a data file without its outboard is the
/// torn window `store.zig` exists to make unreachable, and treating that as
/// owned would make a push wait behind a state no reader will accept. It is
/// opened as a pair or not at all, and both descriptors are released here.
fn owned(io: std.Io, dir: std.Io.Dir, paths: store.Names) Error!bool {
    const opened = store.openComplete(io, dir, paths) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    opened.close(io);
    return true;
}

// --- tests

const t = std.testing;
const outboard_mod = @import("bao_outboard.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");
const test_ids = @import("../relay/relay_test_ids.zig");

/// 49153 bytes is 49 chunks, 4 groups and 3 outboard pairs, so a pushed blob
/// has a real outboard and promoting it renames two non-empty files. It is the
/// size `provider.zig`, `resume.zig` and `observe.zig` all test at.
const blob_size = 49153;

/// A blob over published BLAKE3 input, its tree, and the root hash a grant
/// names.
fn blob() !struct { data: []u8, tree: BaoTree, root: Hash } {
    const data = try published.blake3Input(blob_size);
    const tree = BaoTree.init(data.len);
    return .{ .data = data, .tree = tree, .root = try tree.rootHash(data) };
}

/// A whole-blob push for `hash`, spelled the way the protocol spells one:
/// `PushRequest` over `requests.blob_ranges`, which is one selected spec at the
/// blob and an empty spec one blob on to end the run. The array is a module
/// constant, so the borrow outlives every request below.
fn wholeBlobPush(hash: Hash) PushRequest {
    return PushRequest.new(hash, .{ .items = &requests.blob_ranges });
}

/// Whether either partial name exists in `dir`.
fn anyPartial(dir: std.Io.Dir, paths: store.Names) !bool {
    const found = try resume_mod.inspect(t.io, dir, paths);
    return found.data_bytes != 0 or found.outboard_bytes != 0;
}

/// A blob committed the way `store.zig` commits one: both partials written
/// whole, then promoted, outboard first.
fn commitBlob(dir: std.Io.Dir, data: []const u8, tree: BaoTree, root: Hash) !void {
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, root);
    var outboard: [3 * outboard_mod.pair_length]u8 = undefined;
    const written = try outboard_mod.encode(tree, data, &outboard);
    const partial = try store.createPartial(t.io, dir, paths);
    try partial.data.writeStreamingAll(t.io, data);
    try partial.outboard.writeStreamingAll(t.io, outboard[0..written]);
    partial.close(t.io);
    try store.commit(t.io, dir, paths);
}

// The authority rule, arm by arm. A push whose peer is not the grant's, whose
// hash is not the grant's, or whose size is not the grant's, is refused — and
// refused *before the directory is touched*, so nothing is left behind. The
// emptiness check is the part that matters: a refusal after the open would leave
// a `.partial` for `resume.settle` to find on the next attempt, which is a
// refusal that costs the next one.
test "a push the grant does not cover is refused, and writes nothing" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);
    const stranger = try test_ids.testNodeId(22);
    const other_hash: Hash = @splat(0x44);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();

    const cases = [_]struct { name: []const u8, peer: NodeId, hash: Hash, size: u64 }{
        .{ .name = "another peer", .peer = stranger, .hash = b.root, .size = blob_size },
        .{ .name = "another blob", .peer = peer, .hash = other_hash, .size = blob_size },
        .{ .name = "another size", .peer = peer, .hash = b.root, .size = blob_size - 1 },
        .{ .name = "no size at all", .peer = peer, .hash = b.root, .size = 0 },
    };
    for (cases) |case| {
        var name_storage: store.NameStorage = undefined;
        var scratch: [64]u8 = undefined;
        const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };
        const request = wholeBlobPush(case.hash);
        const checkpoint = nothing(case.size);
        try t.expectError(error.NotPermitted, admit(
            t.io,
            tmp.dir,
            &name_storage,
            case.peer,
            request,
            grant,
            checkpoint,
            &scratch,
        ));
        // Nothing was created: no partial under the grant's hash, and none
        // under the hash the request asked about either.
        try t.expect(!try anyPartial(tmp.dir, store.names(&name_storage, b.root)));
        try t.expect(!try anyPartial(tmp.dir, store.names(&name_storage, case.hash)));
        // And no committed pair, so the refusals cost this node nothing at all.
        try t.expectError(error.FileNotFound, store.openComplete(
            t.io,
            tmp.dir,
            store.names(&name_storage, b.root),
        ));
    }
}

// The grant covers the request, and the pair opens for writing with nothing in
// it. The descriptors are two and they are the partial names, so a caller
// writing through them cannot reach the committed pair.
test "a covered push is admitted, and writes only under the partial names" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    var name_storage: store.NameStorage = undefined;
    var scratch: [64]u8 = undefined;
    const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };

    const writing = try admit(
        t.io,
        tmp.dir,
        &name_storage,
        peer,
        wholeBlobPush(b.root),
        grant,
        nothing(blob_size),
        &scratch,
    );
    try t.expectEqual(blob_size, writing.size);
    // The names are the grant's hash's names and not the request's, built here
    // into storage of their own: a `Writing` reached by any other route would
    // let a caller write under a blob its grant never named.
    var expected_names: store.NameStorage = undefined;
    const named = store.names(&expected_names, grant.hash);
    try t.expectEqualStrings(named.data, writing.paths.data);
    try t.expectEqualStrings(named.data_partial, writing.paths.data_partial);
    // Both partials exist and are empty, and the committed pair does not: this
    // is a transfer in progress, which is the only state `admit` leaves.
    try t.expectEqual(resume_mod.Found{}, try resume_mod.inspect(t.io, tmp.dir, writing.paths));
    try t.expectEqual(@as(u64, 0), try writing.handles.data.length(t.io));
    try t.expectEqual(@as(u64, 0), try writing.handles.outboard.length(t.io));
    try t.expectError(error.FileNotFound, store.openComplete(t.io, tmp.dir, writing.paths));
    writing.close(t.io);
}

// Ownership, arm one: a push onto a blob this node already holds is refused,
// and the committed pair is untouched afterwards. The grant covers the request
// exactly, so the only thing standing between the push and the store is the
// ownership check.
test "a push onto a blob this node already holds is refused, and the blob survives" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try commitBlob(tmp.dir, b.data, b.tree, b.root);

    var name_storage: store.NameStorage = undefined;
    var scratch: [64]u8 = undefined;
    const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };
    try t.expectError(error.AlreadyOwned, admit(
        t.io,
        tmp.dir,
        &name_storage,
        peer,
        wholeBlobPush(b.root),
        grant,
        nothing(blob_size),
        &scratch,
    ));

    // The committed blob is byte for byte what it was. This is the assertion
    // the rule is for: a push that renamed over it would have replaced the
    // outboard and left the data to be torn against it.
    const paths = store.names(&name_storage, b.root);
    const handles = try store.openComplete(t.io, tmp.dir, paths);
    defer handles.close(t.io);
    try t.expectEqual(@as(u64, blob_size), try handles.data.length(t.io));
    try t.expectEqual(@as(u64, 3 * outboard_mod.pair_length), try handles.outboard.length(t.io));
    var read_back: [blob_size]u8 = undefined;
    const read = try handles.data.readPositionalAll(t.io, &read_back, 0);
    try t.expectEqual(@as(usize, blob_size), read);
    try t.expectEqualSlices(u8, b.data, &read_back);
}

// The interrupted-push rule, and it is the reuse of `resume.zig` rather than a
// bypass of it. A partial holding real bytes of the real blob — bytes a caller
// could verify if it held a checkpoint it trusted — is still discarded, because
// the only checkpoint this caller can offer is its own unverified word and the
// offset it names is zero. A push that died starts again.
test "an interrupted push is discarded rather than resumed, even when the bytes are right" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, b.root);

    // A dead pusher's partial: the first twenty kilobytes of the blob and an
    // outboard written beside them, exactly as `admit` would have left it.
    const at: usize = 20 * 1024;
    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data[0..at]);
    var outboard: [3 * outboard_mod.pair_length]u8 = undefined;
    try partial.outboard.writeStreamingAll(t.io, outboard[0..try outboard_mod.encode(
        b.tree,
        b.data,
        &outboard,
    )]);
    partial.close(t.io);
    const found = try resume_mod.inspect(t.io, tmp.dir, paths);
    try t.expectEqual(@as(u64, at), found.data_bytes);

    // The push is admitted, and the partial is gone: `settle` took its restart
    // path, so both files come back empty rather than one of them keeping the
    // bytes and the other not. This is the negative space of the reuse — a
    // `settle` that adopted the prefix would have handed the pusher a `Writing`
    // whose data file already held twenty kilobytes it never verified.
    var scratch: [64]u8 = undefined;
    const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };
    const writing = try admit(
        t.io,
        tmp.dir,
        &name_storage,
        peer,
        wholeBlobPush(b.root),
        grant,
        nothing(blob_size),
        &scratch,
    );
    try t.expectEqual(@as(u64, 0), try writing.handles.data.length(t.io));
    try t.expectEqual(@as(u64, 0), try writing.handles.outboard.length(t.io));
    writing.close(t.io);
    try t.expectEqual(resume_mod.Found{}, try resume_mod.inspect(t.io, tmp.dir, paths));
    // The outboard is emptied and never resumed, which is `resume.zig`'s own
    // rule: nothing in a push checked the pairs, so nothing may keep them.
    try t.expectError(error.FileNotFound, store.openComplete(t.io, tmp.dir, paths));
}

// The happy path end to end: admit, write the data and the outboard, promote.
// The committed pair is the blob, and `provider.zig`'s own store of it is the
// test that the result is servable rather than merely present.
test "a completed push commits the pair, and the pair is the blob" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    var name_storage: store.NameStorage = undefined;
    var scratch: [64]u8 = undefined;
    const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };

    const writing = try admit(
        t.io,
        tmp.dir,
        &name_storage,
        peer,
        wholeBlobPush(b.root),
        grant,
        nothing(blob_size),
        &scratch,
    );
    var outboard: [3 * outboard_mod.pair_length]u8 = undefined;
    const written = try outboard_mod.encode(b.tree, b.data, &outboard);
    try writing.handles.data.writeStreamingAll(t.io, b.data);
    try writing.handles.outboard.writeStreamingAll(t.io, outboard[0..written]);
    writing.close(t.io);

    try promote(t.io, tmp.dir, writing, blob_size);

    // The pair opens, its lengths are the tree's, and the data hashes to the
    // hash the grant named — so a provider serving it would serve this blob.
    const handles = try store.openComplete(t.io, tmp.dir, writing.paths);
    defer handles.close(t.io);
    try t.expectEqual(outboard_mod.bytes(b.tree), try handles.outboard.length(t.io));
    var read_back: [blob_size]u8 = undefined;
    try t.expectEqual(
        @as(usize, blob_size),
        try handles.data.readPositionalAll(t.io, &read_back, 0),
    );
    try t.expectEqual(b.root, try b.tree.rootHash(&read_back));
    // And the partial names are gone, which is what makes the second push below
    // an ownership refusal rather than a second commit.
    try t.expectEqual(resume_mod.Found{}, try resume_mod.inspect(t.io, tmp.dir, writing.paths));
}

// Two refusals on the commit point, and they are different facts. A transfer
// the caller has not verified to its end is `Incomplete` and renames nothing; a
// blob that became committed between `admit` and `promote` is `AlreadyOwned`
// and renames nothing either. The second is the window this store has no lock
// for, so it is checked at the last possible moment instead.
test "promote refuses an unfinished transfer, and refuses a blob committed meanwhile" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const peer = try test_ids.testNodeId(21);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    var name_storage: store.NameStorage = undefined;
    var scratch: [64]u8 = undefined;
    const grant: Grant = .{ .peer = peer, .hash = b.root, .size = blob_size };

    const writing = try admit(
        t.io,
        tmp.dir,
        &name_storage,
        peer,
        wholeBlobPush(b.root),
        grant,
        nothing(blob_size),
        &scratch,
    );
    try writing.handles.data.writeStreamingAll(t.io, b.data[0..2048]);
    writing.close(t.io);

    // The bytes are on disk and the transfer is nowhere near finished. Nothing
    // is renamed, so the store reads the blob as absent rather than as the torn
    // pair a partial promotion would have left.
    try t.expectError(error.Incomplete, promote(t.io, tmp.dir, writing, 2048));
    try t.expectError(error.FileNotFound, store.openComplete(t.io, tmp.dir, writing.paths));

    // Now the blob is committed by something else in the window, and a promote
    // that did not re-check would rename over it. The grant is unchanged and
    // the request would be admitted again — only this check stands in the way.
    try commitBlob(tmp.dir, b.data, b.tree, b.root);
    try t.expectError(error.AlreadyOwned, promote(t.io, tmp.dir, writing, blob_size));

    const handles = try store.openComplete(t.io, tmp.dir, writing.paths);
    defer handles.close(t.io);
    try t.expectEqual(@as(u64, blob_size), try handles.data.length(t.io));
}

// The grant is a value and the check is over values, so a grant issued to one
// peer is useless to another and a grant for one blob is useless for another.
// Both directions of that are the same comparison, and the test says so rather
// than leaving it to the arm-by-arm test above: swapping the two node ids in a
// grant changes nothing about which push is admitted.
test "a grant is for one peer and one blob, and swapping either changes the answer" {
    const b = try blob();
    defer t.allocator.free(b.data);
    const first = try test_ids.testNodeId(21);
    const second = try test_ids.testNodeId(22);
    const other_hash: Hash = @splat(0x55);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    var name_storage: store.NameStorage = undefined;
    var scratch: [64]u8 = undefined;

    // Admitted for the peer and hash both grants name.
    const writing = try admit(
        t.io,
        tmp.dir,
        &name_storage,
        first,
        wholeBlobPush(b.root),
        .{ .peer = first, .hash = b.root, .size = blob_size },
        nothing(blob_size),
        &scratch,
    );
    writing.close(t.io);

    // The same grant, presented by the other peer: refused.
    try t.expectError(error.NotPermitted, admit(
        t.io,
        tmp.dir,
        &name_storage,
        second,
        wholeBlobPush(b.root),
        .{ .peer = first, .hash = b.root, .size = blob_size },
        nothing(blob_size),
        &scratch,
    ));

    // The same peer asking about the same blob, but holding a grant for a
    // different one: refused. A peer with *some* grant has no grant for this
    // push, which is the "one blob" half stated as a value rather than as a
    // flag. And the refusal does not disturb the transfer already in progress,
    // which is the other half of "a refused push costs this node nothing".
    try t.expectError(error.NotPermitted, admit(
        t.io,
        tmp.dir,
        &name_storage,
        first,
        wholeBlobPush(b.root),
        .{ .peer = first, .hash = other_hash, .size = blob_size },
        nothing(blob_size),
        &scratch,
    ));
    const paths = store.names(&name_storage, b.root);
    const after = try resume_mod.inspect(t.io, tmp.dir, paths);
    try t.expectEqual(@as(u64, 0), after.data_bytes);
    try t.expectError(error.FileNotFound, store.openComplete(t.io, tmp.dir, paths));
}
