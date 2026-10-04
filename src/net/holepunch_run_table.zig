//! The per-peer path table: where a candidate is filed, and what the ceiling
//! leaves behind.
//!
//! A path table is a map keyed by address, not a list. That is the whole rule
//! this module exists to keep: an address the table already carries has its
//! status replaced and gets no second entry, and two entries for one address
//! would make `holepunch.prune` count one path twice.
//!
//! The storage is the caller's, deliberately. Nothing below `ozai.base` takes
//! an allocator, so the array is inline in `holepunch_run.Join` and every
//! function here is handed that array and a pointer to its live count rather
//! than wrapping it in a type of its own — a `Join` is then still a value whose
//! `paths` and `path_count` are plain fields, and copying one copies the whole
//! table. `max_paths` is what bounds the array; `holepunch_path.zig` is what
//! says which paths a prune may take out of it.
//!
//! The prune runs on every call and not only on the ones that recorded
//! something: the storage is reachable and a caller can write into it, so the
//! ceiling is enforced whatever the table's last change was.
//!
//! What a path's status *is* is not decided here. `holepunch_run.zig`'s
//! multipath gap leaves that with the transport, and the tests that pin the
//! ordering are in `holepunch_run_join.zig`, where a whole chain reaches this
//! table.

const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Path = holepunch.Path;
const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;

/// How many paths one peer may carry between prunes.
///
/// `holepunch.max_non_relay_paths` is where pruning starts rather than a bound
/// on the table — paths that are open, and paths nobody has tried, survive
/// however many there are — so a burst of untested candidates makes the table
/// longer before it makes it shorter. Two ceilings' worth of room lets such a
/// burst be absorbed and then judged by the prune instead of refused by the
/// storage, and the storage is the only bound this layer has: nothing below
/// `ozai.base` takes an allocator. What does not fit is counted and reported,
/// never dropped in silence.
pub const max_paths: usize = 2 * holepunch.max_non_relay_paths;

/// What recording one path did to the table.
pub const Filed = struct {
    /// Whether the table now carries this path. False means the table was
    /// full, and the status that came with the path is dropped with it: a
    /// path nobody can see is a path nobody may claim to have tried.
    stored: bool,
    /// What the prune dropped over the whole table once the change was in.
    pruned: holepunch.Pruned,
};

/// What one burst of candidates cost.
///
/// The dropped counts are the sum over the burst rather than the last prune's
/// tally, because each candidate is a separate change and each change is
/// pruned: a burst is a run of changes, not one change.
pub const Absorbed = struct {
    /// Candidates the table did not already carry.
    added: usize,
    /// Candidates the path table had no room for. The advertised set has its
    /// own ceiling and counts it on itself; see
    /// `holepunch_run_join.Peered`.
    refused: usize,
    /// What the whole burst cost the table.
    pruned: holepunch.Pruned,
};

/// The tally of a burst that has filed nothing yet.
pub const none_pruned: holepunch.Pruned = .{
    .kept = 0,
    .unusable_dropped = 0,
    .inactive_dropped = 0,
};

/// Enforce the per-peer ceiling over `paths[0..count.*]`, in place, and write
/// the surviving count back.
///
/// A pass-through to `holepunch.prune`: the order the rule fires in — unusable
/// first and always, then at most `holepunch.max_inactive_non_relay_paths` of
/// the rest, and never a path nobody has tried — is the gate's and is not
/// restated here. What this adds is where the survivors live, which is the
/// caller's own storage.
pub fn prune(paths: []Path, count: *usize) holepunch.Pruned {
    const result = holepunch.prune(paths[0..count.*]);
    count.* = result.kept;
    return result;
}

/// Record one path and enforce the ceiling over the table.
///
/// An address the table already carries has its status replaced by the one
/// this call names, and gets no second entry: a path table is a map keyed by
/// address, and two entries for one address would make the prune count one path
/// twice. This is the only call that replaces a status — `file` and
/// `holepunch_run_join.Join.observePeer` file a candidate the table already
/// carries without touching one, because neither can name a status.
///
/// The status is the caller's to know. `unknown` is what a candidate arrives
/// as, because a probe round learns an address and never learns whether
/// anything was sent over it; `open`, `inactive` and `unusable` are what the
/// multipath layer reports, and no rule about which follows which is written
/// here.
pub fn observe(paths: []Path, count: *usize, path: Path) Filed {
    if (find(paths[0..count.*], path.addr)) |held| {
        held.status = path.status;
    } else if (count.* == paths.len) {
        // The status came with the address and the address is not stored, so
        // the status is dropped with it: a path nobody can see is a path
        // nobody may claim to have tried.
        return .{ .stored = false, .pruned = prune(paths, count) };
    } else {
        paths[count.*] = path;
        count.* += 1;
    }
    return .{ .stored = true, .pruned = prune(paths, count) };
}

/// File one untried candidate, and add what it cost to a running tally.
///
/// A candidate the table already carries keeps the status it has. Filing it
/// `unknown` again would answer for a status this producer cannot name: a
/// record says where the peer is and says nothing about what happened over the
/// path, so a path that was open would read back as one nobody has tried — and
/// `holepunch.prune` reads that status to decide what a burst may not evict.
/// `observe` is the seam that changes one; this is not it.
///
/// `unknown` for a candidate the table does not carry, because that is what
/// the module doc's multipath gap leaves every candidate with, and the prune
/// runs on every candidate rather than only on the ones that inserted: the
/// storage is reachable and a caller can write into it, so the ceiling is
/// enforced whatever the table's last change was.
pub fn file(paths: []Path, count: *usize, into: *Absorbed, candidate: SocketAddr) void {
    // Read before the change, because `Absorbed.added` counts candidates the
    // table did not already carry, and an address it does carry is not filed
    // again below.
    const known = find(paths[0..count.*], .{ .ip = candidate }) != null;
    const filed: Filed = if (known)
        .{ .stored = true, .pruned = prune(paths, count) }
    else
        observe(paths, count, .{ .addr = .{ .ip = candidate }, .status = .unknown });
    if (!filed.stored) {
        into.refused += 1;
    } else if (!known) {
        into.added += 1;
    }
    into.pruned.unusable_dropped += filed.pruned.unusable_dropped;
    into.pruned.inactive_dropped += filed.pruned.inactive_dropped;
}

/// File a burst of candidates, and hand back what the burst cost.
///
/// One filed candidate per entry rather than one at the end, because the
/// prune runs on every change: the rule is that an unusable path goes first
/// and always, and a single prune at the end of a burst would leave a burst's
/// unusable paths sitting in the table for the whole of it.
///
/// Every candidate the table does not carry arrives `unknown` through `file`,
/// which is the status the module doc's multipath gap leaves it with; one the
/// table already carries keeps the status it has.
pub fn absorb(paths: []Path, count: *usize, candidates: []const SocketAddr) Absorbed {
    var result: Absorbed = .{ .added = 0, .refused = 0, .pruned = none_pruned };
    for (candidates) |candidate| file(paths, count, &result, candidate);
    result.pruned.kept = count.*;
    return result;
}

/// The slot holding `wanted`, or null when the table does not carry it.
fn find(paths: []Path, wanted: TransportAddr) ?*Path {
    for (paths) |*path| {
        if (path.addr.order(wanted) == .eq) return path;
    }
    return null;
}