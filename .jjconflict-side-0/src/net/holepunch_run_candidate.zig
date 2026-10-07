//! The storage a join keeps its candidates in, and the tallies that say what
//! filing them cost.
//!
//! `holepunch_run.zig` is the facade for this module; this half holds the
//! bounded, deduplicating candidate set and the three counts that describe what
//! one burst of candidates did to the two tables behind it. The join that owns
//! them is `holepunch_run_peer.zig`.
//!
//! The module doc `holepunch_run.zig` carries is the argument for the whole
//! file and is not repeated here.

const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");

const SocketAddr = addr.SocketAddr;

/// One set of candidate addresses, in this file's own storage.
///
/// Sized by the same constant that bounds what the QUIC stack will accept,
/// because a set longer than that is a set the stack answers
/// `too_many_addresses` to — a fatal error — and a bound that were larger
/// would only defer the refusal. What does not fit is counted in `overflow`
/// rather than dropped, and the count is what `ready` asks
/// `holepunch.mayAdvertise` about: a truncated set that looked complete is a
/// set nobody can tell is not.
pub const Set = struct {
    /// The candidates, first `len` of them and the rest unspecified.
    ///
    /// Entries past `len` are never written and are never read, so a default
    /// `Set` is a *valid* value with an entirely undefined array behind it: an
    /// empty set, not a broken one. Read the prefix through `slice` rather
    /// than by indexing, and compare a candidate with
    /// `SocketAddr.order` as `append` does, because two spellings of one
    /// address are one candidate.
    items: [holepunch.max_qnt_addresses]SocketAddr = undefined,
    /// How many entries of `items` are live: zero by default, and never above
    /// `items.len`, because `append` counts what does not fit in `overflow`
    /// rather than growing past the ceiling. It counts *distinct* candidates,
    /// since `append` refuses one the set already holds.
    len: usize = 0,
    /// Candidates that did not fit. Never silently absorbed, because the
    /// ceiling is a correctness bound and not a tuning one.
    overflow: usize = 0,

    /// The candidates, for the gate and for a reader: exactly `items[0..len]`.
    ///
    /// The slice borrows `self`, so it is a view of this `Set` and dies with
    /// it — copying a `Set` copies the candidates, and a slice into the
    /// original keeps naming the original's. Anything that rewrites the prefix
    /// replaces what it names: `observeReport` and `observePeer` clear and
    /// refill it, `settle` copies `local` over `previous`. The gate is handed
    /// a fresh slice per turn and stores nothing, which is why borrowing here
    /// is safe; see the module doc under "Three buffers".
    pub fn slice(self: *const Set) []const SocketAddr {
        return self.items[0..self.len];
    }

    pub fn clear(self: *Set) void {
        self.len = 0;
        self.overflow = 0;
    }

    fn holds(self: *const Set, candidate: SocketAddr) bool {
        for (self.slice()) |kept| {
            if (kept.order(candidate) == .eq) return true;
        }
        return false;
    }

    /// Append unless the set already carries it, and unless it is full.
    ///
    /// A candidate the set holds is not appended twice, because `len` is what
    /// `ready` asks `holepunch.mayAdvertise` about: a repeated address would
    /// inflate the count the ceiling is asked with, and a set that reached
    /// the ceiling by repetition would be refused for candidates nobody can
    /// name.
    pub fn append(self: *Set, candidate: SocketAddr) void {
        if (self.holds(candidate)) return;
        if (self.len == self.items.len) {
            self.overflow += 1;
            return;
        }
        self.items[self.len] = candidate;
        self.len += 1;
    }
};
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
    /// own ceiling and counts it on itself; see `Peered`.
    refused: usize,
    /// What the whole burst cost the table.
    pruned: holepunch.Pruned,
};

/// What one peer's published record did to the join.
///
/// Two counts and a tally, because one record reaches two sets that have
/// separate ceilings: `candidates` is the path table's, and what the
/// advertised set could not hold is counted on the set itself
/// (`Join.remote.overflow`), which is the one `ready` asks the stack's ceiling
/// about.
pub const Peered = struct {
    /// What the record's direct addresses cost the path table.
    candidates: Absorbed,
    /// Addresses in the record that were not candidates: a relay URL and a
    /// custom transport. Counted, because a record carrying nothing else
    /// leaves no candidate at all, and that is not the same fact as a peer
    /// that published none.
    not_candidates: usize,
};
