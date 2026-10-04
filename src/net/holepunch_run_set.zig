//! One candidate set, in this layer's own storage.
//!
//! `holepunch_gate.decide` borrows three candidate sets for the length of one
//! turn and stores none of them, so where they live is the producer's problem
//! and not the gate's. This is the answer: a fixed-capacity inline array, held
//! by value inside `holepunch_run.Join`, so a `Join` is a value and a copy of
//! one carries its own candidates rather than a pointer to the original's.
//!
//! Two ceilings reach one set and they are not the same one. `items` is sized
//! by the QUIC stack's advertised-address ceiling, so a set longer than that is
//! a set the stack answers `too_many_addresses` to — a fatal error — and a
//! bound that were larger would only defer the refusal. What does not fit is
//! counted in `overflow` rather than dropped, because the ceiling is a
//! correctness bound and not a tuning one, and a truncated set that looked
//! complete is a set nobody can tell is not.
//!
//! `clear` and `append` are the two writes a producer makes, and the callers
//! are `holepunch_run_join.zig`: `observeReport` and `observePeer` clear and
//! refill, because a report and a record each replace the one before it rather
//! than add to it. Nothing else in the tree writes a set.

const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");

const SocketAddr = addr.SocketAddr;

/// One set of candidate addresses, in this file's own storage.
///
/// Sized by the same constant that bounds what the QUIC stack will accept,
/// because a set longer than that is a set the stack answers
/// `too_many_addresses` to — a fatal error — and a bound that were larger
/// would only defer the refusal. What does not fit is counted in `overflow`
/// rather than dropped, and the count is what `holepunch_run_join.Join.ready`
/// asks `holepunch.mayAdvertise` about: a truncated set that looked complete
/// is a set nobody can tell is not.
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
    /// is safe; see the `holepunch_run.zig` module doc under "Three buffers".
    pub fn slice(self: *const Set) []const SocketAddr {
        return self.items[0..self.len];
    }

    /// Forget the set and start again from empty, count included.
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
    /// `holepunch_run_join.Join.ready` asks `holepunch.mayAdvertise` about: a
    /// repeated address would inflate the count the ceiling is asked with, and
    /// a set that reached the ceiling by repetition would be refused for
    /// candidates nobody can name.
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