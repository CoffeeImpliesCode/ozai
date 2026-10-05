//! The random choices membership makes, as a value the caller seeds.
//!
//! Upstream threads a `rand::Rng` through `State::new` and reaches for a
//! process-global generator by default. A global generator is forbidden here —
//! it breaks every test that has to run twice — so the generator is a field
//! and `Rng.init(seed)` is how a caller gets a reproducible one.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const key = @import("../../base/key.zig");

const NodeId = key.NodeId;

/// The random choices membership makes, as a value the caller seeds.
///
/// Upstream threads a `rand::Rng` through `State::new` and uses a
/// `rand::thread_rng()` by default. A process-global generator is forbidden
/// here — `docs/ARCHITECTURE.md` invariant 2 is about sorted collections and
/// invariant 14 is about purity, and a global generator breaks every test
/// that has to run twice — so the generator is a field, and
/// `Rng.init(seed)` is how a caller gets a reproducible one.
pub const Rng = struct {
    prng: std.Random.Xoshiro256,

    pub fn init(seed: u64) Rng {
        return .{ .prng = std.Random.Xoshiro256.init(seed) };
    }

    pub fn next(self: *Rng) u64 {
        return self.prng.next();
    }

    /// Uniform in `[0, n)`, and `0` for `n == 0` so a caller can write
    /// `pick(x) orelse fallback` without a separate empty check.
    pub fn below(self: *Rng, n: usize) usize {
        if (n == 0) return 0;
        return self.prng.random().intRangeLessThan(usize, 0, n);
    }

    /// Uniform in `[lo, hi)`.
    pub fn range(self: *Rng, lo: u64, hi: u64) u64 {
        if (hi <= lo) return lo;
        return self.prng.random().intRangeLessThan(u64, lo, hi);
    }

    /// A child generator, drawn from this one. This is what
    /// `Network::insert_with_config` gives each simulated node upstream
    /// (`R::from_rng(&mut self.rng)`), and the reason two nodes in the same
    /// simulation do not walk in lockstep.
    pub fn child(self: *Rng) Rng {
        return .init(self.next());
    }

    /// Fisher-Yates over node ids. Upstream `IndexSet::shuffled` calls
    /// `slice::shuffle`, which is the same algorithm and therefore the same
    /// permutation for the same input order.
    pub fn shuffle(self: *Rng, items: []NodeId) void {
        var index = items.len;
        while (index > 1) {
            index -= 1;
            const other = self.below(index + 1);
            std.mem.swap(NodeId, &items[index], &items[other]);
        }
    }
};
