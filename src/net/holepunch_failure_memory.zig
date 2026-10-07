//! What one peer has already been told does not work, and the whole of what a
//! planner still believes about a candidate.
//!
//! Split out of `holepunch_trigger.zig`, which owns the attempt list and
//! answers the gate. The two meet at four call sites and nowhere else: `start`
//! asks `covered`, `settle` writes through `remember` and `forget`, and `expire`
//! writes through `remember` too. Nothing here reads a `Target`, a deadline,
//! an outcome or a `holepunch.Action`, so this memory has no way to become
//! wrong about an attempt — it holds addresses and instants, and the only
//! question it answers is whether one of them is still held against a
//! candidate.
//!
//! Inline storage and no allocator, so a whole memory is a value a caller holds
//! on the stack and a copied `Memory` is independent of the original. Nothing
//! in here points into itself, so a copy is a snapshot rather than an alias.
//!
//! # How an unreachable candidate is remembered, and how it expires
//!
//! One `Failure` per address: the address, and the instant the failure was
//! recorded. `start` skips a candidate a live record covers, so a known-dead
//! address costs nothing on the next pass — no socket, no deadline, no entry
//! in the attempt list.
//!
//! **A permanently remembered failure is its own bug, and this one expires.**
//! A record is live for `failure_hold` and no longer; nothing in this file can
//! extend it, and `start` collects the expired ones before it looks at the
//! candidates. Two reasons it cannot be permanent. First, a NAT rebinding is
//! not a failure of the address — `docs/DECISIONS/0001` records one measured at
//! 2.2 s, and an address whose mapping was rebuilt during a punch answers on
//! the next round. A record that outlived that would blacklist a working
//! address for the life of the connection. Second, this tree has no way to
//! learn that a peer's mapping changed: `holepunch_run`'s gap table says the
//! candidate sets are never aged, so expiry is the *only* mechanism that can
//! bring a candidate back, and a permanent record would be a peer's direct path
//! gone for good over one round that nobody answered.
//!
//! `failure_hold` is two `punch_interval`s. One interval is the gap between
//! rounds, and a candidate that failed in the round just gone is retried in the
//! next round under `holepunch.decide`'s own rule — that is what the gate's
//! interval is for. Holding it for twice that means a record spans exactly one
//! skipped round, which is long enough to stop a dead address being retried in
//! a loop and short enough that a rebinding costs one round of silence.
//!
//! A `.connected` clears the record for that address outright: the address
//! worked, so nothing about it is remembered.
//!
//! # At the bound
//!
//! **`max_failures` is a refusal, and it refuses the newest.** A record being
//! dropped is one the peer already earned, and the record that cannot be written
//! is a failure this round had not learned before. Trading an earned memory for
//! a fresh one is the worse of the two: the earned one stops a wasted attempt
//! and the fresh one only saves one. The refusal is reported as
//! `Answer.unremembered` by the planner that holds this memory rather than
//! dropped in silence, because a caller choosing between more peers and more
//! memory per peer cannot answer without being told which happened.

const base_addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const target_mod = @import("holepunch_target.zig");

const SocketAddr = base_addr.SocketAddr;
const Nanos = target_mod.Nanos;

/// How many unreachable candidates one peer may have on record.
///
/// The same eight as `holepunch_trigger.max_attempts`, and for the same reason
/// without the substrate citation: a record is 24 bytes against an attempt's
/// eighty, so eight is not this memory's constraint — consistency with
/// `max_attempts` is, so a reader who has learned one bound has learned both.
pub const max_failures: usize = 8;

/// How long one unreachable record suppresses its candidate.
pub const failure_hold: Nanos = 2 * holepunch.punch_interval;

/// One candidate this peer has already been told does not work.
pub const Failure = struct {
    /// The address that failed. Compared with `SocketAddr.order`, because two
    /// spellings of one address are one candidate — the same rule
    /// `holepunch_run_candidate.Set` appends under.
    addr: SocketAddr,
    /// When the failure was recorded. The record is live while this is younger
    /// than `failure_hold`; nothing rewrites it beyond re-recording the same
    /// address and nothing extends it, so a record's age is the one thing that
    /// decides whether it still suppresses anything.
    at: Nanos,

    /// Whether this record still suppresses its address at `now`.
    ///
    /// Saturating, so a caller whose timeline runs past the ceiling reads a
    /// record as expired rather than as one whose age wrapped into the far
    /// past and is therefore fresh.
    pub fn live(self: Failure, now: Nanos) bool {
        return now -| self.at < failure_hold;
    }
};

/// The unreachable candidates one peer has on record, as a value.
pub const Memory = struct {
    /// The unreachable candidates, first `held` of them. Never above
    /// `max_failures`, and never written past it either — a full memory
    /// refuses.
    failures: [max_failures]Failure = undefined,
    /// How many entries of `failures` are live.
    held: usize,

    /// A memory with nothing remembered.
    pub fn init() Memory {
        return .{ .held = 0 };
    }

    /// The unreachable candidates, exactly `failures[0..held]`.
    pub fn remembered(self: *const Memory) []const Failure {
        return self.failures[0..self.held];
    }

    /// Whether a live record covers `addr` at `now`.
    pub fn covered(self: *const Memory, addr: SocketAddr, now: Nanos) bool {
        for (self.failures[0..self.held]) |failure| {
            if (!failure.live(now)) continue;
            if (failure.addr.order(addr) == .eq) return true;
        }
        return false;
    }

    /// Record `addr` as unreachable, or refuse to.
    ///
    /// An address already recorded has its record rewritten at `now` rather
    /// than a second one written: a record is one fact about one address, and
    /// two of them would let the older one expire and leave the newer behind to
    /// suppress a candidate with nothing left to say. Rewriting restarts the
    /// hold, which is the honest reading — the failure is current.
    pub fn remember(self: *Memory, addr: SocketAddr, now: Nanos) bool {
        for (self.failures[0..self.held]) |*failure| {
            if (failure.addr.order(addr) == .eq) {
                failure.at = now;
                return true;
            }
        }
        if (self.held == self.failures.len) return false;
        self.failures[self.held] = .{ .addr = addr, .at = now };
        self.held += 1;
        return true;
    }

    /// Drop the record for `addr`, if there is one.
    pub fn forget(self: *Memory, addr: SocketAddr) void {
        var index: usize = 0;
        while (index < self.held) : (index += 1) {
            if (self.failures[index].addr.order(addr) != .eq) continue;
            // The loop ensures index < held; ZBC cannot connect that guard to this subtraction.
            // zbc-disable-next-line: index-minus-one-without-zero-guard
            self.failures[index] = self.failures[self.held - 1];
            self.held -= 1;
            return;
        }
    }

    /// Drop every record whose hold has run out, and answer how many went.
    ///
    /// Compaction rather than a tombstone, and a forward walk rather than an
    /// index that steps back: the live records are copied down over the dead
    /// ones and `held` shrinks, so the array stays dense and no state has to
    /// say which slots are holes. A backwards index would need `held - 1` on
    /// the last step, and one that underflows is a trap rather than a loop.
    pub fn forgetExpired(self: *Memory, now: Nanos) usize {
        var kept: usize = 0;
        var index: usize = 0;
        while (index < self.held) : (index += 1) {
            if (!self.failures[index].live(now)) continue;
            self.failures[kept] = self.failures[index];
            kept += 1;
        }
        const dropped = self.held - kept;
        self.held = kept;
        return dropped;
    }
};
