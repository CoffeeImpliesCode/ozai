//! One gate decision becomes a bounded, ordered list of attempts with
//! deadlines, and the list remembers which candidates have already proven
//! unreachable.
//!
//! Pure over `now`. No socket, no clock, no allocator: the gate's own
//! instruction arrives as `holepunch.Action` and this file answers with a value
//! and counts. The deadlines are absolute, which is what makes them checkable —
//! `holepunch_target.Target`'s module doc gives the reason, and the instant a
//! poller noticed a deadline had passed never enters the answer.
//!
//! # What this file is not
//!
//! It does not decide *whether* to punch. That is `holepunch_gate.decide`, and
//! nothing here re-asks its question: an action arrives and is obeyed. It also
//! does not decide whether punching has ended — `PunchState.stopped` is the
//! gate's field and this file keeps no copy of it, because a second `stopped`
//! that could disagree with the first would be a second opinion about a fatal
//! error. A `.stopPunching` instruction is obeyed once; if a caller then hands
//! over `.initiateNatTraversalRound`, the caller is contradicting its own gate
//! and that is not this file's to repair.
//!
//! Upstream, at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8, runs
//! `initiate_nat_traversal_round` as *one* call over the whole candidate set —
//! `HolepunchAttempt` in `iroh/src/socket/remote_map/remote_state.rs` — so the
//! per-candidate deadline below is an ozai construction with no upstream byte
//! sequence behind it. The tests here pin it, not a vector; see
//! `holepunch_target.zig`'s module doc for the same statement.
//!
//! # One round is one `start`, and it opens everything at once
//!
//! A round's attempts all carry the same `started` and the same `deadline`.
//! Two reasons, and the first is upstream's shape: the gate makes one call and
//! the stack opens paths at every candidate it returned, so an attempt list
//! with staggered starts would describe a sequence of rounds rather than one.
//!
//! The second is honesty about `Target.started`, which is the instant an
//! attempt *went out*. A future instant in that field would be a fact about
//! this planner's intentions rather than about the network, and a copied
//! `Target` would report it as though it had happened.
//!
//! # What supersedes an in-flight attempt, and who closes its socket
//!
//! Three things, and all three leave every other pending attempt
//! `.superseded`:
//!
//! 1. **Another attempt reached `.connected`.** The peer answered; every other
//!    address has nothing left to prove.
//! 2. **A new round started.** The previous round's whole deadline is
//!    `attempt_timeout`, which is `holepunch.punch_interval` — so the gate has
//!    already decided the next round is due. Two rounds in flight at one peer
//!    is what `holepunch_run.zig`'s module doc calls acting on two copies of
//!    one `Join`, and it is two nodes punching for one peer.
//! 3. **`.stopPunching`.** The gate ended punching.
//!
//! A timeout does **not** supersede the others. One address not answering says
//! that address is gone; it says nothing about the rest of the round, and the
//! remaining attempts are the only evidence left about whether this peer can be
//! reached directly at all.
//!
//! **The owner closes the socket, not the attempt.** `holepunch_target`'s
//! module doc gives the whole of the argument: a descriptor was opened by
//! whoever opened it, `.pending` is the only state in which one was ever handed
//! out, and `Settled.released` is the fact that says so. Putting a descriptor in
//! the value would make a copied `Target` copy a handle and would give a
//! deadline authority to free something the owner is still reading. So this
//! file holds none, and every count it returns — `Answer.released`,
//! `Answer.superseded`, `Started.superseded` — is a number of descriptors the
//! owner has to close, not a queue of them.
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
//! Two bounds, and they behave differently on purpose.
//!
//! - **`max_attempts` is a refusal, and it refuses the newest.** A candidate
//!   with no slot is counted in `Started.refused` and does not become an
//!   attempt. Which candidates get the slots is therefore decided by the order
//!   they arrive in, and that is a real cost of refusing rather than evicting:
//!   a peer whose record lists twelve addresses gets the first eight it
//!   offered. The caller controls that order — `holepunch_run_candidate.Set`
//!   already fixes it — so the cost is a documented caller decision rather than
//!   a silent one here.
//! - **`max_failures` is a refusal too, and it refuses the newest.** A record
//!   being dropped is one the peer already earned, and the record that cannot
//!   be written is a failure this round had not learned before. Trading an
//!   earned memory for a fresh one is the worse of the two: the earned one
//!   stops a wasted attempt and the fresh one only saves one. The refusal is
//!   reported as `Answer.unremembered` rather than dropped in silence, because
//!   a caller choosing between more peers and more memory per peer cannot
//!   answer without being told which happened.

const std = @import("std");
const base_addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const target_mod = @import("holepunch_target.zig");

const NodeId = base_addr.NodeId;
const SocketAddr = base_addr.SocketAddr;

/// Nanoseconds on the caller's own monotonic timeline, re-exported from
/// `holepunch_target` so a caller driving this file needs one import rather
/// than two. `holepunch.Nanos` is the same type; the alias exists because every
/// instant in this file's surface is the one a `Target` carries.
pub const Nanos = target_mod.Nanos;

/// One attempt, held by value. Re-exported for the same reason as `Nanos`.
pub const Target = target_mod.Target;
/// What an attempt became. `holepunch_target.Outcome` under this file's name.
pub const Outcome = target_mod.Outcome;
/// Whether an attempt is past its deadline and still in flight.
pub const expired = target_mod.expired;

/// How many attempts one round may hold.
///
/// Eight, and the tree already says why twice: `docs/DECISIONS/0001` records
/// that iroh works to "up to 8 concurrent paths per connection" against a core
/// holding two `NetworkPath`s behind one `active_path_idx`
/// (`vendor/quic/src/quic/connection.zig:626`), and `path_table.max_paths`
/// adopts the same figure with the same citation. More than eight in-flight
/// direct attempts to one peer is more concurrent paths than the substrate is
/// built for, so the ninth is a refusal rather than a ninth socket.
///
/// A round whose candidate set is shorter than this never reaches the bound,
/// and one that is longer has candidates the round will not try this pass.
pub const max_attempts: usize = 8;

/// How long one attempt may run before it is timed out.
///
/// `holepunch.punch_interval`, taken whole: a round that is still unanswered
/// when the gate would start the next one has told us everything it can, and
/// the next round supersedes it. A deadline longer than the interval between
/// rounds would leave two rounds live at once, which is the same fault as two
/// copies of one `Join` being acted on.
pub const attempt_timeout: Nanos = holepunch.punch_interval;

/// How many unreachable candidates one peer may have on record.
///
/// The same eight, and for the same reason without the substrate citation: a
/// record is 24 bytes against an attempt's eighty, so eight is not this
/// memory's constraint — consistency with `max_attempts` is, so a reader who
/// has learned one bound has learned both.
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
    /// than `failure_hold`; nothing rewrites it and nothing extends it, so a
    /// record's age is the one thing that decides whether it still suppresses
    /// anything.
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

/// What one round did.
///
/// Every count is of something that did not happen, and none of them is a
/// silent loss: a caller that asked for eight attempts over ten candidates
/// needs to know which two it did not get, and whether one of the others was
/// held back over a failure it already knew about.
pub const Started = struct {
    /// Attempts in flight after this call, including the ones this call
    /// started.
    live: usize,
    /// Candidates skipped because a live failure record covered them.
    skipped: usize,
    /// Candidates with no slot under `max_attempts`.
    refused: usize,
    /// Attempts this call superseded. Each had a descriptor open, so this is a
    /// count of sockets the owner has to close.
    superseded: usize,
};

/// What one settlement did.
///
/// Every count here is of a descriptor the owner had open and owns, or of a
/// fact about a candidate the owner should now stop trying. Nothing in this
/// file frees anything and nothing in it is freed, because nothing in this
/// file holds anything: `holepunch_target`'s module doc gives the whole of the
/// argument, and the short form is that a `Target` is a value whose copy has
/// to read its own bytes, which a handle would not.
pub const Answer = struct {
    /// The attempt this call named, after the transition. Null when the
    /// planner held no attempt at that address — a settlement for an address
    /// nobody started is an answer about nothing, not an error.
    target: ?Target,
    /// Attempts this call took out of `.pending`. Each had a live descriptor,
    /// so this is how many sockets the owner has to close, and it is the whole
    /// of what superseding costs.
    released: usize,
    /// The subset of `released` that was superseded rather than settled on its
    /// own terms. Split out because it says how many of the round's addresses
    /// the peer never got to answer on.
    superseded: usize,
    /// The failure this settlement learned could not be recorded, because
    /// `max_failures` was already full of live records. Reported rather than
    /// dropped; see the module doc under "At the bound".
    unremembered: bool,
};

/// Whether `candidate` is worth opening a socket to, as far as this planner's
/// memory is concerned: not covered by a live record.
///
/// Exported because it is the question `start` asks per candidate, and a caller
/// logging a round wants the same answer without re-deriving it. It says
/// nothing about whether the address works — only about what this planner still
/// believes, which is a different and much weaker question.
pub fn mayAttempt(planner: *const Planner, candidate: SocketAddr, now: Nanos) bool {
    return !planner.covered(candidate, now);
}

/// One peer's attempts, in one value.
///
/// Inline storage and no allocator, so a whole planner is a value a test holds
/// on the stack and a copied `Planner` is independent of the original. Targets
/// hold their addresses and peer by value, and `Failure` does too, so nothing
/// in here points into itself — the property `holepunch_target` is built around
/// and the one that makes a copy a snapshot rather than an alias.
pub const Planner = struct {
    /// The peer every attempt presents and expects back. Taken once, at
    /// construction, because it is the same for every attempt in the list and
    /// a planner that could be pointed at two peers would be one planner
    /// holding two peers' worth of state.
    peer: NodeId,
    /// The attempts, first `live` of them. Never written past `max_attempts`.
    /// Settled attempts stay: the caller learns the outcome from the record and
    /// a settlement on an address nobody started has to be tellable from one
    /// that was already answered.
    targets: [max_attempts]Target = undefined,
    /// How many entries of `targets` are live. Never above `targets.len`.
    live: usize,
    /// The unreachable candidates, first `held` of them. Never above
    /// `max_failures`, and never written past it either — a full memory
    /// refuses.
    failures: [max_failures]Failure = undefined,
    /// How many entries of `failures` are live.
    held: usize,

    /// A planner for one peer, with nothing in flight and nothing remembered.
    pub fn init(peer: NodeId) Planner {
        return .{ .peer = peer, .live = 0, .held = 0 };
    }

    /// The attempts, exactly `targets[0..live]`.
    pub fn slice(self: *const Planner) []const Target {
        return self.targets[0..self.live];
    }

    /// The unreachable candidates, exactly `failures[0..held]`.
    pub fn remembered(self: *const Planner) []const Failure {
        return self.failures[0..self.held];
    }

    /// The instant the next attempt falls due, or null when nothing is in
    /// flight. What an owner polls on, and the answer when the planner is idle
    /// is null rather than zero: zero is an instant on the caller's timeline
    /// and this file has no business inventing one.
    pub fn next_due(self: *const Planner) ?Nanos {
        var due: ?Nanos = null;
        for (self.slice()) |target| {
            if (target_mod.settled(target)) continue;
            if (due == null or target.deadline < due.?) due = target.deadline;
        }
        return due;
    }

    /// Obey one gate instruction and answer what it did.
    ///
    /// `.initiateNatTraversalRound` opens a round: every pending attempt from
    /// an earlier round is superseded first, because the gate has already
    /// decided this one is due and two rounds at one peer is the fault named
    /// in the module doc. Candidates are taken in `SocketAddr.order` rather
    /// than in the order they arrive, live failure records are skipped, and
    /// the rest become attempts at `now` with the deadline `attempt_timeout`
    /// out.
    ///
    /// `.wakeAt` builds nothing and supersedes nothing: it is the gate's own
    /// answer that no round is due, and the only thing to obey is its instant,
    /// which is `Action.wakeAt`'s payload and not this file's to schedule.
    ///
    /// `.stopPunching` supersedes everything and builds nothing. It is not
    /// remembered here; see the module doc on why this file keeps no `stopped`.
    pub fn start(
        self: *Planner,
        now: Nanos,
        action: holepunch.Action,
        candidates: []const SocketAddr,
    ) Started {
        var result: Started = .{
            .live = 0,
            .skipped = 0,
            .refused = 0,
            .superseded = 0,
        };
        // Expired records go before the candidates are looked at, so a round
        // never skips an address over a memory that had already run out.
        // The count is not reported. `Started` counts what this round did, and
        // a record that ran out is one this planner no longer believes either
        // way — not an event the caller acted on.
        _ = self.forgetExpired(now);
        switch (action) {
            .initiateNatTraversalRound => {
                result.superseded = self.supersedeAll(now);
                for (candidates) |candidate| {
                    if (self.covered(candidate, now)) {
                        result.skipped += 1;
                        continue;
                    }
                    if (self.file(now, candidate)) {
                        result.live += 1;
                    } else {
                        result.refused += 1;
                    }
                }
            },
            .wakeAt => {},
            .stopPunching => result.superseded = self.supersedeAll(now),
        }
        return result;
    }

    /// Settle every attempt past its deadline at `now`.
    ///
    /// The stamp is `Target`'s own deadline, not `now`: a poller that runs a
    /// full round late files the same timeout as one that ran on time, which is
    /// what `holepunch_target.settle` guarantees and what this call relies on
    /// by asking rather than by assuming. `Answer.released` counts the
    /// descriptors the owner had open, which is one per attempt settled.
    ///
    /// A timeout records the address as unreachable and supersedes nothing: one
    /// address not answering says that address is gone, and the rest of the
    /// round is the only evidence left about whether this peer can be reached
    /// directly at all.
    pub fn expire(self: *Planner, now: Nanos) Answer {
        var answer: Answer = .{
            .target = null,
            .released = 0,
            .superseded = 0,
            .unremembered = false,
        };
        var index: usize = 0;
        while (index < self.live) : (index += 1) {
            const target = self.targets[index];
            if (!target_mod.expired(target, now)) continue;
            const timed_out = target_mod.settle(target, now, .timed_out);
            self.targets[index] = timed_out.target;
            answer.target = timed_out.target;
            answer.released += @intFromBool(timed_out.released);
            // Every timed-out address is a candidate this planner now believes
            // is dead, and a full memory says so rather than losing one.
            answer.unremembered = answer.unremembered or
                !self.remember(target.addr, now);
        }
        return answer;
    }

    /// Settle the attempt at `addr`, and supersede the rest if it connected.
    ///
    /// `.refused` and `.timed_out` record the address as unreachable and
    /// supersede nothing. `.connected` clears any record for the address and
    /// supersedes every other pending attempt, because the peer answered and no
    /// other address has anything left to prove.
    ///
    /// `.pending` and `.superseded` on the way in change nothing: a caller has
    /// no business settling an attempt to either of those, and `settle` answers
    /// the attempt unchanged with `released` zero.
    ///
    /// The first answer to an attempt wins. A late answer describing a
    /// connection nobody is holding releases nothing — `holepunch_target.settle`
    /// is where that is decided, and this file does not re-decide it.
    pub fn settle(
        self: *Planner,
        now: Nanos,
        addr: SocketAddr,
        outcome: Outcome,
    ) Answer {
        var answer: Answer = .{
            .target = null,
            .released = 0,
            .superseded = 0,
            .unremembered = false,
        };
        const index = self.indexOf(addr) orelse return answer;
        // `.pending` is not an outcome and `.superseded` is this file's own
        // mark for an attempt another answer closed, so neither is an answer
        // a caller brings here. `holepunch_target.settle` refuses the first
        // and would accept the second, so both are refused here and the
        // attempt is handed back exactly as it stands.
        if (outcome == .pending or outcome == .superseded) {
            answer.target = self.targets[index];
            return answer;
        }
        const settled = target_mod.settle(self.targets[index], now, outcome);
        self.targets[index] = settled.target;
        answer.target = settled.target;
        answer.released += @intFromBool(settled.released);
        if (!settled.released) return answer;
        switch (outcome) {
            .connected => {
                self.forget(addr);
                answer.superseded = self.supersedeOthers(now, addr);
            },
            .refused, .timed_out => answer.unremembered = !self.remember(addr, now),
            .pending, .superseded => {},
        }
        answer.released += answer.superseded;
        return answer;
    }

    /// Supersede every pending attempt and empty the list.
    ///
    /// The list is emptied as well as superseded, and that is what makes a
    /// second round possible at all: a settled attempt occupies a slot, so
    /// leaving the previous round's attempts in place would fill the bound with
    /// history and refuse every candidate of the round that follows. The
    /// previous round's outcomes are the caller's to have read by then — a
    /// round is over when the next one starts.
    ///
    /// `Answer` is not returned because a caller that wanted a settlement per
    /// attempt has `settle`; what it needs here is the number of descriptors to
    /// close, and the list itself is about to be replaced.
    ///
    /// Kept private because the three reasons to supersede are `start`,
    /// `settle` and `expire`, and a fourth is something this file does not
    /// model.
    fn supersedeAll(self: *Planner, now: Nanos) usize {
        var released_count: usize = 0;
        for (self.targets[0..self.live]) |*target| {
            const settled = target_mod.settle(target.*, now, .superseded);
            target.* = settled.target;
            if (settled.released) released_count += 1;
        }
        self.live = 0;
        return released_count;
    }

    /// Supersede every pending attempt except the one at `addr`, and answer how
    /// many of them the owner has a descriptor for.
    ///
    /// The list is *not* emptied: the peer has answered and the caller reads
    /// the round's outcomes off the attempts, so throwing them away here would
    /// discard the one result that mattered. The next `start` clears them.
    fn supersedeOthers(self: *Planner, now: Nanos, addr: SocketAddr) usize {
        var released_count: usize = 0;
        for (self.targets[0..self.live]) |*target| {
            if (target.addr.order(addr) == .eq) continue;
            const settled = target_mod.settle(target.*, now, .superseded);
            target.* = settled.target;
            if (settled.released) released_count += 1;
        }
        return released_count;
    }

    /// File `candidate` as an attempt at `now`, or refuse it.
    ///
    /// Kept in `SocketAddr.order` rather than appended, so the list reads in
    /// one order whatever order the candidates arrived in and a caller logging
    /// a round can print it as it stands. Insertion is what makes that hold
    /// with a fixed array and no sort scratch.
    ///
    /// The order is *not* what decides who wins a slot under the bound: a full
    /// table refuses, so the survivors are the first candidates offered. See
    /// the module doc under "At the bound" for why that is the caller's
    /// decision and not this file's.
    fn file(self: *Planner, now: Nanos, candidate: SocketAddr) bool {
        if (self.live == self.targets.len) return false;
        var at = self.live;
        while (at > 0 and self.targets[at - 1].addr.order(candidate) == .gt) : (at -= 1) {
            self.targets[at] = self.targets[at - 1];
        }
        self.targets[at] = .{
            .addr = candidate,
            .peer = self.peer,
            .started = now,
            .deadline = now + attempt_timeout,
        };
        self.live += 1;
        return true;
    }

    /// Where `addr` is among the attempts, or null.
    ///
    /// A scan, for `node/conn_index.zig`'s reason: the list is `max_attempts`
    /// entries, so the walk is bounded by the storage it walks and cannot run
    /// away, and a hash would need an allocator this file does not have.
    fn indexOf(self: *const Planner, addr: SocketAddr) ?usize {
        var index: usize = 0;
        while (index < self.live) : (index += 1) {
            if (self.targets[index].addr.order(addr) == .eq) return index;
        }
        return null;
    }

    /// Whether a live record covers `addr` at `now`.
    fn covered(self: *const Planner, addr: SocketAddr, now: Nanos) bool {
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
    fn remember(self: *Planner, addr: SocketAddr, now: Nanos) bool {
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
    fn forget(self: *Planner, addr: SocketAddr) void {
        var index: usize = 0;
        while (index < self.held) : (index += 1) {
            if (self.failures[index].addr.order(addr) != .eq) continue;
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
    fn forgetExpired(self: *Planner, now: Nanos) usize {
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

// --- tests

const t = std.testing;

/// A direct address on `port_number` from one documentation range, so a test
/// that prints one is never mistaken for a routable host.
fn ip(port_number: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port_number };
}

const fixed_peer: NodeId = NodeId.fromBytes([_]u8{9} ** 32) catch
    @compileError("the fixed test peer is not a canonical ed25519 point");

/// `count` candidates on consecutive ports from `first`, in that order.
///
/// The array is `max_attempts` long whatever `count` is, so a caller hands
/// `start` the slice `set[0..count]`: the rest of the array is `undefined`,
/// and an address read out of it is not a candidate.
fn candidate_set(first: u16, count: usize) [max_attempts]SocketAddr {
    var set: [max_attempts]SocketAddr = undefined;
    for (0..count) |offset| {
        set[offset] = ip(first + @as(u16, @intCast(offset)));
    }
    return set;
}

/// The ports the planner holds attempts on, in slice order, into `buf`.
///
/// Slice order rather than sorted, because the planner's contract is that it
/// *files* in `SocketAddr.order` — so asserting on the order as it comes out is
/// asserting on the contract rather than restating it. `buf` is the caller's
/// because a returned slice into a frame-local array is the bug
/// `docs/ARCHITECTURE.md` invariant 6 is about.
fn ports(planner: *const Planner, buf: []u16) []u16 {
    for (planner.slice(), buf[0..planner.slice().len]) |target, *out| {
        out.* = target.addr.port;
    }
    return buf[0..planner.slice().len];
}

/// The ports the planner holds records for, in slice order. Same contract and
/// the same caller-owned buffer as `ports`.
fn rememberedPorts(planner: *const Planner, buf: []u16) []u16 {
    for (planner.remembered(), buf[0..planner.remembered().len]) |failure, *out| {
        out.* = failure.addr.port;
    }
    return buf[0..planner.remembered().len];
}

/// How many attempts are still `.pending`.
fn pendingCount(planner: *const Planner) usize {
    var count: usize = 0;
    for (planner.slice()) |target| {
        if (!target_mod.settled(target)) count += 1;
    }
    return count;
}

/// A planner with one round already started on `count` candidates at `now`.
fn started(count: usize, now: Nanos) Planner {
    var planner = Planner.init(fixed_peer);
    const set = candidate_set(4000, count);
    _ = planner.start(now, .{ .initiateNatTraversalRound = 1 }, set[0..count]);
    return planner;
}

test "a gate decision becomes one ordered list of attempts with one deadline" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = Planner.init(fixed_peer);
    // Handed over in descending order on purpose: the list is the set's order
    // and not the order it arrived in, so the same set filed twice names the
    // same attempts.
    const set = [_]SocketAddr{ ip(4002), ip(4000), ip(4001) };
    const opened = planner.start(now, .{ .initiateNatTraversalRound = 7 }, &set);
    try t.expectEqual(@as(usize, 3), opened.live);
    try t.expectEqual(@as(usize, 0), opened.refused);
    try t.expectEqual(@as(usize, 0), opened.skipped);
    try t.expectEqual(@as(usize, 0), opened.superseded);

    var buf: [max_attempts]u16 = undefined;
    const held = ports(&planner, &buf);
    try t.expectEqualSlices(u16, &[_]u16{ 4000, 4001, 4002 }, held);
    for (planner.slice()) |target| {
        // One round opens everything at `now`, so `started` says what happened
        // rather than what is planned.
        try t.expectEqual(now, target.started);
        try t.expectEqual(now + attempt_timeout, target.deadline);
        try t.expect(std.meta.eql(fixed_peer, target.peer));
        try t.expectEqual(Outcome.pending, target.outcome);
    }
    // One deadline for the round, so `next_due` has one answer.
    try t.expectEqual(@as(?Nanos, now + attempt_timeout), planner.next_due());

    // The same set in ascending order produces the same list.
    const ascending = [_]SocketAddr{ ip(4000), ip(4001), ip(4002) };
    var other = Planner.init(fixed_peer);
    _ = other.start(now, .{ .initiateNatTraversalRound = 7 }, &ascending);
    var other_buf: [max_attempts]u16 = undefined;
    try t.expectEqualSlices(u16, held, ports(&other, &other_buf));
}

test "the gate's own no-round answers are obeyed and change nothing" {
    const now: Nanos = 10 * std.time.ns_per_s;
    const set = candidate_set(4000, 3);

    // No round is due. Nothing is filed and nothing is superseded, because the
    // instruction names an instant and this file does not schedule it.
    var planner = Planner.init(fixed_peer);
    const quiet = planner.start(now, .{ .wakeAt = now + 100 }, set[0..3]);
    try t.expectEqual(@as(usize, 0), quiet.live);
    try t.expectEqual(@as(usize, 0), quiet.superseded);
    try t.expectEqual(@as(usize, 0), planner.slice().len);
    try t.expect(planner.next_due() == null);

    // Punching has ended, and a round in flight is superseded rather than left
    // running: the peer is gone and every socket it had open is the owner's.
    var running = started(3, now);
    const stopped = running.start(now + 1, .stopPunching, &.{});
    try t.expectEqual(@as(usize, 3), stopped.superseded);
    try t.expectEqual(@as(usize, 0), stopped.live);
    try t.expectEqual(@as(usize, 0), pendingCount(&running));
}

test "a new round supersedes the one in flight and files against fresh slots" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    try t.expectEqual(@as(usize, 3), planner.slice().len);

    // The gate says the next round is due; the first one's attempts are
    // superseded and their three sockets are the owner's to close.
    const again = planner.start(now + attempt_timeout, .{ .initiateNatTraversalRound = 1 }, &.{});
    try t.expectEqual(@as(usize, 3), again.superseded);
    try t.expectEqual(@as(usize, 0), pendingCount(&planner));
    // The slots are free again, so the bound is about attempts in flight and
    // not about how many rounds this peer has ever run.
    const set = candidate_set(4000, max_attempts);
    const third = planner.start(now + attempt_timeout, .{ .initiateNatTraversalRound = 1 }, &set);
    try t.expectEqual(@as(usize, max_attempts), third.live);
    try t.expectEqual(@as(usize, max_attempts), planner.slice().len);
}

test "at the bound the round refuses the newest candidates and counts them" {
    const now: Nanos = 10 * std.time.ns_per_s;
    try t.expectEqual(@as(usize, 8), max_attempts);
    // Twelve candidates handed over in descending order. The bound refuses, so
    // the survivors are the eight offered first — the highest here — and the
    // refusal is reported rather than absorbed.
    var twelve: [12]SocketAddr = undefined;
    for (0..12) |offset| twelve[offset] = ip(4011 - @as(u16, @intCast(offset)));
    var planner = Planner.init(fixed_peer);
    const opened = planner.start(now, .{ .initiateNatTraversalRound = 1 }, &twelve);
    try t.expectEqual(@as(usize, 8), opened.live);
    try t.expectEqual(@as(usize, 4), opened.refused);
    try t.expectEqual(@as(usize, 8), planner.slice().len);

    // The eight that got slots are the eight offered first — the highest here
    // — and the list reads them in `SocketAddr.order` rather than in the order
    // they arrived in, because that is how the planner files them. The four
    // that did not are absent from it rather than half-filed.
    var buf: [max_attempts]u16 = undefined;
    const held = ports(&planner, &buf);
    for (held, 0..) |port_number, offset| {
        try t.expectEqual(@as(u16, @intCast(4004 + offset)), port_number);
    }
    for (held) |port_number| {
        try t.expect(port_number >= 4004);
    }

    // The same set offered the other way round gives the other eight. Which
    // candidates win a slot is the caller's order, and this file says so rather
    // than pretending the set decides it.
    var other: [12]SocketAddr = undefined;
    for (0..12) |offset| other[offset] = ip(4000 + @as(u16, @intCast(offset)));
    var flipped = Planner.init(fixed_peer);
    try t.expectEqual(@as(usize, 4), flipped.start(
        now,
        .{ .initiateNatTraversalRound = 1 },
        &other,
    ).refused);
    var flipped_buf: [max_attempts]u16 = undefined;
    const flipped_held = ports(&flipped, &flipped_buf);
    try t.expectEqual(@as(u16, 4000), flipped_held[0]);
    try t.expectEqual(@as(u16, 4007), flipped_held[max_attempts - 1]);
}

test "a refused round supersedes, so two rounds never share a peer" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = Planner.init(fixed_peer);
    // The full bound in flight.
    const set = candidate_set(4000, max_attempts);
    try t.expectEqual(@as(usize, max_attempts), planner.start(
        now,
        .{ .initiateNatTraversalRound = 1 },
        &set,
    ).live);

    // The next round over the same eight is accepted, and the four the bound
    // refused last time are not refused this time: the old attempts gave up
    // their slots, which is the whole of the difference.
    const next = planner.start(now + attempt_timeout, .{ .initiateNatTraversalRound = 1 }, &set);
    try t.expectEqual(@as(usize, 0), next.refused);
    try t.expectEqual(@as(usize, max_attempts), next.superseded);
    try t.expectEqual(@as(usize, max_attempts), next.live);
}

test "a connected attempt supersedes the rest and releases nothing it did not own" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    const answer = planner.settle(now + 1, ip(4001), .connected);

    // One descriptor for the attempt that answered, one for each of the two
    // that were still in flight: three in total, all the owner's.
    // Two of those three were superseded rather than answered, which is what
    // `superseded` counts: the addresses the peer never got to answer on.
    try t.expectEqual(@as(usize, 2), answer.superseded);
    try t.expectEqual(@as(usize, 3), answer.released);
    try t.expectEqual(Outcome.connected, answer.target.?.outcome);
    try t.expectEqual(@as(usize, 0), pendingCount(&planner));

    // The other two read as superseded and stay readable: the round's outcomes
    // are the one result that mattered.
    try t.expectEqual(Outcome.superseded, planner.slice()[0].outcome);
    try t.expectEqual(Outcome.connected, planner.slice()[1].outcome);
    try t.expectEqual(Outcome.superseded, planner.slice()[2].outcome);
    // Nothing is in flight, so there is no deadline left to poll on.
    try t.expect(planner.next_due() == null);

    // A late answer to one of them changes nothing and releases nothing: the
    // first answer is the only one that had a socket open.
    const late = planner.settle(now + 2, ip(4000), .connected);
    try t.expectEqual(@as(usize, 0), late.released);
    try t.expectEqual(Outcome.superseded, late.target.?.outcome);
    // And an address nobody started is an answer about nothing.
    try t.expect(planner.settle(now + 2, ip(9999), .connected).target == null);
}

test "a refusal records the address and supersedes nothing" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    var buf: [max_failures]u16 = undefined;
    const answer = planner.settle(now + 1, ip(4000), .refused);

    // One address not working says that address is gone. The other two are the
    // only evidence left about whether this peer is reachable directly at all.
    try t.expectEqual(@as(usize, 0), answer.superseded);
    try t.expectEqual(@as(usize, 1), answer.released);
    try t.expectEqual(@as(usize, 2), pendingCount(&planner));
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
    try t.expectEqual(@as(u16, 4000), rememberedPorts(&planner, &buf)[0]);
    // A refusal is stamped where it happened, not where it was noticed.
    try t.expectEqual(@as(?Nanos, now + 1), answer.target.?.settled_at);
}

test "a timeout is stamped at the deadline however late the poller runs" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    // Nothing is due before the deadline, so an early poll expires nothing.
    try t.expectEqual(@as(usize, 0), planner.expire(now + attempt_timeout - 1).released);
    try t.expectEqual(@as(usize, 3), pendingCount(&planner));

    // A poller a full interval late files the same three timeouts, each stamped
    // at its own deadline rather than at the instant somebody noticed.
    const answer = planner.expire(now + attempt_timeout * 2);
    try t.expectEqual(@as(usize, 3), answer.released);
    try t.expectEqual(@as(usize, 0), answer.superseded);
    try t.expectEqual(Outcome.timed_out, answer.target.?.outcome);
    for (planner.slice()) |target| {
        try t.expectEqual(@as(?Nanos, now + attempt_timeout), target.settled_at);
        try t.expectEqual(Outcome.timed_out, target.outcome);
    }
    try t.expectEqual(@as(usize, 3), planner.remembered().len);
}

test "a known-unreachable candidate costs nothing on the next pass" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    _ = planner.settle(now + 1, ip(4001), .refused);
    try t.expectEqual(@as(usize, 1), planner.remembered().len);

    // The next pass opens two attempts, not three, and says that one of the
    // candidates was held back rather than filing it and refusing it later.
    const set = candidate_set(4000, 3);
    const again = planner.start(
        now + holepunch.punch_interval,
        .{ .initiateNatTraversalRound = 1 },
        set[0..3],
    );
    try t.expectEqual(@as(usize, 2), again.live);
    try t.expectEqual(@as(usize, 1), again.skipped);
    try t.expectEqual(@as(usize, 0), again.refused);
    for (planner.slice()) |target| {
        try t.expect(target.addr.port != 4001);
    }
    // The record is still there, so it is not consumed by being acted on.
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
}

test "a remembered failure expires rather than blacklisting an address forever" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(2, now);
    _ = planner.settle(now + 1, ip(4000), .refused);

    // A NAT rebinding is not a failure of the address. `DECISIONS/0001`
    // measures one at 2.2 s, so a record that outlived a hold longer than the
    // rebinding would blacklist a working address for the connection's life —
    // and nothing in this tree can learn that a mapping changed.
    const after_hold: Nanos = now + 1 + failure_hold;
    // The record runs out at its own hold, to the nanosecond: one short of it
    // the address is still suppressed, and at it the candidate opens again.
    try t.expect(planner.remembered()[0].live(after_hold - 1));
    try t.expect(!planner.remembered()[0].live(after_hold));
    const set = candidate_set(4000, 2);
    const again = planner.start(
        after_hold,
        .{ .initiateNatTraversalRound = 1 },
        set[0..2],
    );
    try t.expectEqual(@as(usize, 0), again.skipped);
    try t.expectEqual(@as(usize, 2), again.live);
    // The record was collected, not merely ignored, so the memory a round has
    // is never stale.
    try t.expectEqual(@as(usize, 0), planner.remembered().len);
}

test "a repeated failure moves the record rather than adding a second one" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    _ = planner.settle(now, ip(4000), .refused);
    _ = planner.settle(now, ip(4001), .refused);
    try t.expectEqual(@as(usize, 2), planner.remembered().len);

    // A record is one fact about one address. Two of them would let the older
    // expire and leave the newer suppressing a candidate nothing knows about,
    // and a live record is exactly what holds a candidate back — so the second
    // refusal on 4000 can only arrive once the first record has run out, and it
    // goes into one record rather than into a second.
    const after_hold: Nanos = now + failure_hold;
    const set = candidate_set(4000, 2);
    _ = planner.start(after_hold, .{ .initiateNatTraversalRound = 1 }, set[0..2]);
    try t.expectEqual(@as(usize, 0), planner.remembered().len);
    _ = planner.settle(after_hold, ip(4000), .refused);
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
    // And the record carries the instant the failure is current: the fresh one,
    // not the hold the previous one started.
    const held = planner.remembered();
    var restarted: ?Nanos = null;
    for (held) |failure| {
        if (failure.addr.port != 4000) continue;
        restarted = failure.at;
    }
    try t.expectEqual(@as(?Nanos, now + failure_hold), restarted);
}

test "a connection clears the record for the address that worked" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    var buf: [max_failures]u16 = undefined;
    _ = planner.settle(now, ip(4000), .refused);
    _ = planner.settle(now + failure_hold - 1, ip(4002), .refused);
    try t.expectEqual(@as(usize, 2), planner.remembered().len);

    // A live record is what holds a candidate back, so the attempt on 4000 that
    // answers `.connected` is the next round's: this round's attempt on it has
    // already been answered, and the first answer is the only answer.
    const after_hold: Nanos = now + failure_hold;
    const set = candidate_set(4000, 1);
    _ = planner.start(after_hold, .{ .initiateNatTraversalRound = 1 }, set[0..1]);
    // The record on 4000 ran out and was collected with the round; the one on
    // 4002 is younger than a hold and is still there to be read.
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
    const answer = planner.settle(after_hold + 1, ip(4000), .connected);
    try t.expectEqual(Outcome.connected, answer.target.?.outcome);
    // The address worked, so nothing about it is remembered, and a connection
    // records nothing: the record on the address that did not work is untouched
    // and only that one.
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
    try t.expectEqual(@as(u16, 4002), rememberedPorts(&planner, &buf)[0]);
}

test "a full failure memory refuses the newest and keeps what it had" {
    var now: Nanos = 10 * std.time.ns_per_s;
    var planner = Planner.init(fixed_peer);
    // Fill the memory through settlements, one attempt per failure, so every
    // record in it is one the peer earned rather than one written directly.
    var refused: ?bool = null;
    for (0..max_failures) |offset| {
        const port_number: u16 = @intCast(4000 + offset);
        const set = [_]SocketAddr{ip(port_number)};
        _ = planner.start(now, .{ .initiateNatTraversalRound = 1 }, &set);
        refused = planner.settle(now + 1, ip(port_number), .refused).unremembered;
        now += 1;
    }
    try t.expectEqual(@as(usize, max_failures), planner.remembered().len);
    try t.expect(!refused.?);
    var buf: [max_failures]u16 = undefined;
    const held = rememberedPorts(&planner, &buf);
    for (held, 0..) |port_number, offset| {
        try t.expectEqual(@as(u16, @intCast(4000 + offset)), port_number);
    }

    // The ninth failure cannot be remembered, and says so. Trading an earned
    // memory for a fresh one is the worse of the two: the earned one stops a
    // wasted attempt and the fresh one only saves one, so the refusal is
    // reported rather than absorbed.
    const ninth = [_]SocketAddr{ip(4008)};
    _ = planner.start(now, .{ .initiateNatTraversalRound = 1 }, &ninth);
    try t.expect(planner.settle(now + 1, ip(4008), .refused).unremembered);
    try t.expectEqual(@as(usize, max_failures), planner.remembered().len);

    // And the candidate it learned nothing about is not held back, because
    // nothing was written down about it.
    const round = planner.start(now, .{ .initiateNatTraversalRound = 1 }, &ninth);
    try t.expectEqual(@as(usize, 1), round.live);
    try t.expectEqual(@as(usize, 0), round.skipped);

    // Once the records have run out, the memory has room again and the next
    // failure lands — expiry is what makes a record a memory rather than a
    // blacklist.
    const later: Nanos = now + failure_hold;
    _ = planner.start(later, .{ .initiateNatTraversalRound = 1 }, &ninth);
    try t.expect(!planner.settle(later + 1, ip(4008), .refused).unremembered);
    try t.expectEqual(@as(usize, 1), planner.remembered().len);
    try t.expectEqual(@as(u16, 4008), rememberedPorts(&planner, &buf)[0]);
}

test "mayAttempt is the question start asks and answers the same way" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(2, now);
    _ = planner.settle(now + 1, ip(4000), .refused);
    try t.expect(!mayAttempt(&planner, ip(4000), now + 1));
    try t.expect(mayAttempt(&planner, ip(4001), now + 1));
    // The record's hold is the whole of the answer, so the candidate opens
    // again with the record and not with anything the planner learned about
    // the address itself.
    try t.expect(mayAttempt(&planner, ip(4000), now + 1 + failure_hold));
}

test "settling to a non-outcome changes nothing" {
    const now: Nanos = 10 * std.time.ns_per_s;
    var planner = started(3, now);
    // A caller has no business settling an attempt to `.pending` or to
    // `.superseded`; both are answered unchanged, with nothing released.
    for ([_]Outcome{ .pending, .superseded }) |outcome| {
        const answer = planner.settle(now + 1, ip(4000), outcome);
        try t.expectEqual(@as(usize, 0), answer.released);
        try t.expectEqual(@as(usize, 0), answer.superseded);
        try t.expectEqual(Outcome.pending, answer.target.?.outcome);
        try t.expect(answer.target.?.settled_at == null);
    }
    try t.expectEqual(@as(usize, 3), pendingCount(&planner));
    try t.expectEqual(@as(usize, 0), planner.remembered().len);
}

test "a copied planner is a snapshot and not an alias" {
    const now: Nanos = 10 * std.time.ns_per_s;
    const original = started(3, now);
    const copy = original;
    try t.expectEqual(original.live, copy.live);
    try t.expect(std.meta.eql(original.slice()[0], copy.slice()[0]));

    // Settling one leaves the other in flight, and the copy reaches the same
    // answer the original would have: nothing in a `Target` points into another
    // `Target`, so a copy cannot read its own bytes by way of the original.
    var moving = original;
    const settled = moving.settle(now + 1, ip(4000), .connected).target.?;
    try t.expectEqual(Outcome.pending, copy.slice()[0].outcome);
    try t.expectEqual(@as(usize, 3), pendingCount(&copy));
    try t.expectEqual(@as(usize, 0), pendingCount(&moving));
    try t.expect(std.meta.eql(settle(copy.slice()[0], now + 1, .connected), settled));
}

/// `holepunch_target.settle`, under the name this file re-exports its result
/// by. Present so the copy test above reads as a comparison of two settlements
/// rather than of a value and a pair of field accesses.
fn settle(target: Target, now: Nanos, outcome: Outcome) Target {
    return target_mod.settle(target, now, outcome).target;
}
