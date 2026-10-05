//! One peer's NAT traversal as this file keeps it.
//!
//! `holepunch_run.zig` is the facade for this module; this half holds the join
//! itself: the gate's own state held whole, the three candidate buffers the
//! gate compares, the peer's path table, and the producers that fill them.
//! Every rule about when to punch, how long to wait and which error is fatal
//! stays in `holepunch.zig` and is not restated here.
//!
//! The module doc `holepunch_run.zig` carries is the argument for the whole
//! file and is not repeated here.

const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const report = @import("report.zig");
const candidates_mod = @import("holepunch_run_candidate.zig");

const Nanos = report.Nanos;
const Path = holepunch.Path;
const SocketAddr = addr.SocketAddr;

const Set = candidates_mod.Set;
const Filed = candidates_mod.Filed;
const Absorbed = candidates_mod.Absorbed;
const Peered = candidates_mod.Peered;

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
/// What one turn of the join decided.
pub const Action = union(enum) {
    /// Ask the QUIC stack to start a round on this connection, now.
    punch: holepunch.ConnId,
    /// Ask again at this instant. The gate's own answer for a round that is
    /// not due, and the only instruction a quiet connection ever gets.
    wakeAt: Nanos,
    /// Punch no more on this connection. Only ever the gate's answer to a
    /// fatal refusal; nothing here decides one.
    stop,
    /// The candidate set is over `holepunch.max_qnt_addresses`, carrying this
    /// many addresses in total. Asked before the gate, because the stack
    /// answers a set like this with `too_many_addresses`, which is fatal —
    /// so the round is refused rather than asked and refused.
    tooManyAddresses: usize,
    /// No round is due. Why is the gate's own state to say: `punch.punch` is
    /// null when there is no client connection, `punch.stopped` is set when a
    /// fatal refusal has already ended it, and a live connection is waiting
    /// for the interval to expire.
    hold,
};
/// The tally of a burst that has filed nothing yet.
const none_pruned: holepunch.Pruned = .{
    .kept = 0,
    .unusable_dropped = 0,
    .inactive_dropped = 0,
};

/// One peer's NAT traversal as this file keeps it.
///
/// The gate's state is held whole rather than restated: every rule about when
/// to punch, how long to wait and which error is fatal belongs to
/// `holepunch.zig`, and a copy of one of those rules here would be a second
/// opinion about it. What this value adds is the storage the gate borrows, the
/// producers for both candidate sets and the verdict, and the three questions
/// neither of the two modules above is asked.
pub const Join = struct {
    /// The gate's own state, held whole. Reachable and writable, because a
    /// caller assembling a `Join` from parts needs it; the one rule that goes
    /// with it is that `last.remote`, when set, names a buffer the *caller*
    /// keeps alive, and that `previous` below stays the recorded local set for
    /// whichever round `last` names. Writing `last` directly without putting
    /// that set in `previous` makes `ready` compare this round's candidates
    /// against the wrong one.
    punch: holepunch.PunchState = .{},

    /// What the last folded report said about the mapping, carried whole:
    /// null until two probes to *different* relays of one family have
    /// answered, which is `report.Varying`'s rule and is not restated here.
    ///
    /// Consulted by nothing in this file, and deliberately: `holepunch.decide`
    /// takes no verdict, and inventing a rule that consulted one would be a
    /// policy decision about when to punch, which is the gate's to make. See
    /// the module doc.
    varies_by_dest: ?bool = null,

    /// This node's candidates, as the gate compares them. This file's storage
    /// for the lifetime reason in the module doc: rewritten by every report
    /// and never by `settle`.
    local: Set = .{},

    /// The set the last accepted round was started with, which the gate
    /// compares `local` against. Written by `settle` and by nothing else, so a
    /// round's candidates survive every later report until the next round
    /// records its own.
    ///
    /// Plain storage: no slice stored anywhere names it, and `ready` slices it
    /// afresh on each turn. That is what makes a copied `Join` independent of
    /// the `Join` it was copied from. See the module doc under "A value, and
    /// what that costs".
    previous: Set = .{},

    /// The peer's candidates, as the gate compares them. This file's storage
    /// for the lifetime reason in the module doc: rewritten by every record
    /// and never by `settle`, which records the stack's own answer against
    /// `local` instead.
    remote: Set = .{},

    /// The peer's path table. Inline because a per-peer table is what the
    /// gate prunes and nothing below `ozai.base` takes an allocator; see
    /// `max_paths` for the bound and for what it costs.
    paths: [max_paths]Path = undefined,
    path_count: usize = 0,

    /// Point the join at the connection rounds run on.
    ///
    /// A pass-through to `holepunch.selectPunchConnection`, which owns the
    /// rule: the lowest client connection, and none at all when every
    /// connection is server-side.
    ///
    /// The table is the caller's because this layer has none to give: it
    /// lives in the transport, one layer up, and the side the rule turns on
    /// does not cross it. See the module doc.
    pub fn selectConnection(self: *Join, conns: []const holepunch.Connection) void {
        self.punch.punch = holepunch.selectPunchConnection(conns);
    }

    /// Record what a folded probe round says this node can be reached at.
    ///
    /// `folded` is borrowed rather than taken by value: a `report.Report`
    /// carries its latency table inline — three families of `max_relays`
    /// entries, each holding a `RelayUrl` by value — and this reads two
    /// addresses and a classification out of it.
    ///
    /// `socket` is the caller's interface addresses, which is the half of the
    /// local set no round can measure. An empty slice is a host that has
    /// published none, not a host with none: the gate is handed what was
    /// known and answers about it, and the stack's `not_enough_addresses` is
    /// the answer to a set it cannot use. `net/interface.zig` is what
    /// enumerates them; what is missing is the caller, because nothing in
    /// `src/node/` reaches that module.
    pub fn observeReport(
        self: *Join,
        folded: *const report.Report,
        socket: []const SocketAddr,
    ) void {
        self.varies_by_dest = folded.mappingVariesByDest();
        self.local.clear();
        if (folded.global_v4) |public| self.local.append(public);
        if (folded.global_v6) |public| self.local.append(public);
        for (socket) |candidate| self.local.append(candidate);
    }

    /// Record what the peer's own published record says it can be reached at.
    ///
    /// The one source of a peer's candidates this layer can read without
    /// asking anything: a `NodeAddr` is what discovery, a ticket and a peer's
    /// own announcement all hand over, and this reads it with no allocator.
    ///
    /// Only the `.ip` entries are candidates. A relay is the fallback path
    /// rather than a way in, and a custom transport is not an IP socket;
    /// neither is something to punch at, and both are counted rather than
    /// dropped in silence.
    ///
    /// Each direct address is filed twice — in the peer's advertised set and
    /// in the path table — by this one call, so the two cannot disagree: every
    /// candidate the gate is handed is a path the caller has been told about.
    /// A path the table does not carry arrives `unknown`, the status the module
    /// doc's multipath gap leaves it with; one the table already carries keeps
    /// the status it has, because a record names addresses and says nothing
    /// about what happened over them. Either way `observe` is the seam that
    /// changes a status, for the caller that learned the peer answered on one.
    ///
    /// `remote` is cleared first, for `local`'s reason: a record replaces the
    /// record before it, and an address the peer has withdrawn must stop being
    /// punched at.
    pub fn observePeer(self: *Join, reported: *const addr.NodeAddr) Peered {
        var result: Peered = .{
            .candidates = .{ .added = 0, .refused = 0, .pruned = none_pruned },
            .not_candidates = 0,
        };
        self.remote.clear();
        for (reported.addrs) |entry| switch (entry) {
            .ip => |socket| {
                self.remote.append(socket);
                self.file(&result.candidates, socket);
            },
            .relay, .custom => result.not_candidates += 1,
        };
        result.candidates.pruned.kept = self.path_count;
        return result;
    }

    /// Ask whether a round should start now.
    ///
    /// The ceiling first, and it gates: a set past
    /// `holepunch.max_qnt_addresses` is a fatal refusal from the stack rather
    /// than a slow one, so asking the gate about timing would be work spent
    /// on a round that must not be asked. Everything else is the gate's own
    /// answer, passed through.
    ///
    /// By pointer: `Join` holds `max_paths` paths, and a turn that copied it
    /// would copy the whole table to read three fields of it.
    pub fn ready(self: *const Join, now: Nanos) Action {
        const advertised = self.local.len + self.local.overflow +
            self.remote.len + self.remote.overflow;
        if (!holepunch.mayAdvertise(advertised)) return .{ .tooManyAddresses = advertised };
        // The gate's turn reads its state and leaves it as it was, so only its
        // instruction is wanted here.
        const step = holepunch.decide(self.punch, now, .{
            .local = self.local.slice(),
            .remote = self.remote.slice(),
            .previous_local = self.previous.slice(),
        });
        return instruction(step.action);
    }

    /// Fold what the QUIC stack said about a round back in, and hand back what
    /// the gate wants next.
    ///
    /// The classification is not read here. `holepunch.settle` has already
    /// decided whether a refusal is a 100 ms retry or the end of punching, and
    /// a caller that classified it again would be a second opinion about a
    /// policy this file does not own.
    ///
    /// What is left is the candidate set the round started with, and it is
    /// copied into `previous` rather than swapped in. A swap would keep the
    /// buffer's address while its contents move, and `previous` is read by
    /// value at the next `ready`, so a swap would have nothing to point at.
    /// Only an accepted round copies: a refusal moved no candidate, so the
    /// record the last accepted round made is still the record, and the gate
    /// reads the same candidates as new and tries again rather than sitting
    /// out the interval.
    ///
    /// `previous` is inline storage and `ready` slices the current receiver.
    /// Copies therefore preserve that recorded local set independently.
    /// A manually populated `punch.last.remote` still borrows caller storage,
    /// as stated on `punch`; copying the join does not copy those external bytes.
    pub fn settle(self: *Join, now: Nanos, outcome: holepunch.Outcome) Action {
        if (outcome == .accepted) self.previous = self.local;
        const step = holepunch.settle(self.punch, now, outcome);
        self.punch = step.next;
        return instruction(step.action);
    }

    /// Record one path and enforce the ceiling over the table.
    ///
    /// An address the table already carries has its status replaced by the one
    /// this call names, and gets no second entry: a path table is a map keyed
    /// by address, and two entries for one address would make the prune count
    /// one path twice. This is the only call that replaces a status — `absorb`
    /// and `observePeer` file a candidate the table already carries without
    /// touching one, because neither can name a status.
    ///
    /// The status is the caller's to know. `unknown` is what a candidate
    /// arrives as, because a probe round learns an address and never learns
    /// whether anything was sent over it; `open`, `inactive` and `unusable`
    /// are what the multipath layer reports, and no rule about which follows
    /// which is written here.
    ///
    /// The paths are public storage and a caller can write into it, so the
    /// prune runs on every call and not only on the ones that recorded
    /// something: the ceiling is enforced whatever the table's last change
    /// was.
    pub fn observe(self: *Join, path: Path) Filed {
        if (self.find(path.addr)) |held| {
            held.status = path.status;
        } else if (self.path_count == self.paths.len) {
            // The status came with the address and the address is not stored,
            // so the status is dropped with it: a path nobody can see is a
            // path nobody may claim to have tried.
            return .{ .stored = false, .pruned = self.prune() };
        } else {
            self.paths[self.path_count] = path;
            self.path_count += 1;
        }
        return .{ .stored = true, .pruned = self.prune() };
    }

    /// File one untried candidate, and add what it cost to a running tally.
    ///
    /// A candidate the table already carries keeps the status it has. Filing
    /// it `unknown` again would answer for a status this producer cannot name:
    /// a record says where the peer is and says nothing about what happened
    /// over the path, so a path that was open would read back as one nobody
    /// has tried — and `holepunch.prune` reads that status to decide what a
    /// burst may not evict. `observe` is the seam that changes one; this is
    /// not it.
    ///
    /// `unknown` for a candidate the table does not carry, because that is
    /// what the module doc's multipath gap leaves every candidate with, and
    /// the prune runs on every candidate rather than only on the ones that
    /// inserted: `paths` is public storage a caller can write into, so the
    /// ceiling is enforced whatever the table's last change was.
    fn file(self: *Join, into: *Absorbed, candidate: SocketAddr) void {
        // Read before the change, because `Absorbed.added` counts candidates
        // the table did not already carry, and an address it does carry is
        // not filed again below.
        const known = self.find(.{ .ip = candidate }) != null;
        const filed: Filed = if (known)
            .{ .stored = true, .pruned = self.prune() }
        else
            self.observe(.{ .addr = .{ .ip = candidate }, .status = .unknown });
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
    /// prune runs on every change: the rule is that an unusable path goes
    /// first and always, and a single prune at the end of a burst would leave
    /// a burst's unusable paths sitting in the table for the whole of it.
    ///
    /// Every candidate the table does not carry arrives `unknown` through
    /// `file`, which is the status the module doc's multipath gap leaves it
    /// with; one the table already carries keeps the status it has.
    pub fn absorb(self: *Join, candidates: []const SocketAddr) Absorbed {
        var result: Absorbed = .{ .added = 0, .refused = 0, .pruned = none_pruned };
        for (candidates) |candidate| self.file(&result, candidate);
        result.pruned.kept = self.path_count;
        return result;
    }

    /// Enforce the per-peer ceiling, in place.
    ///
    /// A pass-through to `holepunch.prune`: the order the rule fires in —
    /// unusable first and always, then at most
    /// `holepunch.max_inactive_non_relay_paths` of the rest, and never a path
    /// nobody has tried — is the gate's and is not restated here. What this
    /// adds is where the survivors live, which is this value's own storage.
    pub fn prune(self: *Join) holepunch.Pruned {
        const result = holepunch.prune(self.paths[0..self.path_count]);
        self.path_count = result.kept;
        return result;
    }

    /// The table's paths, for a caller reading what survived.
    pub fn table(self: *const Join) []const Path {
        return self.paths[0..self.path_count];
    }

    /// The slot holding `wanted`, or null when the table does not carry it.
    fn find(self: *Join, wanted: addr.TransportAddr) ?*Path {
        var index: usize = 0;
        while (index < self.path_count) : (index += 1) {
            if (self.paths[index].addr.order(wanted) == .eq) return &self.paths[index];
        }
        return null;
    }
};

/// The gate's instruction in this file's vocabulary.
///
/// One switch for both callers, so the mapping is stated once. `stopPunching`
/// is mapped rather than refused: `holepunch.decide` does not return it today,
/// and a `switch` that did not answer it would be a second opinion about
/// which of the gate's instructions exist.
fn instruction(action: ?holepunch.Action) Action {
    return switch (action orelse return .hold) {
        .initiateNatTraversalRound => |conn| .{ .punch = conn },
        .wakeAt => |at| .{ .wakeAt = at },
        .stopPunching => .stop,
    };
}
