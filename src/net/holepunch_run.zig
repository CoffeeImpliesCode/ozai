//! Running the gate on what a probe round measured: the join between
//! `net/report.zig` and `net/holepunch.zig`.
//!
//! Three modules sit around a hole in the tree. `probe_run.zig` runs a round
//! and files every answer into a `probe.Results`. `probe.zig` folds those
//! into a `report.Report`. `holepunch.zig` decides whether to ask the QUIC
//! stack for a NAT-traversal round, from a candidate set, an instant and a
//! connection. This file is the producer's other half: it turns a folded
//! report and a peer's published record into the gate's inputs, hands the
//! gate's answer back, and restates none of the three modules above it.
//!
//! # The seven inputs, and where each one comes from
//!
//! A probe round measures **this node**, from the inside, over QUIC. The gate
//! asks about **one connection**, from the outside. Three of its seven inputs
//! have a producer here and four do not, and each of the four is named below
//! with what would close it. A reader without this section reads a gap as a
//! rule, and then wonders why the gap is never closed.
//!
//! ```text
//! gate input                          | where it comes from
//! -------------------------------------|----------------------------------
//! local: where this node is reachable | `observeReport`
//! the mapping verdict                  | `observeReport`
//! remote: where the peer is reachable | `observePeer`
//! the connection to punch on          | gap: the transport's table
//! what the stack said about a round   | gap: no QNT in the vendored core
//! whether a path carried traffic      | gap: no multipath layer
//! the socket's interface addresses    | gap: no interface enumeration
//! ```
//!
//! **The connection.** `holepunch.selectPunchConnection` turns a table into
//! the one connection a round runs on, and `Join.selectConnection` is its
//! pass-through. The table belongs to the transport — it is
//! `transport/quic_bridge.Bridge.manager.entries`, one layer above this one
//! (`docs/ARCHITECTURE.md`) — and nothing under `src/net/` imports
//! `src/transport/`, which is what keeps this layer drivable with no QUIC
//! substrate at all. `probe_run.Transport` is how the layer reaches the
//! transport when it has to: a vtable the transport side fills, never an
//! import, and no implementation of one for a connection table exists on the
//! other side of it yet.
//!
//! The side is one field away for whoever writes that implementation:
//! `quic_bridge.Conn.entry` is public and `conn.entry.conn.is_server`
//! (`vendor/quic/src/quic/connection.zig:608`) is what `transport/dial.zig`
//! and `src/node/node.zig` already read. What this layer could not do with
//! it is narrow the table to one peer, because the table holds every
//! connection this node has and a `Join` is one peer's.
//!
//! **The stack's answer.** `initiate_nat_traversal_round` is
//! `draft-seemann-quic-nat-traversal-02`, and the vendored core has no QNT:
//! `qnt`, `traversal` and `path_id` appear nowhere under `vendor/quic/src`,
//! and `docs/DECISIONS/0001` gives the reason — iroh's QUIC is n0's own fork
//! and this is endel/quic-zig. So `holepunch.Outcome` is a value the caller
//! brings back from a call this project cannot make, `settle` is where it
//! arrives, and `holepunch.classify` stays the only thing that reads it.
//!
//! **A path's status.** Nothing in this tree watches traffic per path. The
//! core keeps `paths: [2]NetworkPath` under one `active_path_idx`
//! (`vendor/quic/src/quic/connection.zig:626`) — an active/candidate register
//! rather than a path set, which `DECISIONS/0001` measured and recorded — and
//! `Conn.drain` sends every datagram at the one peer address it holds. So
//! `observe` is handed its status and `absorb` files `unknown`, and no rule
//! about which status follows which is written here.
//!
//! **The socket's interface addresses.** The half of the local set no round
//! measures, and the one argument of `observeReport` a caller has to find.
//! The socket knows a single address and it is not one of these:
//! `transport/socket.zig:885` reads it back with `getsockname`, which on a
//! wildcard bind is `0.0.0.0` or `::` with the ephemeral port — where this
//! node is *bound*, not where a peer may reach it, and advertising it would
//! be worse than advertising nothing. The addresses behind it need
//! `getifaddrs` or a netlink route dump, and neither appears anywhere under
//! `src/`: there is no netwatcher here to call one.
//!
//! # The two mappings
//!
//! `global_v4` and `global_v6` are the addresses a relay saw this node come
//! from, and they are the only form of "where am I reachable" a round can
//! produce. The local set is those, then the caller's interface addresses.
//! Order is not a rule — `holepunch.hasNewAddress` compares sets, and
//! `holepunch.decide` cannot tell which of the two sources a candidate came
//! from.
//!
//! The peer's candidates come the other way round: from the record the peer
//! published, and only from its `.ip` entries. A relay is the fallback path
//! rather than a way in, and a custom transport is not an IP socket, so
//! neither is something to punch at and both are counted rather than dropped
//! in silence. Every direct address is filed twice — once in the advertised
//! set the gate compares, once in the path table the caller learns from —
//! because upstream those are one record (`PathEntry` in
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`) and this file
//! keeps them apart: the gate borrows a set while the table owns one.
//!
//! The verdict is carried and consulted by nothing here, and that is not an
//! omission. `holepunch.decide` takes no verdict, and a rule that consulted
//! one would be invented: a destination-dependent mapping makes hole punching
//! *harder* and does not make it pointless, because the round itself opens
//! the mapping it needs. The verdict is here for the caller deciding whether
//! this node may be published as directly reachable, and only two probes to
//! *different* relays can produce it.
//!
//! # Three buffers, because the gate compares against the last round
//!
//! `holepunch.decide` compares this round's candidate sets against the ones
//! the last round was started with, so those have to outlive the round that
//! produced them. One buffer would be rewritten under the comparison, and a
//! slice into storage the caller owns would make the caller's bookkeeping
//! part of the gate's invariant. So each set this file keeps is its own
//! buffer: live local, recorded local, and the peer's. `settle` copies the
//! live local set into the recorded one and only an accepted round does so,
//! because it is the only outcome that records a set at all. The copy is a
//! few hundred bytes once a round.
//!
//! The recorded buffer is storage this file owns and nothing points into it.
//! `ready` re-slices it on each turn and hands the slice to the gate as
//! `holepunch.Candidates.previous_local`; the gate reads it and stores
//! nothing. That is the whole point of the arrangement, and the earlier
//! arrangement — handing the gate a slice of the recorded buffer and letting
//! it keep that slice in `PunchState.last` — made a copy of a settled `Join`
//! read the *original's* bytes, silently, with nothing to tell the two apart.
//! A value that borrows from itself is not a value.
//!
//! # A value, and what that costs
//!
//! `Join` is a value: no pointer to the transport, no task, no allocator, and
//! every set in it is its own storage. Copying or moving one carries all of
//! it — including the recorded candidate set, which is why that set is
//! re-sliced per turn rather than pointed at once. A copy is a snapshot: the
//! two then answer independently, and acting on both means two nodes punching
//! for one peer.
//!
//! One slice in a settled `Join` is still borrowed, and it is not one of the
//! three buffers: `punch.last.remote` names the candidate list the QUIC stack
//! returned, which arrives in `holepunch.Outcome.accepted` and belongs to the
//! caller. The caller keeps it alive for as long as it reads `punch`, and a
//! copy names the same caller buffer. The stack is one of the gaps above, so
//! there is no producer here to hold anyone to that.
//!
//! # What the gate already decides, and what this file adds
//!
//! Timing is the gate's: `holepunch.decide` answers when a round is due,
//! `holepunch.settle` answers what a refusal means, and `holepunch.prune`
//! answers what a changed path table keeps. This file adds three questions
//! none of them is asked:
//!
//! - **Whether the candidate set may be handed over at all.** A set past
//!   `holepunch.max_qnt_addresses` is answered `too_many_addresses`, which
//!   is fatal rather than slow, so `ready` asks `holepunch.mayAdvertise`
//!   before the gate is consulted at all and refuses the round itself.
//! - **Where the gate's borrowed slices live.** `Join` owns them, so a
//!   caller cannot hand the gate a buffer it is about to rewrite.
//! - **What the burst did.** `absorb` and `observePeer` file candidates and
//!   prune as they go, and hand back what the prune dropped, so the plan's
//!   rule — a burst of untested address-lookup results must not evict the
//!   paths that work — is observable from the caller's side of the seam
//!   rather than only from `holepunch.prune`'s own tests.
//!
//! Freshness is deliberately absent from that list. `report.ProbeResult`
//! carries the instant it was observed and `report.fold` ages it against
//! `report.max_report_age` for the preferred-relay window, but nothing here
//! ages the candidate sets: a caller holding an old report or an old record
//! is a caller that has already decided it is worth handing over.
//!
//! # No clock, no thread, no socket, no allocator
//!
//! Every instant is an argument — `ready(now)` and `settle(now, outcome)` —
//! and a test drives the whole chain on one, from a probe round that opened
//! no socket to a punch decision nobody acted on. Nothing here reads a clock,
//! allocates, or touches a thread: see "A value, and what that costs" for what
//! a `Join` owns and what it borrows.
//!
//! Upstream at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the pin `net/holepunch.zig`
//! carries — for the two things this file joins: `Report` with its
//! `mapping_varies_by_dest`, from `iroh/src/net_report/`, and `PathState`
//! with its `prune_non_relay_paths`, from
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const holepunch = @import("holepunch.zig");
const key = @import("../base/key.zig");
const node_addr = @import("../base/node_addr.zig");
const report = @import("report.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Nanos = report.Nanos;
const Path = holepunch.Path;
const SocketAddr = addr.SocketAddr;

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

    fn clear(self: *Set) void {
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
    fn append(self: *Set, candidate: SocketAddr) void {
        if (self.holds(candidate)) return;
        if (self.len == self.items.len) {
            self.overflow += 1;
            return;
        }
        self.items[self.len] = candidate;
        self.len += 1;
    }
};

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
    /// the answer to a set it cannot use. The module doc says why nothing in
    /// this tree produces them.
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
    pub fn observePeer(self: *Join, reported: *const node_addr.NodeAddr) Peered {
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
    fn find(self: *Join, wanted: transport_addr.TransportAddr) ?*Path {
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

const t = std.testing;
const probe = @import("probe.zig");
const probe_run = @import("probe_run.zig");

/// Ten minutes in, the timeline every test below runs on. Far past every probe
/// instant, and the same constant `probe_run.zig` hands its own rounds.
const start: Nanos = 600 * std.time.ns_per_s;

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// A relay URL rendered into `scratch`. The host is `<n>.example.`, so the
/// URLs sort by index and the fold's relay ordering is predictable.
fn namedRelay(scratch: []u8, index: usize) !base_relay_url.RelayUrl {
    return base_relay_url.RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}

fn relaySet(scratch: []u8) ![3]base_relay_url.RelayUrl {
    return .{
        try namedRelay(scratch[0..64], 0),
        try namedRelay(scratch[64..128], 1),
        try namedRelay(scratch[128..192], 2),
    };
}

/// A direct address on `port`, from the documentation range, so a test that
/// prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
/// The same relay's answer a minute later, after the NAT rebinding.
const rebound_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 11 } }, .port = 61234 };

/// The addresses this node's socket reports: the half of the local set no
/// probe can measure.
const interface: [2]SocketAddr = .{ ip(9000), ip(9001) };

/// One client connection, which is all `holepunch.selectPunchConnection` needs
/// to have somewhere to punch.
const client_conns: []const holepunch.Connection = &.{.{ .id = 4, .side = .client }};

/// The node id a peer's record is published under: one fixed key, so a test
/// is about the addresses in a record and not about who published them.
///
/// Resolved at comptime. The bytes are a constant, so whether they name a
/// curve point is a fact about the build and not about the run: a constant
/// that stopped being one stops the build, where a `catch unreachable` would
/// abort the first test that read it and say nothing about why.
const peer_node: key.NodeId = key.NodeId.fromBytes([_]u8{7} ** 32) catch
    @compileError("the fixed test peer is not a canonical ed25519 point");

/// A published record carrying exactly `addrs`.
///
/// `NodeAddr.addrs` is a mutable slice the type keeps sorted through
/// `insert`, and a test hands over its own array instead: the borrow lasts
/// the length of the test, which is the same borrow `NodeAddr.withRelay`
/// makes into the heap and the reason the type is careful about it.
fn peerRecord(addrs: []transport_addr.TransportAddr) node_addr.NodeAddr {
    return .{ .node_id = peer_node, .addrs = addrs };
}

/// A transport with relays in it, so the chain below runs with no socket.
///
/// One address and one service time per relay, measured from the instant a
/// probe went out, and every open and every close counted: the join has no
/// opinion about the wire, so a test that watched only the fold would not see
/// a probe that never went out. `probe_run.zig` holds a larger fake of this
/// shape for its own tests; this is the part of it a chain needs.
const Wire = struct {
    vtable: probe_run.Transport.VTable = .{
        .open = onOpen,
        .poll = onPoll,
        .close = onClose,
        .beginCheck = onBeginCheck,
        .pollCheck = onPollCheck,
        .endCheck = onEndCheck,
    },
    /// The address each relay reports, or null for one that does not answer.
    /// An HTTPS probe reads no entry, because it reports no address.
    reported: [probe.max_relays]?SocketAddr = @splat(null),
    /// How long each relay takes, from the instant its probe went out.
    think: [probe.max_relays]Nanos = @splat(0),
    live: [probe.max_tasks]probe_run.Open = undefined,
    live_len: usize = 0,
    answered: [probe.max_tasks]bool = @splat(false),
    opened: usize = 0,
    closed: usize = 0,

    fn transport(self: *Wire) probe_run.Transport {
        return .{ .vtable = &self.vtable, .ctx = self };
    }

    /// Forget the previous round's probes and counters, keeping what the
    /// relays are configured to answer. The counters are about one round.
    fn forgetRound(self: *Wire) void {
        self.live_len = 0;
        self.answered = @splat(false);
        self.opened = 0;
        self.closed = 0;
    }

    /// The answer this wire has for `open` at `now`, or null while it has
    /// none: the relay has not finished thinking, or it reports no address
    /// for the family the probe asked about.
    fn answer(self: *const Wire, open: probe_run.Open, now: Nanos) ?probe_run.Observation {
        if (now -| open.at < self.think[open.task.relay]) return null;
        return switch (open.task.proto) {
            .https => .{ .https = self.think[open.task.relay] },
            .qad_ipv4, .qad_ipv6 => .{ .qad = .{
                .latency = self.think[open.task.relay],
                .reported = self.reported[open.task.relay] orelse return null,
            } },
        };
    }
};

fn onOpen(ctx: *anyopaque, at: probe_run.Open) probe_run.SendError!void {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    if (self.live_len == probe.max_tasks) return error.Full;
    self.live[self.live_len] = at;
    self.live_len += 1;
    self.opened += 1;
}

fn onPoll(ctx: *anyopaque, now: Nanos) ?probe_run.Reply {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    for (self.live[0..self.live_len], 0..) |open, index| {
        if (self.answered[index]) continue;
        const value = self.answer(open, now) orelse continue;
        self.answered[index] = true;
        return .{ .task = open.task, .value = value };
    }
    return null;
}

fn onClose(ctx: *anyopaque, _: probe.Task, _: probe_run.Why) void {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    self.closed += 1;
}

fn onBeginCheck(_: *anyopaque, _: probe_run.Check) probe_run.SendError!void {
    // No round below schedules a check: `probe.Round.captive_portal_check`
    // is false and the join never sets it, so a call here would be a round
    // planning something this file did not ask for.
    return error.Full;
}

fn onPollCheck(_: *anyopaque, _: Nanos) ?bool {
    return null;
}

fn onEndCheck(_: *anyopaque, _: probe_run.Why) void {}

/// Run one probe round against the wire and hand back what it folded.
///
/// `Results` and `InFlight` are locals because `probe.fold` returns a
/// `report.Report` by value and nothing in it borrows them: the folded report
/// is what crosses the seam, not the round's storage.
fn probeRound(
    wire: *Wire,
    relays: []const base_relay_url.RelayUrl,
    now: Nanos,
    if_state: probe.IfState,
    protocols: probe.Protocols,
) !report.Report {
    wire.forgetRound();
    // The round's own clock, advanced by the loop to each `wake_at`: the
    // instant is the argument this layer takes instead of reading one.
    var clock = now;
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    var runner = probe.new(.{
        .relays = relays,
        .if_state = if_state,
        .protocols = protocols,
        .now = clock,
    }, &results);
    while (true) {
        const turn = try probe_run.drive(runner, wire.transport(), &in_flight, .{ .now = clock });
        runner = turn.runner;
        clock = turn.wake_at orelse break;
    }
    // Every probe the round opened was closed, including the ones still in
    // flight when the answers satisfied it.
    try t.expectEqual(wire.opened, wire.closed);
    return probe.fold(runner, .{}, clock);
}

/// A wire whose first two relays answer an address-discovery probe with
/// different public addresses, which is what makes the mapping vary.
fn varyingWire() Wire {
    var wire: Wire = .{};
    wire.reported[0] = public_v4;
    wire.reported[1] = rebound_v4;
    wire.think[0] = millis(9);
    wire.think[1] = millis(11);
    return wire;
}

/// How many of the table's paths are on ports `first`..`first + count`.
fn carries(join: *const Join, first: u16, count: u16) usize {
    var total: usize = 0;
    for (join.table()) |path| {
        switch (path.addr) {
            .ip => |socket| {
                if (socket.port >= first and socket.port < first + count) total += 1;
            },
            else => {},
        }
    }
    return total;
}

/// How many of those paths are `inactive`: punched once, and it worked.
fn working(join: *const Join, first: u16, count: u16) usize {
    var total: usize = 0;
    for (join.table()) |path| {
        switch (path.addr) {
            .ip => |socket| {
                if (socket.port < first or socket.port >= first + count) continue;
                if (path.status == .inactive) total += 1;
            },
            else => {},
        }
    }
    return total;
}

/// How many of the table's paths are relay paths, which no prune may drop.
fn relayPaths(join: *const Join) usize {
    var total: usize = 0;
    for (join.table()) |path| {
        switch (path.addr) {
            .relay => total += 1,
            else => {},
        }
    }
    return total;
}

test "a probe round becomes a punch the gate asks for" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire = varyingWire();

    const folded = try probeRound(
        &wire,
        &relays,
        start,
        .{ .have_v4 = true, .have_v6 = false },
        .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
    );
    // Two relays, two different v4 addresses: the round measured this node's
    // public address and, because the two disagree, its mapping as well.
    try t.expect(folded.udp_v4);
    try t.expectEqual(@as(?bool, true), folded.mapping_varies_by_dest_ipv4);
    try t.expectEqualDeep(public_v4, folded.global_v4.?);

    var join: Join = .{};
    join.selectConnection(client_conns);
    join.observeReport(&folded, &interface);

    // The set the gate is handed is the one address the relay saw, plus the
    // two the socket reported. Nothing else: the peer's addresses are the
    // peer's own, and no round measured them.
    try t.expectEqual(@as(usize, 3), join.local.len);
    try t.expect(std.meta.eql(public_v4, join.local.slice()[0]));
    try t.expect(std.meta.eql(interface[1], join.local.slice()[2]));
    try t.expectEqual(@as(usize, 0), join.local.overflow);
    // The verdict crossed the seam whole, and this file did not compute it.
    try t.expectEqual(@as(?bool, true), join.varies_by_dest);
    try t.expect(join.remote.len == 0);

    // And the gate says punch: a client connection and no round on record.
    // Nothing here decided that, and `holepunch.decide` alone would have said
    // it from the same two inputs.
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start)));
    try t.expect(std.meta.eql(
        holepunch.Action{ .initiateNatTraversalRound = 4 },
        try gateSays(&join, start),
    ));

    // The same report offered again with one address twice: `len` is what the
    // ceiling is asked with, and a repeat that counted would refuse a set for
    // candidates it does not hold.
    const repeated = [_]SocketAddr{ public_v4, public_v4, interface[0] };
    join.observeReport(&folded, &repeated);
    try t.expectEqual(@as(usize, 2), join.local.len);
}

test "a rebind inside the interval is a punch and an unchanged report is not" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire = varyingWire();
    const peer = [_]SocketAddr{ip(7000)};

    const first = try probeRound(
        &wire,
        &relays,
        start,
        .{ .have_v4 = true, .have_v6 = false },
        .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
    );
    var join: Join = .{};
    join.selectConnection(client_conns);
    join.observeReport(&first, &interface);

    // An accepted round schedules nothing: the next trigger is an address
    // change, the wakeup already held, or the periodic check.
    try t.expect(std.meta.eql(Action.hold, join.settle(start, .{ .accepted = &peer })));
    // A millisecond later nothing has moved and the interval has not
    // elapsed, so the gate waits rather than flooding the relay.
    try t.expect(std.meta.eql(
        Action{ .wakeAt = start + holepunch.punch_interval },
        join.ready(start + millis(1)),
    ));

    // The same round run again, and this time the first relay reports the
    // rebound address. The relay's answer is the only thing that changed.
    wire.reported[0] = rebound_v4;
    const second = try probeRound(
        &wire,
        &relays,
        start + millis(2),
        .{ .have_v4 = true, .have_v6 = false },
        .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
    );
    try t.expectEqualDeep(rebound_v4, second.global_v4.?);
    join.observeReport(&second, &interface);

    // Two milliseconds after the last round: inside the interval, with a
    // local candidate that was not there then. The plan's first rule, driven
    // by a probe round rather than by a hand-built candidate — and it is the
    // gate that fired it, from the two sets the join kept for it.
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start + millis(2))));

    // And the other half of the plan's first rule, from the half of the chain
    // no probe round reaches: a peer address that was not there then is a
    // punch for the same reason, because `holepunch.decide` compares both
    // sets the same way and only one of them is this file's.
    var seen = [_]transport_addr.TransportAddr{ .{ .ip = peer[0] }, .{ .ip = ip(7001) } };
    _ = join.observePeer(&peerRecord(&seen));
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start + millis(3))));
}

test "a refused round retries and a fatal one stops, as the gate classified" {
    var join: Join = .{};
    join.selectConnection(client_conns);
    // Retryable: the gate's own 100 ms, passed through rather than restated.
    try t.expect(std.meta.eql(
        Action{ .wakeAt = start + holepunch.retry_interval },
        join.settle(start, .{ .refused = .not_enough_addresses }),
    ));
    // Fatal: punching ends and `ready` says nothing afterwards, whatever the
    // candidates are.
    try t.expect(std.meta.eql(
        Action.stop,
        join.settle(start, .{ .refused = .extension_not_negotiated }),
    ));
    try t.expect(std.meta.eql(Action.hold, join.ready(start + holepunch.punch_interval)));
}

test "a round that measures no address supplies neither of the two" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Wire = .{};
    wire.think[0] = millis(12);
    wire.think[1] = millis(9);
    wire.think[2] = millis(30);

    // An HTTPS round: no address family on the host, so no QUIC probe is
    // planned at all and every answer is a latency.
    const folded = try probeRound(&wire, &relays, start, .{}, .{ .https = true });
    try t.expect(!folded.hasUdp());
    try t.expect(folded.mappingVariesByDest() == null);
    try t.expect(folded.preferred_relay != null);

    var join: Join = .{};
    join.selectConnection(client_conns);
    join.observeReport(&folded, &.{});
    // The asymmetry, end to end: a round that timed three relays supplied no
    // candidate to punch at and no verdict, and this file does not fill the
    // gap with something a probe cannot know.
    try t.expectEqual(@as(usize, 0), join.local.len);
    try t.expect(join.varies_by_dest == null);

    // And the gate still punches: an empty candidate set is not this file's
    // business to refuse. `not_enough_addresses` is the stack's answer to a
    // set it cannot use, and it retries.
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start)));
}

test "the advertised ceiling is refused before the gate is asked" {
    var join: Join = .{};
    join.selectConnection(client_conns);
    const blank: report.Report = .{};
    // One interface address past what the stack will accept. A report names at
    // most two addresses, so the ceiling is reached from the caller's side —
    // which is where a host with twenty VPN and docker interfaces reaches it.
    var socket: [holepunch.max_qnt_addresses + 1]SocketAddr = undefined;
    for (&socket, 0..) |*slot, index| slot.* = ip(@intCast(index));
    join.observeReport(&blank, &socket);

    try t.expectEqual(@as(usize, holepunch.max_qnt_addresses), join.local.len);
    try t.expectEqual(@as(usize, 1), join.local.overflow);

    // The gate alone would have punched: there is no round on record, so
    // nothing holds the interval back. Asking it about timing on a set the
    // stack answers `too_many_addresses` to would be work spent on a fatal
    // refusal.
    try t.expect(std.meta.eql(
        holepunch.Action{ .initiateNatTraversalRound = 4 },
        try gateSays(&join, start),
    ));
    try t.expect(std.meta.eql(
        Action{ .tooManyAddresses = holepunch.max_qnt_addresses + 1 },
        join.ready(start),
    ));
    // The peer's addresses count towards the same ceiling, because it is one
    // connection's advertised set.
    var published = [_]transport_addr.TransportAddr{.{ .ip = ip(7000) }};
    _ = join.observePeer(&peerRecord(&published));
    try t.expect(std.meta.eql(
        Action{ .tooManyAddresses = holepunch.max_qnt_addresses + 2 },
        join.ready(start),
    ));
}

test "a burst of untested candidates does not evict the paths that work" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire = varyingWire();
    const peer = [_]SocketAddr{ip(7000)};

    // The chain first, so the burst lands on a peer whose gate has already run:
    // a round, a fold, a punch, and an accepted answer.
    const folded = try probeRound(
        &wire,
        &relays,
        start,
        .{ .have_v4 = true, .have_v6 = false },
        .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
    );
    var join: Join = .{};
    join.selectConnection(client_conns);
    join.observeReport(&folded, &interface);
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start)));
    _ = join.settle(start, .{ .accepted = &peer });

    // Ten paths that were punched and worked, closed before the burst arrived,
    // and five that were punched and did not. The relay path is the fallback
    // and no prune may take it.
    for (0..10) |index| {
        const port: u16 = @intCast(3000 + index);
        try t.expect(join.observe(.{
            .addr = .{ .ip = ip(port) },
            .status = .{ .inactive = start -| millis(10 - index) },
        }).stored);
    }
    for (0..5) |index| {
        const port: u16 = @intCast(3100 + index);
        try t.expect(join.observe(.{ .addr = .{ .ip = ip(port) }, .status = .unusable }).stored);
    }
    _ = join.observe(.{ .addr = .{ .relay = relays[0] }, .status = .unusable });

    // The burst the plan names: forty address-lookup results, none of them
    // tried, every one of them newer than the paths that have been tried.
    var burst: [40]SocketAddr = undefined;
    for (&burst, 0..) |*slot, index| slot.* = ip(@intCast(4000 + index));
    const absorbed = join.absorb(&burst);

    try t.expectEqual(@as(usize, 40), absorbed.added);
    try t.expectEqual(@as(usize, 0), absorbed.refused);
    // The five that failed went first and went once. Nothing else was dropped:
    // the ten that worked are at the cap, and every one of them is older than
    // the burst, so an eviction ordered by freshness rather than by what is
    // known would have taken all of them and kept forty never-tried ones.
    try t.expectEqual(@as(usize, 5), absorbed.pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 0), absorbed.pruned.inactive_dropped);

    try t.expectEqual(@as(usize, 10), working(&join, 3000, 10));
    try t.expectEqual(@as(usize, 10), carries(&join, 3000, 10));
    try t.expectEqual(@as(usize, 0), carries(&join, 3100, 5));
    try t.expectEqual(@as(usize, 40), carries(&join, 4000, 40));
    try t.expectEqual(@as(usize, 1), relayPaths(&join));

    // And the table is what those paths add up to: the burst lengthened it
    // rather than shortening it, which is what `holepunch.prune` documents
    // about paths nobody has tried.
    try t.expectEqual(@as(usize, 51), join.path_count);
    try t.expectEqual(join.path_count, absorbed.pruned.kept);
}

test "a burst through the peer's record does not evict the paths that work" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire = varyingWire();
    const peer = [_]SocketAddr{ip(7000)};

    // The same table the burst test above builds, reached the same way: a
    // round, a fold, a punch, an accepted answer, ten paths that worked and
    // five that did not, and the relay fallback.
    const folded = try probeRound(
        &wire,
        &relays,
        start,
        .{ .have_v4 = true, .have_v6 = false },
        .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
    );
    var join: Join = .{};
    join.selectConnection(client_conns);
    join.observeReport(&folded, &interface);
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start)));
    _ = join.settle(start, .{ .accepted = &peer });

    for (0..10) |index| {
        const port: u16 = @intCast(3000 + index);
        try t.expect(join.observe(.{
            .addr = .{ .ip = ip(port) },
            .status = .{ .inactive = start -| millis(10 - index) },
        }).stored);
    }
    for (0..5) |index| {
        const port: u16 = @intCast(3100 + index);
        try t.expect(join.observe(.{ .addr = .{ .ip = ip(port) }, .status = .unusable }).stored);
    }
    _ = join.observe(.{ .addr = .{ .relay = relays[0] }, .status = .unusable });

    // The same forty untried candidates, this time as the second way into the
    // table: one peer's own record, published all at once. This is the path
    // the module doc promises, so the rule the test above pins is re-pinned
    // here — a producer that bypassed the prune would be worse than none.
    var published: [40]transport_addr.TransportAddr = undefined;
    for (&published, 0..) |*slot, index| slot.* = .{ .ip = ip(@intCast(4000 + index)) };
    const filed = join.observePeer(&peerRecord(&published));

    try t.expectEqual(@as(usize, 40), filed.candidates.added);
    try t.expectEqual(@as(usize, 0), filed.candidates.refused);
    // Same order, same survivors: what failed went first and nothing that had
    // been tried was taken for it.
    try t.expectEqual(@as(usize, 5), filed.candidates.pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 0), filed.candidates.pruned.inactive_dropped);
    try t.expectEqual(@as(usize, 10), working(&join, 3000, 10));
    try t.expectEqual(@as(usize, 40), carries(&join, 4000, 40));
    try t.expectEqual(@as(usize, 0), carries(&join, 3100, 5));
    try t.expectEqual(@as(usize, 1), relayPaths(&join));
    try t.expectEqual(@as(usize, 51), join.path_count);
    try t.expectEqual(join.path_count, filed.candidates.pruned.kept);

    // The two ceilings are separate, and this record is over the advertised
    // one: the set holds what the stack will accept, the rest is counted, and
    // the round is refused before the gate is asked. Three local candidates —
    // one seen by a relay, two by the socket — and all forty of these.
    try t.expectEqual(@as(usize, holepunch.max_qnt_addresses), join.remote.len);
    try t.expectEqual(@as(usize, 8), join.remote.overflow);
    try t.expect(std.meta.eql(
        Action{ .tooManyAddresses = 3 + holepunch.max_qnt_addresses + 8 },
        join.ready(start),
    ));
}

test "the peer's published record is the producer for its candidates" {
    var scratch: [64]u8 = undefined;
    var join: Join = .{};
    join.selectConnection(client_conns);

    // Everything a record may carry, and only one of it a way to punch at: a
    // relay is the fallback path, a custom transport is not an IP socket.
    var published = [_]transport_addr.TransportAddr{
        .{ .relay = try namedRelay(scratch[0..32], 0) },
        .{ .custom = .{ .id = 3, .data = &.{} } },
        .{ .ip = ip(7000) },
        .{ .ip = ip(7001) },
    };
    const filed = join.observePeer(&peerRecord(&published));

    try t.expectEqual(@as(usize, 2), join.remote.len);
    try t.expectEqual(@as(usize, 0), join.remote.overflow);
    try t.expect(std.meta.eql(ip(7000), join.remote.slice()[0]));
    try t.expect(std.meta.eql(ip(7001), join.remote.slice()[1]));
    // The two that are not candidates are counted rather than dropped: a peer
    // that published nothing but a fallback is not the same fact as a peer
    // that published nothing, and both leave an empty set.
    try t.expectEqual(@as(usize, 2), filed.not_candidates);

    // Every advertised candidate is also a path the caller has been told
    // about, `unknown` until something is sent over it — the whole of what
    // this layer cannot say about one of them on its own.
    try t.expectEqual(@as(usize, 2), join.path_count);
    try t.expectEqual(@as(usize, 2), filed.candidates.added);
    try t.expectEqual(join.path_count, filed.candidates.pruned.kept);
    for (join.table()) |path| try t.expect(path.status == .unknown);

    // A later record replaces the one before it: the address the peer
    // withdrew stops being punched at, and the one it kept is a path the table
    // already carries, so it is filed once and not twice.
    var withdrawn = [_]transport_addr.TransportAddr{.{ .ip = ip(7001) }};
    const second = join.observePeer(&peerRecord(&withdrawn));
    try t.expectEqual(@as(usize, 1), join.remote.len);
    try t.expectEqual(@as(usize, 0), second.candidates.added);
    try t.expectEqual(@as(usize, 2), join.path_count);
    try t.expect(std.meta.eql(ip(7001), join.remote.slice()[0]));

    // And a record carrying nothing but a fallback still punches, for the same
    // reason an empty report does: the set is handed over as it is and
    // `not_enough_addresses` is the stack's answer, not this file's.
    var fallback = [_]transport_addr.TransportAddr{
        .{ .relay = try namedRelay(scratch[32..64], 1) },
    };
    const empty = join.observePeer(&peerRecord(&fallback));
    try t.expectEqual(@as(usize, 0), join.remote.len);
    try t.expectEqual(@as(usize, 1), empty.not_candidates);
    try t.expectEqual(@as(usize, 0), empty.candidates.added);
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(start)));
}

test "a path the table already carries is updated, not duplicated" {
    var join: Join = .{};
    _ = join.observe(.{ .addr = .{ .ip = ip(7000) }, .status = .unknown });
    _ = join.observe(.{ .addr = .{ .ip = ip(7000) }, .status = .unusable });
    // One entry, and the status the caller last reported: a path table is a
    // map keyed by address, and two entries for one address would make the
    // prune count one path twice.
    try t.expectEqual(@as(usize, 1), join.path_count);
    try t.expect(join.table()[0].status == .unusable);
}

test "a republished candidate keeps the status its path already carries" {
    var join: Join = .{};
    var published = [_]transport_addr.TransportAddr{ .{ .ip = ip(7000) }, .{ .ip = ip(7001) } };
    const first = join.observePeer(&peerRecord(&published));
    try t.expectEqual(@as(usize, 2), first.candidates.added);

    // What only the caller's own traffic can say: one path is open and
    // carrying, the other was punched once and closed at a known instant. A
    // record names addresses and nothing about what happened over them.
    try t.expect(join.observe(.{ .addr = .{ .ip = ip(7000) }, .status = .open }).stored);
    try t.expect(join.observe(.{
        .addr = .{ .ip = ip(7001) },
        .status = .{ .inactive = start },
    }).stored);

    // The peer re-announces the same two addresses, which is an ordinary
    // thing for a peer to do and arrives through the same producer.
    const again = join.observePeer(&peerRecord(&published));

    // The record is not a second copy of the table: nothing was added, nothing
    // was refused, and the table is the same two paths it was.
    try t.expectEqual(@as(usize, 0), again.candidates.added);
    try t.expectEqual(@as(usize, 0), again.candidates.refused);
    try t.expectEqual(@as(usize, 2), join.path_count);
    try t.expectEqual(join.path_count, again.candidates.pruned.kept);

    // What each path is known to be survives the republish, the close instant
    // included. A status the record cannot carry must not be answered for by
    // the producer that filed the address: `table` is what a caller reads to
    // see what survived, and a path that was open reads back as never tried.
    try t.expect(join.table()[0].status == .open);
    switch (join.table()[1].status) {
        .inactive => |closed| try t.expectEqual(start, closed),
        else => return error.PathIsNotClosed,
    }
    // The prune's rule reads that status — a closed path is one to keep and
    // `unknown` is one nobody has tried — and a caller reads it out of `table`
    // for the same reason.
    try t.expectEqual(@as(usize, 1), working(&join, 7000, 2));

    // And `observe` is still the seam that changes a status, and the only one:
    // a republish that leaves a status alone does not make it unreachable.
    try t.expect(join.observe(.{ .addr = .{ .ip = ip(7000) }, .status = .unusable }).stored);
    try t.expect(join.table()[0].status == .unusable);
    try t.expectEqual(@as(usize, 2), join.path_count);
}

test "a peer's record is refused what a full path table cannot hold" {
    var join: Join = .{};
    // A client connection, so that the refusal below is one the gate would
    // otherwise have punched at this very instant.
    join.selectConnection(client_conns);

    // One path short of what the table holds: one that was punched and
    // worked, and the rest nobody has tried. None of them is a candidate for
    // eviction, so the prune leaves the table where the caller left it.
    try t.expect(join.observe(.{
        .addr = .{ .ip = ip(7000) },
        .status = .{ .inactive = start },
    }).stored);
    for (0..max_paths - 2) |index| {
        const port: u16 = @intCast(7001 + index);
        try t.expect(join.observe(.{ .addr = .{ .ip = ip(port) }, .status = .unknown }).stored);
    }
    try t.expectEqual(@as(usize, max_paths - 1), join.path_count);

    // The peer's own record: the address the table already carries, and one
    // address more than the stack will advertise to a peer, none of them seen
    // before.
    var published: [holepunch.max_qnt_addresses + 1]transport_addr.TransportAddr = undefined;
    published[0] = .{ .ip = ip(7000) };
    for (published[1..], 0..) |*slot, index| slot.* = .{ .ip = ip(@intCast(8000 + index)) };
    const filed = join.observePeer(&peerRecord(&published));

    // One slot was left, so exactly one of the thirty-two fits. The rest are
    // counted as refused rather than dropped in silence or written over a
    // path the table already holds.
    try t.expectEqual(@as(usize, 1), filed.candidates.added);
    try t.expectEqual(@as(usize, 31), filed.candidates.refused);
    try t.expectEqual(@as(usize, max_paths), join.path_count);
    try t.expectEqual(join.path_count, filed.candidates.pruned.kept);
    // The prune ran at the ceiling and dropped nothing, which is what the
    // storage ceiling is sized against: a path nobody has tried is not a path
    // that does not work, so a full table of them is a full table.
    try t.expectEqual(@as(usize, 0), filed.candidates.pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 0), filed.candidates.pruned.inactive_dropped);

    // Every path the table already held is still one of its paths, and the
    // one that fitted is the first address nobody had tried. The thirty-one
    // that did not fit are in the tally and nowhere else.
    try t.expectEqual(@as(usize, max_paths - 1), carries(&join, 7000, max_paths - 1));
    try t.expectEqual(@as(usize, 1), carries(&join, 8000, 1));
    try t.expectEqual(@as(usize, 0), carries(&join, 8001, 31));
    // And the republished address keeps what the caller's own traffic said
    // about it, close instant included: a record names addresses and says
    // nothing about what happened over them, and the prune's rule reads that
    // status back.
    try t.expectEqual(@as(usize, 1), working(&join, 7000, 1));
    try t.expect(std.meta.eql(ip(7000), join.table()[0].addr.ip));
    switch (join.table()[0].status) {
        .inactive => |closed| try t.expectEqual(start, closed),
        else => return error.PathIsNotClosed,
    }

    // Both ends of the connection share one advertised ceiling and this
    // record is over it, so the round is refused here rather than asked and
    // refused by the stack.
    try t.expectEqual(@as(usize, holepunch.max_qnt_addresses), join.remote.len);
    try t.expectEqual(@as(usize, 1), join.remote.overflow);
    try t.expect(std.meta.eql(
        Action{ .tooManyAddresses = 1 + holepunch.max_qnt_addresses },
        join.ready(start),
    ));
}

test "a settled Join copied afterwards answers from its own recorded set" {
    // `Join` is a value and every set in it is its own storage, so a copy has
    // to answer as itself. That fails the moment anything reachable from a copy
    // still points into the `Join` it was copied from — and the gate used to
    // keep exactly such a pointer, to the recorded candidate set it compares
    // against. The copy then read the original's bytes with nothing to tell
    // the two apart, so a copy asking "have my candidates moved?" was answered
    // about the original's, and the candidate-change trigger that decides when
    // a round runs stopped being per-peer.
    var join: Join = .{};
    joinWith(&join, &.{ ip(1000), ip(1001) });
    const discovered = [_]SocketAddr{ ip(2000), ip(2001) };
    // The peer's own candidates, so the gate's "has anything appeared?" question
    // has both halves answered: a peer that advertised nothing now, having
    // advertised two, is a change worth punching, and this test is about the
    // copy, not about that rule.
    var published = [_]transport_addr.TransportAddr{ .{ .ip = ip(2000) }, .{ .ip = ip(2001) } };
    _ = join.observePeer(&peerRecord(&published));
    // Settling records the round; it owes no instruction, and the gate is what
    // decides the next one.
    try t.expect(join.settle(start, .{ .accepted = &discovered }) == .hold);

    // Each copy writes its own storage: mutating one copy's recorded set
    // leaves the original's bytes alone. The probe is its own copy so the one
    // the rest of this test asks questions of still carries the real record.
    const recorded = join.previous.items[0];
    var diverged = join;
    diverged.previous.items[0].port = 4242;
    diverged.local.items[0].port = 4243;
    try t.expectEqual(recorded, join.previous.items[0]);
    try t.expectEqual(@as(u16, 1000), join.local.items[0].port);

    var copied = join;
    try t.expectEqual(@as(usize, 2), copied.previous.len);

    // The one slice a settled `Join` still borrows is the candidate list the
    // stack returned, and it is the caller's: `punch.last.remote` names
    // `discovered` and neither `Join`.
    const last = copied.punch.last orelse return error.TestUnexpectedResult;
    try t.expect(last.remote.ptr == discovered[0..].ptr);

    // A millisecond after the round: inside the interval, so the answer is a
    // wakeup unless something new appeared.
    const later = start + millis(1);
    try t.expect(std.meta.eql(
        Action{ .wakeAt = start + holepunch.punch_interval },
        copied.ready(later),
    ));

    // The original moves on: a candidate its own recorded set does not carry.
    joinWith(&join, &.{ ip(1000), ip(1001), ip(9000) });
    try t.expect(std.meta.eql(Action{ .punch = 4 }, join.ready(later)));
    // The copy has seen none of that, and compares against its *own* recorded
    // set, so it is still waiting the interval out. A copy still pointing into
    // the original's recorded set would have punched here as well.
    try t.expect(std.meta.eql(
        Action{ .wakeAt = start + holepunch.punch_interval },
        copied.ready(later),
    ));

    // And the copy does punch on a change of its own, so the trigger is not
    // merely quiet: one address its recorded set does not carry, on either
    // family of the advertised set.
    joinWith(&copied, &.{ ip(1000), ip(1001), ip(9001) });
    try t.expect(std.meta.eql(Action{ .punch = 4 }, copied.ready(later)));
}

/// Give `join` exactly `socket` as its local candidates, and a client
/// connection for the gate to punch on.
///
/// A folded report with no public address, so `observeReport` files `socket`
/// and nothing else: a test that wants the local set to be the addresses it
/// wrote does not want a probe's address mixed in.
fn joinWith(join: *Join, socket: []const SocketAddr) void {
    const folded: report.Report = .{};
    join.observeReport(&folded, socket);
    join.selectConnection(client_conns);
}

/// The one instruction the gate produced, or the failure that it produced none.
fn onlyAction(step: holepunch.Step) !holepunch.Action {
    return step.action orelse error.NoAction;
}

/// What the gate alone would say for this `Join` at this instant.
///
/// A test uses it to show that `ready` passed the gate through rather than
/// deciding anything of its own, which means asking the gate the same
/// question with the same three sets — including the recorded one, since that
/// is the set the comparison is against.
fn gateSays(join: *const Join, now: Nanos) !holepunch.Action {
    return onlyAction(holepunch.decide(join.punch, now, .{
        .local = join.local.slice(),
        .remote = join.remote.slice(),
        .previous_local = join.previous.slice(),
    }));
}
