//! Running the gate on what a probe round measured: the join between
//! `net/report.zig` and `net/holepunch.zig`.
//!
//! Three modules sit around a hole in the tree. `probe_run.zig` runs a round
//! and files every answer into a `probe.Results`. `probe.zig` folds those
//! into a `report.Report`. `holepunch.zig` decides whether to ask the QUIC
//! stack for a NAT-traversal round, from a candidate set, an instant and a
//! connection. Nothing joins them: every `report.Report` in this project was
//! written by a test, and so is every `holepunch.PunchState`. This file is
//! the producer's other half. It turns a folded report into the gate's
//! inputs, hands the gate's answer back, and restates none of the three
//! modules above it.
//!
//! # What a probe round can supply, and what it cannot
//!
//! A probe round measures **this node**, from the inside, over QUIC. The gate
//! asks about **one connection**, from the outside. The overlap is real, it is
//! small, and it is this section in full — a reader without it reads a gap as
//! a rule, and then wonders why the gap is never closed.
//!
//! ```text
//! gate input                          | from a probe round
//! -------------------------------------|----------------------------------
//! local: where this node is reachable | yes: `global_v4`, `global_v6`
//! the mapping verdict                  | yes: `mappingVariesByDest`
//! remote: where the peer is reachable | no: the peer's own report
//! the connection to punch on           | no: the connection table
//! what the stack said about a round    | no: `initiate_nat_traversal_round`
//! whether a path carried traffic       | no: the multipath layer
//! the socket's interface addresses     | no: the socket
//! ```
//!
//! Every "no" is where a caller is, and each is a thing a probe physically
//! cannot do rather than one this file declines to do:
//!
//! - **The peer's addresses** are the peer's own report, published through
//!   discovery, or what its path table has already seen. A probe answers a
//!   relay's question about *us*; nothing in a round sees across the wire.
//! - **The connection** is `holepunch.selectPunchConnection` over a table the
//!   transport owns, and it is the one input the gate needs on every round.
//! - **The stack's answer** is `initiate_nat_traversal_round`, the call
//!   `docs/DECISIONS/0001` sends away and this milestone never makes. Its
//!   refusal is classified by `holepunch.classify`, which is where a retry
//!   delay and a fatal error are decided, not here.
//! - **A path's status** is what the multipath layer saw on it. A probe
//!   learns an address and never learns whether anything was sent over it, so
//!   every candidate this file records arrives `unknown`, and only the caller
//!   can say otherwise.
//!
//! The socket's interface addresses are the other half of the local set: a
//! relay reports the address this node came *from* and cannot report the
//! addresses on the interfaces underneath, so they arrive as an argument.
//!
//! # The mapping
//!
//! `global_v4` and `global_v6` are the addresses a relay saw this node come
//! from, and they are the only form of "where am I reachable" a round can
//! produce. The local set is those, then the caller's interface addresses.
//! Order is not a rule — `holepunch.hasNewAddress` compares sets, and
//! `holepunch.decide` cannot tell which of the two sources a candidate came
//! from.
//!
//! The verdict is carried and consulted by nothing here, and that is not an
//! omission. `holepunch.decide` takes no verdict, and a rule that consulted
//! one would be invented: a destination-dependent mapping makes hole punching
//! *harder* and does not make it pointless, because the round itself opens
//! the mapping it needs. The verdict is here for the caller deciding whether
//! this node may be published as directly reachable, and only two probes to
//! *different* relays can produce it.
//!
//! # Two buffers, because the gate compares against the last round
//!
//! `holepunch.PunchState.last` borrows the candidates the last round was
//! started with, and `holepunch.decide` compares this round's set against
//! them. One buffer would be rewritten under that comparison, and a slice
//! into storage the caller owns would make the caller's bookkeeping part of
//! the gate's invariant. So the live set and the recorded set are two
//! buffers: `settle` copies the live one into the recorded one and hands the
//! gate *that* slice, and only an accepted round does so, because it is the
//! only outcome that records a set at all. The copy is a few hundred bytes
//! once a round, and it is what makes "a borrowed slice outlives its turn" a
//! property of this type rather than of its caller's care.
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
//! - **What the burst did.** `absorb` files candidates and prunes as it
//!   goes, and hands back what the prune dropped, so the plan's rule — a
//!   burst of untested address-lookup results must not evict the paths that
//!   work — is observable from the caller's side of the seam rather than
//!   only from `holepunch.prune`'s own tests.
//!
//! Freshness is deliberately absent from that list. `report.ProbeResult`
//! carries the instant it was observed and `report.fold` ages it against
//! `report.max_report_age` for the preferred-relay window, but nothing here
//! ages the candidate set: a caller holding an old report is a caller that
//! has already decided that report is worth handing over.
//!
//! # No clock, no thread, no socket, no allocator
//!
//! Every instant is an argument — `ready(now)` and `settle(now, outcome)` —
//! and a test drives the whole chain on one, from a probe round that opened
//! no socket to a punch decision nobody acted on. `Join` is a value: it holds
//! no pointer to the transport, no task and no allocator, and it can be
//! copied and moved without invalidating anything, because the only slice it
//! keeps is the peer's candidate list, which is the caller's to begin with.
//!
//! Upstream at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the pin `net/holepunch.zig`
//! carries — for the two things this file joins: `Report` with its
//! `mapping_varies_by_dest`, from `iroh/src/net_report/`, and `PathState`
//! with its `prune_non_relay_paths`, from
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const report = @import("report.zig");

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
    items: [holepunch.max_qnt_addresses]SocketAddr = undefined,
    len: usize = 0,
    /// Candidates that did not fit. Never silently absorbed, because the
    /// ceiling is a correctness bound and not a tuning one.
    overflow: usize = 0,

    /// The candidates, for the gate and for a reader.
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
    /// Candidates the table had no room for. See `Set.overflow`'s rule.
    refused: usize,
    /// What the whole burst cost the table.
    pruned: holepunch.Pruned,
};

/// One peer's NAT traversal as this file keeps it.
///
/// The gate's state is held whole rather than restated: every rule about when
/// to punch, how long to wait and which error is fatal belongs to
/// `holepunch.zig`, and a copy of one of those rules here would be a second
/// opinion about it. What this value adds is the storage the gate borrows, the
/// verdict the report carries, and the three questions neither of the two
/// modules above is asked.
pub const Join = struct {
    /// The gate's own state.
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

    /// This node's candidates, as the gate compares them. This file's storage,
    /// for the lifetime reason in the module doc: rewritten by every report
    /// and never by `settle`.
    local: Set = .{},

    /// The set `punch.last.local` names, and which the gate compares `local`
    /// against. Written by `settle` and by nothing else, so a round's
    /// candidates survive every later report until the next round records
    /// its own.
    previous: Set = .{},

    /// The peer's candidates. The caller's, and the one slice this value
    /// keeps — see the module doc on what a probe round cannot supply. It has
    /// to outlive the state, because `holepunch.PunchState.last` borrows it
    /// for exactly as long as the gate compares against it.
    remote: []const SocketAddr = &.{},

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
    pub fn selectConnection(self: *Join, conns: []const holepunch.Connection) void {
        self.punch.punch = holepunch.selectPunchConnection(conns);
    }

    /// Record what a folded probe round says this node can be reached at.
    ///
    /// `folded` is borrowed rather than taken by value: a `report.Report` is
    /// four kilobytes of inline latency table, and this reads two addresses
    /// and a classification out of it.
    ///
    /// `socket` is the caller's interface addresses, which is the half of the
    /// local set no round can measure. An empty slice is a host that has
    /// published none, not a host with none: the gate is handed what was
    /// known and answers about it, and the stack's `not_enough_addresses` is
    /// the answer to a set it cannot use.
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
        const advertised = self.local.len + self.local.overflow + self.remote.len;
        if (!holepunch.mayAdvertise(advertised)) return .{ .tooManyAddresses = advertised };
        // The gate's turn reads its state and leaves it as it was, so only its
        // instruction is wanted here.
        const step = holepunch.decide(self.punch, now, self.local.slice(), self.remote);
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
    /// What is left is the candidate set, and it is copied rather than
    /// swapped: the record the gate keeps names `previous`, and `previous` is
    /// written here and nowhere else. A buffer that is swapped into keeps its
    /// address while its contents move, which leaves the gate's borrowed
    /// slice naming the wrong set the moment the swap is done.
    pub fn settle(self: *Join, now: Nanos, outcome: holepunch.Outcome) Action {
        // A refusal records nothing, so on that arm the copy does not happen
        // and the record the last accepted round made stays where it is.
        const record: []const SocketAddr = switch (outcome) {
            .accepted => record: {
                self.previous = self.local;
                break :record self.previous.slice();
            },
            .refused => self.local.slice(),
        };
        const step = holepunch.settle(self.punch, now, record, outcome);
        self.punch = step.next;
        return instruction(step.action);
    }

    /// Record one path and enforce the ceiling over the table.
    ///
    /// An address the table already carries has its status replaced and gets
    /// no second entry: a path table is a map keyed by address, and two
    /// entries for one address would make the prune count one path twice.
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

    /// File a burst of candidates, and hand back what the burst cost.
    ///
    /// One `observe` per candidate rather than one at the end, because the
    /// prune runs on every change: the rule is that an unusable path goes
    /// first and always, and a single prune at the end of a burst would leave
    /// a burst's unusable paths sitting in the table for the whole of it.
    ///
    /// Every candidate arrives `unknown`, which is the status the gap in the
    /// module doc's table leaves it with.
    pub fn absorb(self: *Join, candidates: []const SocketAddr) Absorbed {
        var result: Absorbed = .{
            .added = 0,
            .refused = 0,
            .pruned = .{ .kept = 0, .unusable_dropped = 0, .inactive_dropped = 0 },
        };
        for (candidates) |candidate| {
            const filed = self.observe(.{ .addr = .{ .ip = candidate }, .status = .unknown });
            if (filed.stored) result.added += 1 else result.refused += 1;
            result.pruned.unusable_dropped += filed.pruned.unusable_dropped;
            result.pruned.inactive_dropped += filed.pruned.inactive_dropped;
        }
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
fn namedRelay(scratch: []u8, index: usize) !addr.RelayUrl {
    return addr.RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}

fn relaySet(scratch: []u8) ![3]addr.RelayUrl {
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

    fn ready(self: *const Wire, open: probe_run.Open, now: Nanos) bool {
        if (now -| open.at < self.think[open.task.relay]) return false;
        if (open.task.proto == .https) return true;
        return self.reported[open.task.relay] != null;
    }

    fn observation(self: *const Wire, open: probe_run.Open) probe_run.Observation {
        return switch (open.task.proto) {
            .https => .{ .https = self.think[open.task.relay] },
            .qad_ipv4, .qad_ipv6 => .{ .qad = .{
                .latency = self.think[open.task.relay],
                .reported = self.reported[open.task.relay].?,
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
        if (self.answered[index] or !self.ready(open, now)) continue;
        self.answered[index] = true;
        return .{ .task = open.task, .value = self.observation(open) };
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
    relays: []const addr.RelayUrl,
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
        (try onlyAction(holepunch.decide(join.punch, start, join.local.slice(), &.{}))),
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
    var seen: [2]SocketAddr = .{ peer[0], ip(7001) };
    join.remote = &seen;
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
        (try onlyAction(holepunch.decide(join.punch, start, join.local.slice(), &.{}))),
    ));
    try t.expect(std.meta.eql(
        Action{ .tooManyAddresses = holepunch.max_qnt_addresses + 1 },
        join.ready(start),
    ));
    // The peer's addresses count towards the same ceiling, because it is one
    // connection's advertised set.
    const peer: [1]SocketAddr = .{ip(7000)};
    join.remote = &peer;
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

/// The one instruction the gate produced, or the failure that it produced none.
fn onlyAction(step: holepunch.Step) !holepunch.Action {
    return step.action orelse error.NoAction;
}
