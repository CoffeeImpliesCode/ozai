//! Holepunching: the gate around one call into the QUIC stack.
//!
//! Holepunching is not a protocol. It is `initiate_nat_traversal_round` on a
//! QUIC connection, and relay and direct are two paths on that one connection.
//! What ozai owns is everything around that call: when to make it, what to do
//! with the answer, and which paths to forget.
//!
//! All three are pure over state, so all three are here, and all three are
//! testable before the QUIC stack exists. Nothing below reads a clock — the
//! elapsed time arrives as `now` — and the call leaves as an `Action` value
//! that names it rather than as a call. `docs/DECISIONS/0001` is why the call
//! leaves at all: the substrate is a fork of someone else's QUIC and is not in
//! this tree yet.
//!
//! Every function here takes plain slices and returns plain values, which is
//! what makes them fuzzable: `decide`, `settle`, `classify` and `prune`
//! allocate nothing and reach nothing a test cannot hand them, so a
//! `std.testing.fuzz` target can drive them from bytes against fixed oracles —
//! every prune keeps every `open` path, keeps the
//! `max_inactive_non_relay_paths` most recently closed `inactive` paths, and
//! drops no relay. No target is registered yet; those are its oracles.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `HOLEPUNCH_ATTEMPTS_INTERVAL`, `trigger_holepunching`, `do_holepunching`
//!   and `HolepunchAttempt` from `iroh/src/socket/remote_map/remote_state.rs`.
//! - `MAX_QNT_ADDRESSES` from `iroh/src/socket.rs:145`.
//! - `MAX_NON_RELAY_PATHS`, `MAX_INACTIVE_NON_RELAY_PATHS`, `PathStatus`,
//!   `PathState` and `prune_non_relay_paths` from
//!   `iroh/src/socket/remote_map/remote_state/path_state.rs`.
//!
//! The error arms are `noq_proto::n0_nat_traversal::Error`, fetched from
//! n0-computer/noq at commit 89ed00c31297c2127d1697a7b63983d60fd02ecb,
//! `noq-proto/src/n0_nat_traversal.rs:114`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const report = @import("report.zig");
const transport_addr = @import("../base/transport_addr.zig");

const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// `net/report.zig` already defines it for the fold from probe results, and two
/// definitions of "an instant" in one layer would only invite a conversion
/// nobody wants.
pub const Nanos = report.Nanos;

/// How long to wait before repeating a round that changed nothing.
///
/// Upstream's `HOLEPUNCH_ATTEMPTS_INTERVAL`. Punching on every wakeup floods
/// the relay and never converges, so this is the floor on how often a round
/// runs while the candidate sets have not moved.
pub const punch_interval: Nanos = 5 * std.time.ns_per_s;

/// How long to wait before repeating a round the stack refused.
///
/// Upstream writes the 100 ms inline in `do_holepunching`, for the two errors
/// that mean "not yet" rather than "never".
pub const retry_interval: Nanos = 100 * std.time.ns_per_ms;

/// How many non-relay paths one peer may carry before anything is pruned.
///
/// Upstream's `MAX_NON_RELAY_PATHS`, a `usize`. It is the point at which
/// pruning starts, not a bound on the table: paths that are open, and paths
/// nobody has tried, are never dropped however many there are. A relay path is
/// neither counted nor dropped — it is the fallback, and a ceiling that can
/// evict the fallback is not a ceiling.
pub const max_non_relay_paths: usize = 30;

/// How many previously-successful paths may survive a prune.
///
/// Upstream's `MAX_INACTIVE_NON_RELAY_PATHS`, read as the cap its own doc
/// comment gives it rather than as its code reads it:
/// `split_off(inactive.len() - MAX)` prunes the oldest `MAX` and leaves the
/// newest `len - MAX`, so the survivors number `len - MAX` and not `MAX`. At
/// twenty inactive paths the two readings agree and at fifteen they differ by
/// five, which is the difference between a cap that bounds the working set and
/// one that spends it. These are the paths that have demonstrably worked, and
/// capping them is also what the plan asks for. See the divergence note in
/// `docs/ARCHITECTURE.md`.
pub const max_inactive_non_relay_paths: usize = 10;

/// How many addresses one connection may advertise to its peer.
///
/// Upstream's `MAX_QNT_ADDRESSES`, a `u8` there and chosen for machines with
/// many interfaces — a MacOS host carrying more than 25 VPN and docker
/// interfaces is the reason written beside it. Overrunning it is
/// `too_many_addresses`, and that error is fatal, so the ceiling is a
/// correctness bound rather than a tuning one. `docs/DECISIONS/0001` calls it
/// the tuning knob that matters after the multipath substrate lands, because
/// convergence is then carried by how fast the path table churns.
pub const max_qnt_addresses: usize = 32;

/// Whether `count` addresses fit under `max_qnt_addresses`.
///
/// Asked before the set is handed to the stack, because the answer past the
/// ceiling is a fatal error and not a slow one.
pub fn mayAdvertise(count: usize) bool {
    return count <= max_qnt_addresses;
}

/// The `stable_id` the QUIC stack gives a connection.
///
/// Upstream's `ConnId(usize)`. It is unique among live connections, which is
/// what makes "the lowest one" a well-defined choice rather than an arbitrary
/// one.
pub const ConnId = usize;

/// Which end of the handshake a connection is. Upstream reads noq's `Side`; the
/// only thing holepunching needs of it is that the dialling side starts a
/// round and the accepting side does not.
pub const Side = enum { client, server };

/// One connection to the peer, as far as the punch gate is concerned.
pub const Connection = struct {
    id: ConnId,
    side: Side,
};

/// The connection a round runs on: the client connection with the lowest id.
///
/// Upstream takes `min_by_key` over the client connections on every trigger,
/// so both endpoints may initiate a round when both hold a client connection,
/// and a path that opens is opened on the others without a round of its own.
/// Null when every connection is server-side, which upstream reports as "no
/// client connection" and does not punch.
pub fn selectPunchConnection(conns: []const Connection) ?ConnId {
    var best: ?ConnId = null;
    for (conns) |conn| {
        if (conn.side != .client) continue;
        if (best == null or conn.id < best.?) best = conn.id;
    }
    return best;
}

/// Whether `current` names an address `previous` does not.
///
/// Upstream's `!current.is_subset(previous)` over two `BTreeSet`s. Addresses may
/// disappear and that is not news; one appearing is. Sets and not sequences, so
/// the answer does not depend on the order the two were collected in, which is
/// what lets a caller hand over whatever it happens to hold. A scan rather than
/// a tree: neither set is longer than `max_qnt_addresses`, and building a tree
/// would mean an allocator this layer does not have.
pub fn hasNewAddress(current: []const SocketAddr, previous: []const SocketAddr) bool {
    for (current) |candidate| {
        if (!containsAddr(previous, candidate)) return true;
    }
    return false;
}

fn containsAddr(set: []const SocketAddr, needle: SocketAddr) bool {
    for (set) |member| {
        if (member.order(needle) == .eq) return true;
    }
    return false;
}

/// One round the stack accepted: when it started, and what the stack found.
///
/// Upstream's `HolepunchAttempt`, minus its `local` field. Upstream can keep
/// that field as a borrowed slice because its state lives in an `Arc` behind
/// the machine that started the round; here `PunchState` is a plain value that
/// callers copy — `Step.next` is one, `Join` is one — and a field that borrows
/// storage *inside the value being copied* is silently wrong the moment it is:
/// the copy reads the original's bytes and nobody can tell. The local set a
/// round started with is therefore an argument to `decide` rather than a field
/// of the state, and it is read exactly once, on the turn that compares it.
///
/// What is left borrows from the caller and nothing else: `remote` names the
/// candidates the stack returned, which arrive in `Outcome.accepted` and stay
/// the caller's to keep alive. Copying a state copies that pointer, and both
/// copies name the same caller buffer, which is what makes the copy safe. A
/// state holding a slice into itself would not have that property.
pub const Attempt = struct {
    /// When the accepted round started, on the caller's timeline.
    when: Nanos,
    /// The candidates the stack reported for it. Borrowed from whoever decoded
    /// them, as `Outcome.accepted` is: keep that storage alive for as long as
    /// this state names it.
    remote: []const SocketAddr,
};

/// One remote's NAT-traversal state. A plain value with no borrow of its own
/// storage: copying it copies values and caller-owned pointers, never a
/// pointer into itself, so a copy reads what the original reads and the two
/// cannot drift apart. The one slice it carries, `last.remote`, belongs to the
/// caller and both copies name the same buffer.
pub const PunchState = struct {
    /// The connection a round runs on, or null while the gate holds for want of
    /// one. See `selectPunchConnection`.
    punch: ?ConnId = null,
    /// The last round the stack accepted, or null when none has been.
    ///
    /// Upstream writes this only on `Ok`, and that is load-bearing rather than
    /// incidental: a round that failed moved no candidate, so the next wakeup
    /// has to see the same candidates as new and try again rather than sit out
    /// the interval.
    ///
    /// This holds *when* that round started and what the stack found, not what
    /// it was started with: the local set it started with is the caller's, and
    /// `decide` takes it as `Candidates.previous_local`. See `Attempt` for why
    /// it is not a field here.
    last: ?Attempt = null,
    /// The path the connection is currently selected onto.
    ///
    /// Carried because the invariant it protects is about a pair of states, not
    /// about one: a connection selected onto a relay must still punch. Nothing
    /// in this file reads it, and that is the point — the test named for the
    /// invariant is its only reader, so a branch that starts consulting it has
    /// to change the answer that test pins.
    selected: ?TransportAddr = null,
    /// The error that ended punching, if one did.
    ///
    /// Upstream only logs the four fatal variants and schedules nothing, and
    /// the "for now" is implemented by the actor having no wakeup left — a fact
    /// about the actor's loop rather than about the peer. Carrying it keeps the
    /// machine honest: a state handed back with it set does not punch.
    stopped: ?NatTraversalError = null,
};

/// One instruction for whoever drives the QUIC stack.
///
/// The call is the transport's and lands with the substrate in
/// `docs/DECISIONS/0001`. Naming it as a value is what lets the gate be tested
/// without one: a test compares the instruction, not a socket.
pub const Action = union(enum) {
    /// Call `initiate_nat_traversal_round` on this connection, now.
    initiateNatTraversalRound: ConnId,
    /// Run the gate again at this instant.
    wakeAt: Nanos,
    /// Punch no more on this connection.
    stopPunching,
};

/// What one turn of the machine produced.
///
/// At most one instruction: a turn does at most one thing, and so does
/// upstream's — a round, a wakeup, a stop, or silence. Held by value rather than
/// as a slice into an array built in the frame that returned this, because that
/// slice outlives the array and the whole of invariant 6 is that it must not.
pub const Step = struct {
    next: PunchState,
    action: ?Action = null,
};

/// The three candidate sets one turn of the gate reads.
///
/// Three slices of the same type, so they travel together: named positions in a
/// parameter list are three ways to transpose the same address and the gate
/// would answer about one peer while the caller asked about another. All three
/// are borrowed from the caller for the length of the `decide` call and none
/// of them is retained: `decide` returns a `PunchState` and an `Action`, and
/// neither names any of them. What the state keeps from a round is in
/// `Attempt`, and that keeps only what the caller already owns.
pub const Candidates = struct {
    /// What this node may be punched at, as it stands now.
    local: []const SocketAddr,
    /// What the peer may be punched at, as it stands now.
    remote: []const SocketAddr,
    /// What this node was punched at when the last accepted round started — the
    /// caller's own copy of that set, kept wherever the caller keeps it. Empty
    /// when there is no accepted round on record. Read only when
    /// `PunchState.last` is not null; then an empty set affects the comparison.
    ///
    /// **Not `Attempt.local`.** A round's starting set is compared exactly once,
    /// on the turn after it, and a state that held it would have to borrow it
    /// from somewhere: from the state that owns it, which is a copy that reads
    /// the wrong bytes. See `Attempt`.
    previous_local: []const SocketAddr,
};

/// The gate. One wakeup in, one decision out.
///
/// `now` is the current instant on the caller's own timeline. Upstream reads
/// `Instant::now()` at three points inside this function; passing it in is what
/// makes "too soon" and "due" two answers a test can tell apart.
///
/// Pure, and it stays that way: nothing it is handed is stored anywhere it
/// returns. `next` is `state` itself on every arm, so the answer is the state
/// the caller already had plus at most one instruction.
pub fn decide(
    state: PunchState,
    now: Nanos,
    candidates: Candidates,
) Step {
    if (state.stopped != null) return .{ .next = state };
    const conn = state.punch orelse return .{ .next = state };
    const last = state.last;
    // A candidate that appeared beats the interval, and an expired interval
    // beats having nothing new. Both halves matter: drop the first and every
    // address event becomes a round, which floods the relay; drop the second
    // and a peer whose NAT mapping simply aged out is never tried again.
    if (last) |previous| {
        const appeared = hasNewAddress(candidates.local, candidates.previous_local) or
            hasNewAddress(candidates.remote, previous.remote);
        if (!appeared) {
            // Saturating, so a timeline within five seconds of its ceiling waits
            // rather than wrapping into a round that is always due.
            const due = previous.when +| punch_interval;
            if (due > now) return .{ .next = state, .action = .{ .wakeAt = due } };
        }
    }
    return .{ .next = state, .action = .{ .initiateNatTraversalRound = conn } };
}

/// What the stack said about a round.
pub const Outcome = union(enum) {
    /// `Ok`, and the remote candidates it found. These are what the next wakeup
    /// compares against, so they are the ones the caller must keep alive.
    accepted: []const SocketAddr,
    /// `Err`, classified by `classify`.
    refused: NatTraversalError,
};

/// Fold a round's answer back into the state. Pure, like `decide`.
///
/// Takes no candidate set, because there is nothing left of one to keep: the
/// accepted arm records when the round started and what the stack found, and
/// the caller already holds the set it started the round with — it is the same
/// `Candidates.local` it will hand to the next `decide` as
/// `previous_local`. Recording a slice of it here instead would be the one
/// thing in this file that survives a copy of the state pointing at bytes that
/// are no longer the state being read.
pub fn settle(
    state: PunchState,
    now: Nanos,
    outcome: Outcome,
) Step {
    return switch (outcome) {
        .accepted => |remote| .{ .next = .{
            .punch = state.punch,
            .last = .{ .when = now, .remote = remote },
            .selected = state.selected,
            .stopped = state.stopped,
        } },
        .refused => |err| switch (classify(err)) {
            .retry => .{
                .next = state,
                .action = .{ .wakeAt = now +| retry_interval },
            },
            .fatal => .{
                .next = .{
                    .punch = state.punch,
                    .last = state.last,
                    .selected = state.selected,
                    .stopped = err,
                },
                .action = .stopPunching,
            },
        },
    };
}

/// Why a round could not start. Upstream's `noq_proto::n0_nat_traversal::Error`,
/// one arm per variant.
///
/// `Multipath` carries a `PathError` upstream and does not here: every failure
/// inside it classifies the same way, so the payload would be a second thing to
/// keep correct for a decision that never changes.
pub const NatTraversalError = enum {
    /// The advertised set is full. Fatal, and see `max_qnt_addresses`.
    too_many_addresses,
    /// The round is not allowed from this end of the connection.
    wrong_connection_side,
    /// The peer never negotiated the extension, so a round cannot mean anything.
    extension_not_negotiated,
    /// Not enough addresses on one side or the other yet.
    not_enough_addresses,
    /// The multipath layer refused to open the paths the round asked for.
    multipath,
    /// The connection is closed or closing.
    closed,
};

comptime {
    // Upstream matches on this enum exhaustively, so a variant added there is a
    // compile error there. The switch in `classify` is exhaustive for the same
    // reason; this says so out loud and pins the count the arms above were
    // copied from, so a variant added without a classification fails the build
    // rather than inheriting a default arm nobody chose.
    if (@typeInfo(NatTraversalError).@"enum".fields.len != 6) {
        @compileError("a NatTraversalError variant has no classification");
    }
}

/// What to do about a refused round.
pub const Verdict = union(enum) {
    /// Ask again after this long. Only for the errors that mean the stack is not
    /// ready yet rather than that it never will be.
    retry: Nanos,
    /// Stop punching on this connection.
    fatal,
};

/// What a refused round means.
///
/// A function from the error to the decision, not an if-chain: each arm is a
/// policy call about whether this peer can still be reached directly, and there
/// is no "everything else" — the enum is closed, and closing it is the point.
pub fn classify(err: NatTraversalError) Verdict {
    return switch (err) {
        // Neither refuses the idea, only the moment: the multipath layer was
        // busy, or there were not enough addresses on one side to try with.
        .multipath, .not_enough_addresses => .{ .retry = retry_interval },
        // One end is full, one is the wrong end, one never spoke the extension,
        // one is gone. None of them becomes untrue while the connection is up.
        .closed, .too_many_addresses, .wrong_connection_side, .extension_not_negotiated => .fatal,
    };
}

/// How usable a path to the peer is. Upstream's `PathStatus`.
///
/// `inactive` carries the instant the path was abandoned, because the prune
/// keeps the most recently closed of them and cannot do that from a bare tag.
pub const PathStatus = union(enum) {
    /// Open and carrying traffic.
    open,
    /// Opened once and closed at this instant: punched, and it worked.
    inactive: Nanos,
    /// Punched, and it did not work.
    unusable,
    /// Never punched, or a punch is in flight. Nothing is known about it, which
    /// is not the same as it having failed.
    unknown,
};

/// One path to the peer and everything known about it.
///
/// `addr` is the destination, borrowed in the `custom` arm, so the caller keeps
/// that storage alive for as long as the path is in the table.
pub const Path = struct {
    addr: TransportAddr,
    status: PathStatus,
};

/// What one prune dropped. `paths[0..kept]` are the survivors; the tail is left
/// untouched, so the caller can keep appending to the same storage.
pub const Pruned = struct {
    kept: usize,
    unusable_dropped: usize,
    inactive_dropped: usize,
};

/// Enforce the per-peer path ceiling, in place.
///
/// Upstream's `prune_non_relay_paths`, and the order is the whole point:
///
/// 1. `unusable` goes first and always. A path that was punched and failed is
///    the only kind that has been shown not to work.
/// 2. Of the rest, at most `max_inactive_non_relay_paths` survive, and they are
///    the ones closed most recently, because those are the ones that worked.
/// 3. `open` and `unknown` are never candidates for eviction. A path nobody has
///    tried is not a path that does not work, so a burst of address-lookup
///    results cannot displace anything that has been tried and has held.
///
/// Relay paths are outside all three, for the reason `max_non_relay_paths`
/// gives.
pub fn prune(paths: []Path) Pruned {
    var result: Pruned = .{
        .kept = paths.len,
        .unusable_dropped = 0,
        .inactive_dropped = 0,
    };
    var non_relay: usize = 0;
    var unusable: usize = 0;
    var top: TopInactive = .{};
    for (paths, 0..) |path, index| {
        if (isRelay(path.addr)) continue;
        non_relay += 1;
        switch (path.status) {
            .unusable => unusable += 1,
            .inactive => |closed| top.offer(closed, index),
            .open, .unknown => {},
        }
    }
    // Upstream tests the total count and then the non-relay count; the first
    // test is implied by the second, so only the second is here.
    if (non_relay < max_non_relay_paths) return result;

    // Every path is one that failed. Upstream's guard against pruning a peer's
    // whole table, except that it compares the unusable count against the total,
    // which counts the relay path — so it never fires on exactly the peers that
    // always have one. Compared against the non-relay count it fires as its
    // comment says it should. Which of the survivors is kept is upstream's
    // `HashMap` iteration order and therefore arbitrary; the caller's order is a
    // rule, so this pins one and the test names it.
    const keep_unusable = if (non_relay == unusable) max_non_relay_paths else 0;

    // Compact in place. The write cursor trails the read cursor, so nothing a
    // later iteration reads has been overwritten.
    var seen: usize = 0;
    var out: usize = 0;
    for (paths, 0..) |path, index| {
        const why: ?Why = if (isRelay(path.addr))
            null
        else switch (path.status) {
            .unusable => blk: {
                seen += 1;
                break :blk if (seen > keep_unusable) .unusable else null;
            },
            .inactive => |closed| if (!top.keeps(closed, index)) .inactive else null,
            .open, .unknown => null,
        };
        if (why) |reason| {
            switch (reason) {
                .unusable => result.unusable_dropped += 1,
                .inactive => result.inactive_dropped += 1,
            }
            continue;
        }
        paths[out] = path;
        out += 1;
    }
    result.kept = out;
    return result;
}

/// Why one path was dropped. Private because it is a tally, not a decision.
const Why = enum { unusable, inactive };

fn isRelay(value: TransportAddr) bool {
    return std.meta.activeTag(value) == .relay;
}

/// The `max_inactive_non_relay_paths` most recently closed inactive paths.
///
/// A fixed-size top-k rather than a sort, because a sort needs storage the
/// caller would have to hand over and the bound is a constant. Keyed on the
/// closing instant and the index together, so two paths abandoned at the same
/// nanosecond still order — upstream sorts by the instant alone over a
/// `FxHashMap`, which leaves the tie to an iteration order that is not stable
/// between runs.
const TopInactive = struct {
    const Entry = struct { closed: Nanos, index: usize };

    items: [max_inactive_non_relay_paths]Entry = undefined,
    len: usize = 0,

    fn offer(self: *TopInactive, closed: Nanos, index: usize) void {
        if (self.len == self.items.len and
            laterThan(closed, index, self.items[0].closed, self.items[0].index) != .gt)
        {
            return;
        }
        var at = self.len;
        if (at == self.items.len) at -= 1;
        // The walk stops at the first entry under the cursor that the
        // candidate does not beat, and at zero there is no entry under the
        // cursor at all — which is why the bound is stated on the cursor
        // itself rather than on the slot it reads. Naming the entry also
        // costs one read per step instead of three.
        while (at > 0) {
            const below = self.items[at - 1];
            if (laterThan(closed, index, below.closed, below.index) != .gt) break;
            self.items[at] = below;
            at -= 1;
        }
        self.items[at] = .{ .closed = closed, .index = index };
        if (self.len < self.items.len) self.len += 1;
    }

    fn keeps(self: *const TopInactive, closed: Nanos, index: usize) bool {
        for (self.items[0..self.len]) |entry| {
            if (entry.closed == closed and entry.index == index) return true;
        }
        return false;
    }
};

/// Orders two inactive paths: most recently closed first, later index first on
/// a tie, so the order is total over indices that are themselves unique.
fn laterThan(closed_a: Nanos, index_a: usize, closed_b: Nanos, index_b: usize) std.math.Order {
    return switch (std.math.order(closed_a, closed_b)) {
        .eq => std.math.order(index_a, index_b),
        else => |ordering| ordering,
    };
}

const t = std.testing;

/// A direct address on port `port`, all from one documentation range so a test
/// that prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// Fill `paths` with direct paths on consecutive ports, starting at `first`.
fn fillIp(paths: []Path, first: u16, status: PathStatus) void {
    for (paths, 0..) |*path, index| {
        path.* = .{
            .addr = .{ .ip = ip(first + @as(u16, @intCast(index))) },
            .status = status,
        };
    }
}

/// Whether `paths` still carries a direct path on `port`.
fn carries(paths: []const Path, port: u16) bool {
    for (paths) |path| {
        switch (path.addr) {
            .ip => |socket| if (socket.port == port) return true,
            else => {},
        }
    }
    return false;
}

/// How many of `paths` are relay paths.
fn countRelays(paths: []const Path) usize {
    var count: usize = 0;
    for (paths) |path| {
        if (isRelay(path.addr)) count += 1;
    }
    return count;
}

/// Whether two address lists name the same addresses in the same order.
/// `SocketAddr` is a struct, so `expectEqualSlices` cannot compare one.
fn expectSameAddrs(expected: []const SocketAddr, actual: []const SocketAddr) !void {
    if (expected.len != actual.len) return error.DifferentAddresses;
    for (expected, actual) |left, right| {
        if (left.order(right) != .eq) return error.DifferentAddresses;
    }
}

/// The one instruction a step produced.
fn onlyAction(step: Step) !Action {
    return step.action orelse error.NoAction;
}

/// What a refused round classified to, as the two things a caller can ask.
fn expectVerdict(err: NatTraversalError, want: Verdict) !void {
    switch (want) {
        .retry => |after| switch (classify(err)) {
            .retry => |delay| try t.expectEqual(after, delay),
            .fatal => return error.NotRetried,
        },
        .fatal => switch (classify(err)) {
            .fatal => {},
            .retry => return error.NotFatal,
        },
    }
}

test "the punch connection is the lowest client connection" {
    const conns: []const Connection = &.{
        .{ .id = 7, .side = .server },
        .{ .id = 9, .side = .client },
        .{ .id = 4, .side = .server },
        .{ .id = 2, .side = .client },
    };
    try t.expectEqual(@as(?ConnId, 2), selectPunchConnection(conns));
    // Only server-side connections, which is what an inbound-only endpoint
    // holds, and what upstream declines to punch on.
    const inbound: []const Connection = &.{
        .{ .id = 7, .side = .server },
        .{ .id = 4, .side = .server },
    };
    try t.expectEqual(@as(?ConnId, null), selectPunchConnection(inbound));
    try t.expectEqual(@as(?ConnId, null), selectPunchConnection(&.{}));
}

test "a peer with no client connection is not punched" {
    const state: PunchState = .{};
    const step = decide(state, 0, .{
        .local = &.{ip(1)},
        .remote = &.{ip(2)},
        .previous_local = &.{},
    });
    try t.expect(step.action == null);
}

test "the first round runs whatever else is true" {
    // No attempt on record, so there is no interval and no comparison set.
    const state: PunchState = .{ .punch = 3 };
    const step = decide(state, 0, .{ .local = &.{}, .remote = &.{}, .previous_local = &.{} });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "a new address before the interval is still a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &.{} },
    };
    // A millisecond after the last round, with a remote candidate that was not
    // there then. The interval has not elapsed and the round happens anyway.
    const step = decide(state, 1_000 + std.time.ns_per_ms, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "a new local address before the interval is still a punch" {
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + std.time.ns_per_ms, .{
        .local = &.{ip(1000)},
        .remote = &remote,
        .previous_local = &.{},
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "an expired interval with nothing new is still a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + punch_interval, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "neither a new address nor an expired interval is not a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + punch_interval - 1, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    const wanted: Action = .{ .wakeAt = 1_000 + punch_interval };
    try t.expect(std.meta.eql(wanted, try onlyAction(step)));
}

test "an address disappearing is not news" {
    const before = [_]SocketAddr{ ip(1000), ip(1001), ip(1002) };
    const after = [_]SocketAddr{ip(1002)};
    try t.expect(!hasNewAddress(&after, &before));
    try t.expect(!hasNewAddress(&before, &before));
    try t.expect(hasNewAddress(&.{ ip(1002), ip(1003) }, &before));
}

test "every retryable error asks again in 100 ms" {
    const state: PunchState = .{ .punch = 3 };
    for ([_]NatTraversalError{ .multipath, .not_enough_addresses }) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(
            Action{ .wakeAt = 50_000 + retry_interval },
            try onlyAction(step),
        ));

        try t.expect(step.next.stopped == null);
    }
}

test "every fatal error stops punching" {
    const state: PunchState = .{ .punch = 3 };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    for (fatal) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(Action.stopPunching, try onlyAction(step)));
        try t.expectEqual(err, step.next.stopped.?);
        // A stopped state does not punch again, whatever the wakeup says.
        const again = decide(step.next, 50_000 + punch_interval, .{
            .local = &.{},
            .remote = &.{ip(1)},
            .previous_local = &.{},
        });
        try t.expect(again.action == null);
    }
}

test "every error variant is classified, and none is left over" {
    // The `comptime` guard above is the half the compiler checks: a variant
    // without a classification fails the build. This is the half it cannot —
    // that each of the six the guard names lands where upstream puts it.
    const retryable = [_]NatTraversalError{ .multipath, .not_enough_addresses };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    try t.expectEqual(
        @typeInfo(NatTraversalError).@"enum".fields.len,
        retryable.len + fatal.len,
    );
    for (retryable) |err| try expectVerdict(err, .{ .retry = retry_interval });
    for (fatal) |err| try expectVerdict(err, .fatal);
}

test "an accepted round records when it ran and what the stack found" {
    const discovered = [_]SocketAddr{ ip(2000), ip(2001) };
    const state: PunchState = .{ .punch = 3, .selected = .{ .ip = ip(1000) } };
    const step = settle(state, 7_000, .{ .accepted = &discovered });
    // Upstream schedules nothing on `Ok`: the next trigger is an address
    // change, the scheduled wakeup it may already hold, or the periodic
    // connection check.
    try t.expect(step.action == null);
    const last = step.next.last orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(Nanos, 7_000), last.when);
    try expectSameAddrs(&discovered, last.remote);
    // The set the round *started* with is not recorded here: it is the caller's,
    // and the caller hands it back as `Candidates.previous_local`. A state that
    // kept a slice of it would be borrowing the storage its own owner holds,
    // and a copy of the state would read the original's bytes.
    try t.expectEqual(@as(?ConnId, 3), step.next.punch);
}

test "a refused round does not move the interval" {
    // The state has no record of the failed round, so the same candidates read
    // as new on the next wakeup and the round happens again rather than sitting
    // out five seconds. This is what makes the 100 ms retry reachable at all.
    const local = [_]SocketAddr{ip(1000)};
    const state: PunchState = .{ .punch = 3 };
    const step = settle(state, 1_000, .{ .refused = .not_enough_addresses });
    try t.expect(step.next.last == null);
    const again = decide(step.next, 1_000 + retry_interval, .{
        .local = &local,
        .remote = &local,
        .previous_local = &.{},
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(again)));
}

test "a selected relay path does not suppress a punch" {
    const relay_url = try base_relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./");
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const last: Attempt = .{ .when = 1_000, .remote = &.{} };
    // A millisecond after the last round: inside the interval, with a remote
    // candidate that was not there then.
    const now = 1_000 + std.time.ns_per_ms;
    const wanted: Action = .{ .initiateNatTraversalRound = 3 };

    const candidates: Candidates = .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    };
    const on_relay = decide(
        .{ .punch = 3, .last = last, .selected = .{ .relay = relay_url } },
        now,
        candidates,
    );
    const on_direct = decide(
        .{ .punch = 3, .last = last, .selected = .{ .ip = ip(1000) } },
        now,
        candidates,
    );
    try t.expect(std.meta.eql(wanted, try onlyAction(on_relay)));
    try t.expect(std.meta.eql(try onlyAction(on_direct), try onlyAction(on_relay)));

    // And on the interval, with nothing new either way: the two states differ
    // only in what the connection is currently sending on, and both wait for
    // the same instant. Selecting a relay is not a reason to stop trying to
    // leave it.
    const held: Attempt = .{ .when = 1_000, .remote = &remote };
    const waited: Action = .{ .wakeAt = 1_000 + punch_interval };
    const held_candidates: Candidates = .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    };
    const relay_wait = decide(
        .{ .punch = 3, .last = held, .selected = .{ .relay = relay_url } },
        now,
        held_candidates,
    );
    const direct_wait = decide(
        .{ .punch = 3, .last = held, .selected = .{ .ip = ip(1000) } },
        now,
        held_candidates,
    );
    try t.expect(std.meta.eql(waited, try onlyAction(relay_wait)));
    try t.expect(std.meta.eql(try onlyAction(direct_wait), try onlyAction(relay_wait)));
}

test "the advertised-address ceiling is a hard one" {
    try t.expect(mayAdvertise(max_qnt_addresses));
    try t.expect(!mayAdvertise(max_qnt_addresses + 1));
    // Past the ceiling the stack answers `too_many_addresses`, which is fatal,
    // so an over-full lookup result ends the punch loop instead of slowing it.
    try expectVerdict(.too_many_addresses, .fatal);
}

test "nothing is pruned below the ceiling" {
    var paths: [max_non_relay_paths - 1]Path = undefined;
    fillIp(&paths, 1_000, .unknown);
    for (0..5) |index| paths[index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[10 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, paths.len), result.kept);
    try t.expectEqual(@as(usize, 0), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
}

test "unusable paths are pruned before inactive ones" {
    var paths: [35]Path = undefined;
    fillIp(&paths, 1_000, .open);
    for (0..15) |index| paths[15 + index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[30 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    // The ten most recently closed of the fifteen: ports 1_020..1_029.
    try t.expectEqual(@as(usize, 5), result.inactive_dropped);
    try t.expectEqual(@as(usize, 25), result.kept);
    const alive = paths[0..result.kept];
    for (0..15) |index| try t.expect(carries(alive, 1_000 + @as(u16, @intCast(index))));
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_030 + @as(u16, @intCast(index))));
    }
    for (5..15) |index| {
        try t.expect(carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
}

test "at most ten previously-successful paths survive" {
    var paths: [50]Path = undefined;
    fillIp(&paths, 2_000, .unknown);
    for (0..20) |index| paths[index].status = .{ .inactive = @intCast(index) };

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.inactive_dropped);
    // The twenty most recently closed are ports 2_010..2_019.
    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(!carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    for (10..20) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    // The thirty untried paths are not candidates for eviction at all.
    for (20..50) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
}

test "a burst of untested results does not evict the paths that work" {
    // The ten working paths sit at the cap and were closed first; the burst
    // arrives afterwards, forty addresses long, and every one of them is
    // untried. An eviction ordered by freshness rather than by what is known
    // drops all ten working paths and keeps thirty never-tried ones.
    var paths: [55]Path = undefined;
    for (0..10) |index| {
        paths[index] = .{
            .addr = .{ .ip = ip(3_000 + @as(u16, @intCast(index))) },
            .status = .{ .inactive = @intCast(index) },
        };
    }
    fillIp(paths[10..15], 3_100, .unusable);
    fillIp(paths[15..], 4_000, .unknown);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
    try t.expectEqual(@as(usize, 50), result.kept);

    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(carries(alive, 3_000 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 3_100 + @as(u16, @intCast(index))));
    }
    for (0..40) |index| {
        try t.expect(carries(alive, 4_000 + @as(u16, @intCast(index))));
    }
}

test "a table that is entirely unusable keeps the ceiling worth keeping" {
    var paths: [40]Path = undefined;
    fillIp(&paths, 5_000, .unusable);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.unusable_dropped);
    try t.expectEqual(@as(usize, max_non_relay_paths), result.kept);
    // Upstream's guard does not fire once a relay path is present, and drops
    // every path instead of any; this keeps the paths the caller listed first.
    const alive = paths[0..result.kept];
    try t.expect(carries(alive, 5_000));
    try t.expect(!carries(alive, 5_030));
}

test "relay paths are neither counted nor pruned" {
    const relay_url = try base_relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./");

    // Thirty-five direct paths against four relay ones, so the non-relay count
    // is over the ceiling on its own and the prune has something to do.
    var over: [39]Path = undefined;
    fillIp(&over, 6_000, .open);
    for (0..5) |index| over[30 + index].status = .unusable;
    for (0..4) |index| {
        over[35 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const pruned = prune(&over);
    try t.expectEqual(@as(usize, 5), pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 34), pruned.kept);
    try t.expectEqual(@as(usize, 4), countRelays(over[0..pruned.kept]));

    // The same relays beside twenty-five direct paths: under the ceiling, and
    // nothing is dropped however many of the paths are unusable.
    var under: [29]Path = undefined;
    fillIp(&under, 7_000, .unusable);
    for (0..4) |index| {
        under[25 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const held = prune(&under);
    try t.expectEqual(@as(usize, 29), held.kept);
    try t.expectEqual(@as(usize, 0), held.unusable_dropped);
}
