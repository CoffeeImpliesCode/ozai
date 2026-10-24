//! The gate around one call into the QUIC stack.
//!
//! `holepunch.zig` is the facade for this module; this half holds the punch
//! gate itself: which connection a round runs on, whether it is due, what a
//! refusal means, and the state that carries both between turns. Nothing here
//! reads a clock — the elapsed time arrives as `now` — and the call into the
//! stack leaves as an `Action` value that names it rather than as a call.
//!
//! The module doc `holepunch.zig` carries is the argument for the whole file
//! and is not repeated here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");

const SocketAddr = addr.SocketAddr;
const TransportAddr = addr.TransportAddr;

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

/// How many addresses one connection may advertise to its peer.
///
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
    if (@typeInfo(NatTraversalError).@"enum".field_names.len != 6) {
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
