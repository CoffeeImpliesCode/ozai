//! The gate machine: the state a round is decided against, and `decide`, the
//! one function that reads it.
//!
//! `holepunch_refusal.zig` answers what a round's answer means and
//! `holepunch_path.zig` what a changed path table keeps; `holepunch.zig`
//! re-exports all three as the layer's one surface.
//!
//! The mutual import between this module and the refusal one is the reason
//! the machine is one module rather than two. `PunchState.stopped` carries the
//! error that ended punching and `settle` is what writes it, so the state
//! needs the module that declares the error and that module's `settle` needs
//! the state. Splitting them any finer would only hide a cycle rather than
//! remove one.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const refusal = @import("holepunch_refusal.zig");
const report = @import("report.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Nanos = report.Nanos;
const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;

/// How long to wait before repeating a round that changed nothing.
///
/// Upstream's `HOLEPUNCH_ATTEMPTS_INTERVAL`. Punching on every wakeup floods
/// the relay and never converges, so this is the floor on how often a round
/// runs while the candidate sets have not moved.
pub const punch_interval: Nanos = 5 * std.time.ns_per_s;

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
/// callers copy — `Step.next` is one, `holepunch_run.Join` is one — and a field
/// that borrows storage *inside the value being copied* is silently wrong the
/// moment it is: the copy reads the original's bytes and nobody can tell. The
/// local set a round started with is therefore an argument to `decide` rather
/// than a field of the state, and it is read exactly once, on the turn that
/// compares it.
///
/// What is left borrows from the caller and nothing else: `remote` names the
/// candidates the stack returned, which arrive in
/// `holepunch_refusal.Outcome.accepted` and stay the caller's to keep alive.
/// Copying a state copies that pointer, and both copies name the same caller
/// buffer, which is what makes the copy safe. A state holding a slice into
/// itself would not have that property.
pub const Attempt = struct {
    /// When the accepted round started, on the caller's timeline.
    when: Nanos,
    /// The candidates the stack reported for it. Borrowed from whoever decoded
    /// them, as `holepunch_refusal.Outcome.accepted` is: keep that storage
    /// alive for as long as this state names it.
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
    stopped: ?refusal.NatTraversalError = null,
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

const t = std.testing;

/// A direct address on port `port`, all from one documentation range so a test
/// that prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// The one instruction a step produced.
fn onlyAction(step: Step) !Action {
    return step.action orelse error.NoAction;
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
    // Past the ceiling the stack answers `too_many_addresses`, and
    // `holepunch_refusal.zig` puts that on the fatal side rather than the retry
    // side, so an over-full lookup result ends the punch loop instead of
    // slowing it. "every error variant is classified" there is where that
    // classification is pinned.
}