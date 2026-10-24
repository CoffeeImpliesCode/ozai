//! What a change to this node's own interfaces means for the paths it holds.
//!
//! `interface.zig` reads this machine twice and reports how much of the
//! reachable set moved. It stops there on purpose: "one address retired" is a
//! fact about this host's `getifaddrs` output, and the paths this node holds
//! are pairs of addresses, half of them somebody else's. This file is the join
//! between the two — given a change and a path, what is true of the path now —
//! and it is the last half of what `net/holepunch_run.zig`'s module doc lists
//! as the "socket's interface addresses" gap.
//!
//! Pure: no socket, no clock, no allocator, no global. The two reads and the
//! policy they were compared under are the whole input, and every answer is a
//! value. Nothing here writes an `Entry` or a `PathStatus`; `path_table.zig`
//! owns every figure and `path_select.zig` owns every choice.
//!
//! # A path whose local address is gone is demoted, never removed
//!
//! Three answers were available for a path reached at an address this node no
//! longer holds — remove it, mark it, leave it alone — and only the middle one
//! survives.
//!
//! **Remove** is the answer that loses every connection on a routine DHCP
//! renewal, and the two reads cannot tell that renewal from the Wi-Fi going
//! down. `interface.zig` chose snapshot comparison over a netlink subscription
//! and recorded the price: a change is seen at the next read, on the caller's
//! own interval. A lease renews on a timer this node does not own, so whether
//! the renewal falls inside one interval is luck — inside it `Change.moved()`
//! says nothing moved and no caller is troubled; outside it, the same renewal is
//! indistinguishable from an interface that went down and did not come back.
//! The evidence is byte-for-byte the same in both cases, so an irreversible
//! decision taken on it is taken on a coin. And the cost of losing that coin is
//! not one path: a node with one interface address reached *every* direct path
//! it holds at that address, so the wrong read empties every direct path to
//! every peer at once, and a re-learn takes a probe round per peer to undo.
//!
//! **Leave it alone** leaves the record lying. An entry filed against an
//! address the kernel no longer has claims a mapping nothing can reproduce, and
//! every later decision that ranks on it ranks on that mapping. Silence is not
//! the safe side here; it is the side that keeps a false claim in the table
//! until something else happens to overwrite it.
//!
//! **Mark** is the answer, and it is here rather than in the status vocabulary
//! for two reasons that are the tree's own. `PathStatus.inactive` carries the
//! instant a path was abandoned, and a clock is the one thing this module must
//! not read — so writing it would have to come from the caller and this module
//! would be the place a caller reads a status instead of an answer.
//! `.unusable` is worse: it is a recorded *failure*, a punch that was tried and
//! did not work, and `Entry.dialable` refuses exactly it. An address that left
//! is not a failure of a path, and calling it one would refuse a path that may
//! well work over the address that replaced it. `path_revalidate.Verdict` is
//! the precedent for exactly this shape — a module that reports rather than
//! writes, and says so in its own doc.
//!
//! So nothing is removed and no status is invented. What comes out is a
//! `Verdict`, and the one act this module names is the irreversible one it
//! declines: the path's record is unsound, the path is not proven dead, and the
//! entry stays.
//!
//! # A change here says nothing about a peer's addresses
//!
//! Two facts, two sources, and no relationship between them. "This node's
//! interfaces changed" is read out of `struct ifaddrs`. "The peer's addresses
//! changed" is read out of an `OBSERVED_ADDRESS` frame, a relay's report, or the
//! record a peer published — `net/qad.zig`, `net/report.zig`,
//! `net/holepunch_run.zig`'s `observePeer`. Nothing in this machine's
//! interface list mentions a host on another network, and where the two facts
//! are true at the same moment they are still two facts with two sources.
//!
//! Conflating them is what tears down working connections: a node's own Wi-Fi
//! blinks, the paths it holds to eight peers all describe a mapping that is
//! gone, and the peer addresses — which almost always did not move — go with
//! them. The guarantee here is structural rather than a promise in prose. A
//! path in this directory is a *pairing*, and the only half any function below
//! reads is the local one. There is no parameter anywhere in this file that
//! could carry a peer-side change, and `Held.remote` is carried solely so the
//! caller can look the entry up with it — `path_table.Table.find` takes a
//! `TransportAddr`. A relay path and a custom-transport path fall out of the
//! same rule for free: they were never reached at one of this machine's
//! addresses, so no interface change is about them at all.
//!
//! # The synthetic address is not an interface address
//!
//! `interface.Reach` carries a third set beside the two families: `any_path`,
//! the address a peer reaches this node at before it has chosen a path. Its
//! host bits are allocated by the transport seam — `base/ula.zig`'s module doc
//! says so — and no read of this machine's interfaces can retire them. Nothing
//! below reads that field, and the test that pins the two inert arguments to
//! `reachableAt` pins this too.
//!
//! # What is not claimed
//!

const std = @import("std");

const addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");
const interface = @import("interface.zig");

const IpAddress = addr.IpAddress;
const TransportAddr = addr.TransportAddr;
const HostBits = ula.HostBits;

// `interface.zig` owns all three. Bound here rather than re-declared so that
// `Change` and `Snapshot` cannot stop being the types this module was written
// against. `SnapshotError` is bound for the same reason: `Snapshot.add` refuses
// past `max_entries` and a test fixture built here has to be able to say so.
const Change = interface.Change;
const Snapshot = interface.Snapshot;
const SnapshotError = interface.SnapshotError;
const Reach = interface.Reach;

/// This node's own binding: the identity the transport seam allocated and the
/// port the socket bound.
///
/// `interface.reachableAt` asks for both, so a caller that has no binding cannot
/// be answered at all — but neither of them reaches a verdict. The host bits
/// build the synthetic address and the port is paired onto every interface
/// address, and this module compares addresses as `IpAddress` and reads no
/// synthetic address, so both are inert here. That is stated because a
/// parameter which provably cannot change the answer is otherwise a reader's
/// puzzle, and it is pinned by behaviour rather than by assertion.
pub const Binding = struct {
    /// The eight host bits `base/ula.zig`'s map allocated for this node.
    host: HostBits,
    /// The port the socket bound. An interface address has no port of its own —
    /// `reachableAt` takes it — and the port does not move with the address.
    port: u16,
};

/// One path as this node holds it: the peer's address, and the address on this
/// machine the path was reached at on the way to it.
///
/// The pairing, not either half, and nothing in this directory records it. The
/// per-peer tables — `net/path_table.zig`'s `Entry`, and the candidate sets in
/// `net/holepunch_run.zig` — keep each half in its own flat list compared as a
/// set, because `holepunch.decide` asks "is there a new address" and never
/// "which path was reached where". So the caller assembles this and hands it
/// over; this module cannot invent the join, and saying that is better than
/// answering about a local address it picked itself.
pub const Held = struct {
    /// The peer's address. Carried so the caller can find the entry this
    /// verdict is about — `path_table.Table.find` takes a `TransportAddr` — and
    /// read by nothing here, which is the module's whole claim about peers.
    remote: TransportAddr,
    /// The address on this machine the path was reached at, or null for a path
    /// reached at none: a relay, a custom transport, or one nothing has paired
    /// yet. Null is not a wildcard — a path with no local address has no local
    /// address for a change to take away.
    local: ?IpAddress,
};

/// What one path's local address being gone means, or that it is not.
pub const Verdict = enum {
    /// This path is not reached at an address of this machine's — it is a relay
    /// or a custom transport, it was never paired, or it names an address no
    /// read has produced. No change to this node's interfaces is about it, and
    /// the entry stays exactly where it is.
    unbound,
    /// The address this path was reached at is in the later read. The record is
    /// still true and nothing needs deciding.
    ///
    /// A fact about `current` alone: a path paired after the change reads the
    /// same as one paired before it, because what matters is whether the
    /// machine holds the address now, not whether it held it then.
    held,
    /// The address retired and this node still holds at least one address it
    /// held before. This pairing is wrong; the node is not. The caller
    /// withdraws this path from what it advertises, and the address that
    /// replaced it is republished under the same paths.
    ///
    /// This is the DHCP-renewal answer, and it is deliberately a demotion
    /// rather than a removal — see the module doc.
    rebound,
    /// The address retired and this node now holds none of the addresses it
    /// held before. Every direct path it was reached at is wrong for the same
    /// reason, and the node has lost its own direct reachability rather than
    /// one pairing of it.
    stranded,
};

/// How many arms `Verdict` has.
///
/// Read from the enum rather than written down, so `Tally` grows with the type
/// and a new answer cannot be added to a counter that has no room for it.
pub const verdict_count = @typeInfo(Verdict).@"enum".field_names.len;

/// How many of a set of paths each verdict covers.
///
/// Counts and not paths, the shape `interface.Move` already has: a caller that
/// wants a per-path answer calls `verdict`, and a caller that wants to know what
/// a change costs across a whole table needs the size of the bill rather than
/// the list of names. Nothing here bounds or refuses, so a caller with more
/// paths than it expects gets a true count of all of them.
pub const Tally = struct {
    /// One slot per `Verdict` arm, in enum order.
    counts: [verdict_count]usize = @splat(0),

    /// How many paths came to `answer`.
    pub fn get(self: *const Tally, answer: Verdict) usize {
        return self.counts[@backingInt(answer)];
    }

    fn record(self: *Tally, answer: Verdict) void {
        self.counts[@backingInt(answer)] += 1;
    }
};

/// What one path's local address being gone means, given a change.
///
/// Builds the reachable set of each read once and decides once. By pointer for
/// `held`, because `TransportAddr` holds a `RelayUrl` inline and
/// `path_table.Entry` is passed by pointer for the same reason.
pub fn verdict(change: *const Change, held: *const Held, binding: Binding) Verdict {
    const before = reachable(change, &change.previous, binding);
    const after = reachable(change, &change.current, binding);
    return classify(&before, &after, held.local);
}

/// What one change did to a whole set of paths.
///
/// The same decision as `verdict`, with the two reachable sets built once
/// instead of once per path: `interface.Reach` is a value with two
/// `max_entries` arrays behind it, and a per-peer table is walked on every
/// change this node notices, which is often enough that rebuilding it per path
/// would be the larger half of the work.
pub fn tally(change: *const Change, paths: []const Held, binding: Binding) Tally {
    const before = reachable(change, &change.previous, binding);
    const after = reachable(change, &change.current, binding);
    var counted: Tally = .{};
    for (paths) |held| counted.record(classify(&before, &after, held.local));
    return counted;
}

/// The decision, over reachability that has already been built.
///
/// The one place a verdict is made. `verdict` and `tally` differ only in how
/// many times they build the two sets, so a rule here cannot hold for one entry
/// point and quietly not for the other.
fn classify(before: *const Reach, after: *const Reach, local: ?IpAddress) Verdict {
    const ip = local orelse return .unbound;
    if (carries(after, ip)) return .held;
    // Not held now. Whether this machine ever reported it is the next question
    // and not a formality: a path paired with an address no read has produced is
    // a record this change did not spoil, and calling it `.stranded` would
    // report this node losing an address it never had.
    if (!carries(before, ip)) return .unbound;
    if (overlaps(before, after)) return .rebound;
    return .stranded;
}

/// The reachable set of one read, under the policy the change was stored with.
///
/// `change.loopback` rather than an argument of its own, which is what makes
/// "the peer is on this host" or "it is not" the caller's stored policy rather
/// than a choice this file could make differently from the one it compares
/// under — the mistake `interface.Change` exists to make impossible.
fn reachable(change: *const Change, read: *const Snapshot, binding: Binding) Reach {
    return interface.reachableAt(read, binding.host, binding.port, change.loopback);
}

/// Whether `reach` carries `ip`, in either family.
///
/// `Reach.any_path` is not read, and that is the point rather than an oversight:
/// its host bits are the transport seam's allocation and a read of this
/// machine's interfaces cannot retire them.
fn carries(reach: *const Reach, ip: IpAddress) bool {
    for (reach.v4Addrs()) |socket| {
        if (std.meta.eql(socket.ip, ip)) return true;
    }
    for (reach.v6Addrs()) |socket| {
        if (std.meta.eql(socket.ip, ip)) return true;
    }
    return false;
}

/// Whether the two reachable sets share an address.
///
/// An intersection, which `interface.Move` cannot answer however it is spelled:
/// `retired` counts the addresses the later read lost and says nothing about how
/// many of the earlier ones survived, and that count is the whole question a
/// caller has before deciding whether a retired address costs it one pairing or
/// every direct path it holds.
fn overlaps(before: *const Reach, after: *const Reach) bool {
    for (before.v4Addrs()) |socket| {
        if (carries(after, socket.ip)) return true;
    }
    for (before.v6Addrs()) |socket| {
        if (carries(after, socket.ip)) return true;
    }
    return false;
}

// --- tests

const t = std.testing;

/// `eth0` as the kernel spells it. One interface in every snapshot written
/// below: nothing here reads `Entry.interface`, so the name is decoration and
/// the kernel's per-row names are not the subject.
const eth0: interface.Name = .{
    .bytes = .{ 'e', 't', 'h', '0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .len = 4,
};
/// `lo`, for the one test that needs an interface the loopback policy turns on
/// and off.
const lo: interface.Name = .{
    .bytes = .{ 'l', 'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .len = 2,
};

/// A host value that is not all zero and a port nothing special, so a test
/// cannot be satisfied by an argument that happens to be the default.
const test_binding: Binding = .{
    .host = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
    .port = 41234,
};

/// The documentation range, so an address a failing test prints is never
/// mistaken for a routable host. The last octet is the argument.
fn v4(last: u8) IpAddress {
    return .{ .v4 = .{ 192, 0, 2, last } };
}

/// `fd00::1`, written out rather than built. `fd15:70a:510b::` is the subnet
/// `base/ula.zig` allocates inside, so an address under `fd00` is never the
/// synthetic one a test asks a reachable set about.
fn v6() IpAddress {
    return .{ .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
}

/// An address on `eth0`, up and not loopback.
fn on(ip: IpAddress) interface.Entry {
    return .{ .interface = eth0, .ip = ip, .up = true, .loopback = false };
}

/// A `Snapshot` carrying `entries` in the order they are written, and nothing
/// else.
///
/// Whole or nothing, and the refusal is propagated rather than discarded: the
/// ceiling belongs to `Snapshot.add`, which this file does not test, so a
/// fixture that grew past it is a broken fixture this file should be told
/// about rather than a case to assert is unreachable.
fn snapshot(entries: []const interface.Entry) SnapshotError!Snapshot {
    var read: Snapshot = undefined;
    read.clear();
    for (entries) |entry| try read.add(entry);
    return read;
}

/// A direct path to `peer`, reached at `local`.
fn direct(peer: u8, local: ?IpAddress) Held {
    return .{ .remote = .{ .ip = .{ .ip = v4(peer), .port = 7842 } }, .local = local };
}

/// A relayed path. The variant that has no local address to take away.
fn relayed(local: ?IpAddress) !Held {
    return .{
        .remote = .{ .relay = try addr.RelayUrl.parse("https://relay.example./") },
        .local = local,
    };
}

test "an unchanged machine holds every path it held" {
    const read = try snapshot(&.{ on(v4(1)), on(v4(2)) });
    const change: Change = .{ .previous = read, .current = read, .loopback = false };

    const one = direct(10, v4(1));
    const two = direct(11, v4(2));
    try t.expectEqual(Verdict.held, verdict(&change, &one, test_binding));
    try t.expectEqual(Verdict.held, verdict(&change, &two, test_binding));

    // The same two as a set. A verdict that fired on a poll with nothing moved
    // would withdraw a path on every turn of an idle loop, and the counts are
    // what a caller watching a whole table would act on.
    const counted = tally(&change, &.{ one, two }, test_binding);
    try t.expectEqual(@as(usize, 2), counted.get(.held));
    try t.expectEqual(@as(usize, 0), counted.get(.rebound));
    try t.expectEqual(@as(usize, 0), counted.get(.stranded));
    try t.expectEqual(@as(usize, 0), counted.get(.unbound));
}

test "a retired local address costs one pairing while the node holds another" {
    const change: Change = .{
        .previous = try snapshot(&.{ on(v4(1)), on(v4(2)) }),
        .current = try snapshot(&.{on(v4(2))}),
        .loopback = false,
    };

    // Whatever the cause — Wi-Fi blinked, a lease renewed, a VPN came up — the
    // address the first path was reached at is gone and a second one is not.
    const lost = direct(10, v4(1));
    const kept = direct(11, v4(2));
    try t.expectEqual(Verdict.rebound, verdict(&change, &lost, test_binding));
    // And the path that was never reached at that address is untouched, which is
    // what makes this a per-path answer rather than a per-node one.
    try t.expectEqual(Verdict.held, verdict(&change, &kept, test_binding));

    const counted = tally(&change, &.{ lost, kept }, test_binding);
    try t.expectEqual(@as(usize, 1), counted.get(.rebound));
    try t.expectEqual(@as(usize, 1), counted.get(.held));
}

test "a node that keeps none of its addresses strands the paths it was reached at" {
    const change: Change = .{
        .previous = try snapshot(&.{on(v4(1))}),
        .current = try snapshot(&.{on(v4(9))}),
        .loopback = false,
    };

    const lost = direct(10, v4(1));
    try t.expectEqual(Verdict.stranded, verdict(&change, &lost, test_binding));

    // The address this node holds now reads `.held` whatever the earlier read
    // said about it, because `.held` is a fact about `current`. An answer built
    // from the intersection instead would call this `.unbound` and send a
    // caller looking for an address it already has.
    const fresh = direct(11, v4(9));
    try t.expectEqual(Verdict.held, verdict(&change, &fresh, test_binding));
}

test "the verdict reads the local half of a path and never the peer's" {
    const change: Change = .{
        .previous = try snapshot(&.{on(v4(1))}),
        .current = try snapshot(&.{on(v4(9))}),
        .loopback = false,
    };
    const gone = v4(1);

    // Three peers behind one local address, one of them a custom transport: a
    // change on this machine cannot tell them apart and does not try. Were the
    // peer's half consulted at all, two of these three would have to differ.
    const first = direct(10, gone);
    const second = direct(11, gone);
    const third: Held = .{
        .remote = .{ .custom = .{ .id = 7, .data = &.{} } },
        .local = gone,
    };
    for ([_]*const Held{ &first, &second, &third }) |one| {
        try t.expectEqual(Verdict.stranded, verdict(&change, one, test_binding));
    }

    // And the converse, which is the failure this file exists to prevent: one
    // peer reached at two local addresses gets two different answers, and the
    // peer's address is in neither of them. A peer whose own network moved
    // keeps every path this node holds to it, and this node's Wi-Fi blinking
    // withdraws only the pairing whose local half is the one that died.
    const same_peer_here = direct(10, v4(9));
    const same_peer_gone = direct(10, gone);
    try t.expectEqual(Verdict.held, verdict(&change, &same_peer_here, test_binding));
    try t.expectEqual(Verdict.stranded, verdict(&change, &same_peer_gone, test_binding));
}

test "a path reached at no interface address is unbound under any change" {
    const change: Change = .{
        .previous = try snapshot(&.{on(v4(1))}),
        .current = try snapshot(&.{}),
        .loopback = false,
    };

    // This change strips the node of every address it had. A relay path and a
    // custom-transport path are not reached at one of them, so the address that
    // left cannot be about either, and neither is withdrawn.
    const via_relay = try relayed(null);
    const via_custom: Held = .{
        .remote = .{ .custom = .{ .id = 7, .data = &.{} } },
        .local = null,
    };
    try t.expectEqual(Verdict.unbound, verdict(&change, &via_relay, test_binding));
    try t.expectEqual(Verdict.unbound, verdict(&change, &via_custom, test_binding));

    // The same relay paired with a local address is a different record, and the
    // local half decides it: null is not a wildcard, and pairing is what makes
    // a path reachable at an address of this machine's at all.
    const paired = try relayed(v4(1));
    try t.expectEqual(Verdict.stranded, verdict(&change, &paired, test_binding));
}

test "an address no read ever reported is unbound, not stranded" {
    const change: Change = .{
        .previous = try snapshot(&.{on(v4(1))}),
        .current = try snapshot(&.{on(v4(9))}),
        .loopback = false,
    };

    // The caller paired a path with an address the machine never reported: a
    // stale record, or a bug in the caller. This node did not lose it, and
    // `.stranded` would say it did — a lie about this machine dressed as a
    // conservative answer. Fail closed is about what the two reads prove, and
    // they prove nothing here, so the answer is the one that admits it.
    const never = direct(10, v4(7));
    try t.expectEqual(Verdict.unbound, verdict(&change, &never, test_binding));
}

test "the loopback policy the change was stored with decides what was held" {
    const change: Change = .{
        .previous = try snapshot(&.{
            on(v4(1)),
            .{ .interface = lo, .ip = v4(3), .up = true, .loopback = true },
        }),
        .current = try snapshot(&.{on(v4(1))}),
        .loopback = false,
    };
    const wide: Change = .{
        .previous = change.previous,
        .current = change.current,
        .loopback = true,
    };

    // `v4(3)` is on `lo`. Counted under a policy that hides loopback — a peer on
    // another host — it is in neither read, so this change never held it and
    // never took it. Counted under the policy that admits it, it was in the
    // earlier read and is not in the later one, and the path reached at it lost
    // its address. Two reads, two policies, two answers, and this module picks
    // neither: the policy is stored on the change and applied by
    // `interface.reachableAt`.
    //
    // Under the wider policy the answer is `.rebound` and not `.stranded`,
    // because `v4(1)` survived and this node is not out of addresses. That is
    // the whole weight of the policy: the same lost loopback address sends one
    // caller to re-publish and another to leave a path alone, and neither
    // choice is made here.
    const on_loopback = direct(10, v4(3));
    try t.expectEqual(Verdict.unbound, verdict(&change, &on_loopback, test_binding));
    try t.expectEqual(Verdict.rebound, verdict(&wide, &on_loopback, test_binding));

    // And the policy decides nothing else: `v4(1)` is held under both, so a
    // loopback address moving under the wider policy is not what made this
    // path's answer `.held`.
    const on_eth0 = direct(11, v4(1));
    try t.expectEqual(Verdict.held, verdict(&change, &on_eth0, test_binding));
    try t.expectEqual(Verdict.held, verdict(&wide, &on_eth0, test_binding));
}

test "an address on an interface that is down was never held" {
    const change: Change = .{
        .previous = try snapshot(&.{
            .{ .interface = eth0, .ip = v4(1), .up = false, .loopback = false },
        }),
        .current = try snapshot(&.{}),
        .loopback = false,
    };

    // The kernel does not route an address off an interface that is down, so
    // this node was never reachable at `v4(1)` and its departure takes nothing
    // away. The `IFF_UP` filter is `interface.reachableAt`'s and is not restated
    // here; this pins that it reaches the answer rather than that it exists.
    const path = direct(10, v4(1));
    try t.expectEqual(Verdict.unbound, verdict(&change, &path, test_binding));
}

test "the host bits and the port cannot reach the verdict" {
    const change: Change = .{
        .previous = try snapshot(&.{on(v4(1))}),
        .current = try snapshot(&.{ on(v4(9)), on(v6()) }),
        .loopback = false,
    };
    const lost = direct(10, v4(1));

    // Four bindings, one answer. `reachableAt` is handed the host bits and the
    // port because its signature asks for them, and a verdict that read either
    // would be a verdict about something other than this machine's interfaces.
    const bindings = [_]Binding{
        test_binding,
        .{ .host = @splat(0xff), .port = 0 },
        .{ .host = @splat(0), .port = 1 },
        .{ .host = @splat(0xaa), .port = std.math.maxInt(u16) },
    };
    for (bindings) |one| {
        try t.expectEqual(Verdict.stranded, verdict(&change, &lost, one));
    }

    // These are four different inputs, not one argument spelled four ways: the
    // synthetic address a peer reaches this node at before it has chosen a path
    // is built from the host bits and differs between them, and the port lands
    // on every interface address. None of it is in a family list this module
    // reads — which is also why an interface address carries no port of its own
    // and is compared as an `IpAddress`.
    for (bindings, 0..) |one, index| {
        const reach = interface.reachableAt(&change.current, one.host, one.port, false);
        try t.expect(!carries(&reach, ula.anyPathSocketAddr(one.host).ip));
        for (reach.v4Addrs()) |socket| try t.expectEqual(one.port, socket.port);
        for (reach.v6Addrs()) |socket| try t.expectEqual(one.port, socket.port);
        if (index == 0) continue;
        const earlier = bindings[index - 1];
        try t.expect(!std.meta.eql(
            ula.anyPathSocketAddr(earlier.host).ip,
            ula.anyPathSocketAddr(one.host).ip,
        ));
    }
}

test "every verdict arm is reachable and the tally counts each path once" {
    const rebound_change: Change = .{
        .previous = try snapshot(&.{ on(v4(1)), on(v4(2)) }),
        .current = try snapshot(&.{on(v4(2))}),
        .loopback = false,
    };
    const stranded_change: Change = .{
        .previous = try snapshot(&.{ on(v4(1)), on(v4(2)) }),
        .current = try snapshot(&.{}),
        .loopback = false,
    };

    // Under the first change `v4(2)` is held and `v4(1)` is rebound. Under the
    // second nothing of the earlier read survived, so both of those are
    // stranded and only the relayed path — which carries no local address at
    // all — is unbound. Every arm is produced by one of the two.
    const paths = [_]Held{
        try relayed(null),
        direct(10, v4(2)),
        direct(11, v4(1)),
    };
    const counted = [_]Tally{
        tally(&rebound_change, &paths, test_binding),
        tally(&stranded_change, &paths, test_binding),
    };

    var seen: usize = 0;
    inline for (@typeInfo(Verdict).@"enum".field_names) |field| {
        var hits: usize = 0;
        for (counted) |one| hits += one.get(@field(Verdict, field));
        // An arm nothing reaches is an answer this file cannot give, and adding
        // one would otherwise land at zero with nothing looking for it.
        try t.expect(hits > 0);
        seen += hits;
    }
    // Every path carried exactly one verdict per change, so the arms partition
    // the set: no path is counted twice and none is dropped.
    try t.expectEqual(@as(usize, paths.len * counted.len), seen);
}

test "the tally is the per-path verdict, counted" {
    const change: Change = .{
        .previous = try snapshot(&.{ on(v4(1)), on(v4(2)) }),
        .current = try snapshot(&.{on(v4(2))}),
        .loopback = false,
    };
    const paths = [_]Held{
        direct(10, v4(1)),
        direct(11, v4(2)),
        direct(12, null),
        try relayed(null),
        direct(13, v4(7)),
    };

    // `verdict` and `tally` build the reachable sets a different number of
    // times, so this is the one that says they are the same decision rather than
    // two that happen to agree today.
    const want = [_]Verdict{ .rebound, .held, .unbound, .unbound, .unbound };
    for (paths, want) |one, expected| {
        try t.expectEqual(expected, verdict(&change, &one, test_binding));
    }

    const counted = tally(&change, &paths, test_binding);
    try t.expectEqual(@as(usize, 1), counted.get(.held));
    try t.expectEqual(@as(usize, 1), counted.get(.rebound));
    try t.expectEqual(@as(usize, 0), counted.get(.stranded));
    try t.expectEqual(@as(usize, 3), counted.get(.unbound));
}
