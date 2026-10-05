//! One decoded OBSERVED_ADDRESS frame, turned into the address the peer is
//! seen at.
//!
//! `qad.zig` is a codec over bytes and says so: it decodes a frame and stops,
//! and its module doc names the two things it deliberately does not own — the
//! canonicalisation of what a relay reported, and the rule for a sequence
//! number that did not move forward. Both are decisions about what a frame
//! *means*, and both belong here.
//!
//! Nothing here reads a clock, opens a socket or allocates. A frame and a
//! latency go in; an `Observation` comes out. The path state the sequence rule
//! needs is a parameter (`Sequence`), not a capture.
//!
//! # The family is explicit, and it is two families
//!
//! One `Observation` type carries a v4 and a v6 sighting, and it carries two
//! family fields rather than one, because after canonicalisation they can
//! differ: `family` is what the frame's type said (§4.1's least significant
//! bit) and `ipFamily` is what the address in it now is. A frame that arrives
//! on the v6 path carrying `::ffff:a.b.c.d` has `family == .v6` and
//! `ipFamily() == .v4`. Collapsing those into one field would make the case
//! unrepresentable and lose the one fact a caller needs — the address no
//! longer belongs to the path it arrived on.
//!
//! # Decision: an IPv4-mapped IPv6 address canonicalises to its IPv4 form
//!
//! `::ffff:a.b.c.d` and `a.b.c.d` are one host on one wire path, and RFC 4291
//! §2.5.5.2 defines the first as a spelling of the second. This module
//! **unmaps**, keeping the frame's declared family in `Observation.family`.
//! `qad.zig`'s own test for the mapped form is not reachable on a v4 frame —
//! §4.1's family bit decides that the body is four bytes — so this path is v6
//! only.
//!
//! Three reasons, and the first is the one that decides it:
//!
//! 1. **Left mapped, it lies to the report.** `report_fold.fold` routes on
//!    `qad.addr.ip` and sets `Report.udp_v6 = true` on the `.v6` arm
//!    (`report_fold.zig:276-282`). A relay dual-stack, answering a v6 probe
//!    with `::ffff:198.51.100.7`, would publish an IPv4 address into the v6
//!    slot and assert that this node has a working v6 path because it does.
//!    That is a false `hasUdp` answer, and `hasUdp` is what makes hole punching
//!    try.
//! 2. **Unmapped, it is excluded instead, which is the true answer.** The
//!    same address on the `.v4` arm of that switch falls through to `{}`: the
//!    measurement is kept, the address is dropped, and the family mismatch is
//!    visible to the caller through `Observation.family`. This matches what
//!    upstream's `to_canonical` (`net_report.rs:857`) produces before
//!    `Report::update`'s own family check (`report.rs:81-84`).
//! 3. **A disagreement is the worst available outcome, so neither spelling may
//!    produce one.** Two relays reporting the same public address, one through
//!    a native v4 socket and one through a dual-stack socket that produced the
//!    mapped form, would disagree under `Varying.observe`'s `std.meta.eql` —
//!    a union tag is part of the comparison — and `mapping_varies_by_dest_*`
//!    would read `true`. That is a destination-dependent NAT invented from a
//!    spelling, and hole punching reads that field.
//!
//! **What is not unmapped.** `::a.b.c.d` — the IPv4-compatible form of
//! RFC 4291 §2.5.5.1, deprecated by the same section — stays a v6 address. It
//! is not what a dual-stack socket produces, and a real v6 path can legitimately
//! be numbered from that block, so collapsing it would invent a v4 observation
//! out of a v6 one. The test below pins both halves of that split.
//!
//! # Decision: a sequence number that does not move forward is a stale frame
//!
//! `Sequence.admit` refuses a frame whose sequence number is not greater than
//! the last accepted one. It returns `.stale`, and it is **not** an error: no
//! arm of this module's `Error` can be raised by a sequence number, and
//! `qad.zig` has no sequence refusal either. The three readings of a backward
//! number were considered separately, and only one of them survives as a
//! possibility at all:
//!
//! - **A reordered frame — impossible.** QUIC delivers a connection's packets
//!   in packet-number order (RFC 9000 §13.2), so two OBSERVED_ADDRESS frames
//!   cannot be handed to this layer out of order. This is the only one of the
//!   three that a network could cause, and the network cannot cause it.
//! - **A second path — excluded by the numbering, not by us.** §4.1's sequence
//!   number increments once per frame on the *connection*, and a genuinely new
//!   path takes the *next* number. A peer that restarted at zero for a new path
//!   would be off-spec, and a frame from it is refused by exactly this rule
//!   whether it is a bug, a fork, or an attack.
//! - **A duplicate or a replay — the only reading left.** The bytes cannot
//!   tell a peer that re-sent a frame from an attacker who re-injected one, and
//!   nothing in-band ever could. Packet protection already makes off-path
//!   injection infeasible (RFC 9001 §5.4), so what remains is a peer that is
//!   buggy or lying.
//!
//! So all three collapse to one safe action, and it is the action the draft
//! itself names: ignore the frame. **The only QAD protocol error is a peer that
//! sends when it was not asked to receive** (`qad.Role.shouldReport`, already
//! enforced at `qad.zig:176`), and that is a send-side violation about a
//! transport parameter — it is visible at handshake time, carries no sequence
//! number, and cannot be inferred from a frame that arrives late. Failing a
//! connection over a stale frame would punish the one reading that is
//! reachable.
//!
//! Two consequences are load-bearing and both are pinned by the tests: the
//! window does **not** move on a stale frame (a later higher number is still
//! accepted), and a stale frame never reaches the reporter, so it cannot count
//! as a second independent observation. The sequence is a 62-bit variable-length
//! integer (`qad.max_sequence`) and a connection does not live long enough to
//! wrap it, so there is no wrap case to handle.
//!
//! # Two refusals, both at the wire boundary
//!
//! A report's `global_v4` is published to peers as "try here", so an address
//! that cannot be dialled must not reach it. `canonical` refuses
//!
//! - `error.SyntheticAddress` — one of our own dress-up addresses. `ula.zig`
//!   owns that spelling (`prefix_l`, `global_id`, the three subnets) and its
//!   `classify` is the one test for it; this module adds no second. Upstream's
//!   `DEFAULT_FAKE_ADDR` is `ula.default_fake_addr` and lands on the `any_path`
//!   arm, so the named constant is exercised below.
//! - `error.NotReachable` — the unspecified address of a family, loopback, or
//!   port zero. A relay on the open internet cannot have seen us at any of the
//!   three, and a datagram cannot be sent from port zero at all.
//!
//! Refusing drops the address, never the round: `report_fold.fold` already keeps
//! the latency of an address it refuses for a family mismatch
//! (`report_fold.zig:268-274`), and a caller does the same here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");
const qad = @import("qad.zig");
const measure = @import("report_measure.zig");

const Family = qad.Family;
const IpAddress = addr.IpAddress;
const SocketAddr = addr.SocketAddr;
const Nanos = measure.Nanos;

const t = std.testing;

/// Everything `canonical` refuses, in one closed set. No sequence number can
/// raise any of these; see the module doc for why a stale frame is not one.
pub const Error = error{
    /// The address is one of ours: `fd15:70a:510b::/64`, `/1::/64` or `/3::/64`
    /// as `ula.classify` spells them. Not routable, and never a public address.
    SyntheticAddress,
    /// The unspecified address of the family, or a loopback address. No peer
    /// on the open internet has been seen at either.
    NotReachable,
};

/// The twelve octets RFC 4291 §2.5.5.2 puts in front of an IPv4 address to
/// spell it in IPv6: ten zeros and two `0xff`. Sixteen minus four, which is
/// what makes the mapped form's collapse a slice copy rather than a parse.
const mapped_prefix: [12]u8 = .{0} ** 10 ++ .{ 0xff, 0xff };

/// What a frame means, once its address is canonical and its latency is known.
///
/// A value: fixed size, no borrow, no allocation, so it can sit in a probe
/// result array and be compared without a lifetime.
pub const Observation = struct {
    /// The family the frame's type declared, §4.1's least significant bit.
    /// Read against the probe that carried it, which is the check
    /// `report_fold.fold` performs and this module does not repeat.
    family: Family,
    /// The address the peer appears to be at, canonicalised: unmapped if it
    /// arrived in the IPv4-mapped IPv6 form, refused if it is synthetic or
    /// unroutable.
    addr: SocketAddr,
    /// The round trip measured for the round that produced this frame, in
    /// `Nanos` on the caller's own timeline. The frame carries no time, so this
    /// is an argument and never something read from a clock here.
    latency: Nanos,
    /// §4.1's sequence number, unconverted. `Sequence.admit` is what reads it;
    /// keeping it on the value means a caller cannot gate on it without having
    /// the number in hand.
    sequence: u64,

    /// The family of `addr` itself, which after canonicalisation is not always
    /// `family`. This is the family a claim about this node's address belongs
    /// to.
    pub fn ipFamily(self: Observation) Family {
        return switch (self.addr.ip) {
            .v4 => .v4,
            .v6 => .v6,
        };
    }
};

/// Turn a decoded frame plus its round's latency into an observation.
///
/// Pure in the strong sense: the frame and the latency are the only inputs,
/// the result borrows nothing, and two calls with equal arguments produce
/// equal values.
///
/// Fails closed on an address that is not a public address; see the two
/// refusals in the module doc. `Error` is the whole of what a peer can provoke
/// here — `qad.decode` has already refused everything a malformed frame can be.
pub fn canonical(observed: qad.ObservedAddress, latency: Nanos) Error!Observation {
    return .{
        .family = switch (observed.addr.ip) {
            .v4 => .v4,
            .v6 => .v6,
        },
        .addr = try publicAddr(observed.addr),
        .latency = latency,
        .sequence = observed.sequence,
    };
}

/// The address as a peer could actually be dialled at.
///
/// The order is load-bearing and it is address-then-port, for a reason about
/// legibility rather than safety: a synthetic address is refused as a
/// synthetic address whether or not its port is zero, because that is what
/// the address is, and nothing before the port check reads anything else.
fn publicAddr(socket: SocketAddr) Error!SocketAddr {
    if (socket.port == 0) return error.NotReachable;
    switch (socket.ip) {
        .v4 => |octets| {
            if (unroutableV4(octets)) return error.NotReachable;
            return socket;
        },
        .v6 => |octets| {
            if (unroutableV6(octets)) return error.NotReachable;
            switch (ula.classify(socket)) {
                .any_path, .relay, .custom => return error.SyntheticAddress,
                .ip => {},
            }
            return .{ .ip = unmap(octets), .port = socket.port };
        },
    }
}

/// The IPv4 address `::ffff:a.b.c.d` names, or `octets` unchanged when the
/// address is anything else — including the deprecated IPv4-compatible form
/// `::a.b.c.d`, which stays v6 for the reason the module doc gives.
fn unmap(octets: [16]u8) IpAddress {
    if (!std.mem.eql(u8, octets[0..12], &mapped_prefix)) return .{ .v6 = octets };
    return .{ .v4 = .{ octets[12], octets[13], octets[14], octets[15] } };
}

/// `0.0.0.0` is the unspecified address; `127.0.0.0/8` is the whole loopback
/// block, not just `127.0.0.1`, because every address in it is local-only.
fn unroutableV4(octets: [4]u8) bool {
    return std.mem.allEqual(u8, &octets, 0) or octets[0] == 127;
}

/// `::` is the unspecified address and `::1` the loopback one. They are two
/// different addresses, so this is two tests rather than the v4 test's one.
fn unroutableV6(octets: [16]u8) bool {
    if (std.mem.allEqual(u8, &octets, 0)) return true;
    var loopback: [16]u8 = @splat(0);
    loopback[15] = 1;
    return std.mem.eql(u8, &octets, &loopback);
}

/// What a frame's sequence number means against what this path has already
/// accepted.
pub const Admit = enum {
    /// Greater than every sequence accepted so far, or the first on this path.
    /// A new observation, and the window moves to it.
    fresh,
    /// Not greater than the last accepted. The frame adds nothing and is not
    /// an error; see the module doc for the three readings that collapse here.
    stale,
};

/// The sequence state §4.1's monotonicity rule needs, for one path.
///
/// Zero by default and already the answer for the first frame: a fresh window
/// admits whatever number the peer starts at, because §4.1 requires the numbers
/// to increase and says nothing about where they start. A peer that begins at
/// `1 << 40` is as valid as one that begins at `0`.
///
/// State is a parameter and the mutation is explicit, so a caller can run two
/// windows over the same frames — two paths, or two connections — and get two
/// answers without either being a capture.
pub const Sequence = struct {
    /// The last sequence accepted, or null before the first. Null rather than
    /// zero because zero is a legal sequence number and a default window must
    /// not read as though it had accepted one.
    last: ?u64 = null,

    /// Admit `sequence`, and say what it meant. Moves the window on `.fresh`
    /// and leaves it where it is on `.stale`, so a later higher number is
    /// still admitted.
    pub fn admit(self: *Sequence, sequence: u64) Admit {
        if (self.last) |last| {
            if (sequence <= last) return .stale;
        }
        self.last = sequence;
        return .fresh;
    }

    /// The last accepted sequence, or null when nothing has been admitted.
    pub fn accepted(self: *const Sequence) ?u64 {
        return self.last;
    }
};

/// `198.51.100.7` as an IPv4-mapped IPv6 address: RFC 4291 §2.5.5.2's ten
/// zeros, two `0xff`, and the four address octets.
const mapped_v6: [16]u8 = .{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0xff, 0xff, 198, 51, 100, 7,
};

/// The same address in its deprecated IPv4-compatible form, §2.5.5.1: twelve
/// zeros and the four octets. One `0xff` pair is the whole difference between
/// this and `mapped_v6`, and it is the difference between unmapping and not.
const compatible_v6: [16]u8 = .{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0,    0, 198, 51, 100, 7,
};

/// `2001:db8::7`, from the documentation prefix. A real v6 address, and the
/// one vector that shows canonicalisation leaves one alone.
const doc_v6: [16]u8 = .{
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 0x07,
};

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

fn frameOf(sequence: u64, ip: IpAddress, port: u16) qad.ObservedAddress {
    return .{ .sequence = sequence, .addr = .{ .ip = ip, .port = port } };
}

test "a v4 and a v6 frame become one kind of observation, family explicit" {
    const four = try canonical(frameOf(1, .{ .v4 = .{ 198, 51, 100, 7 } }, 41234), millis(9));
    const six = try canonical(frameOf(1, .{ .v6 = doc_v6 }, 41234), millis(30));

    // One type, not a union with a v4 arm and a v6 arm: a caller holds one
    // value either way, and `ipFamily` is what tells it which it holds.
    try t.expectEqual(Family.v4, four.family);
    try t.expectEqual(Family.v6, six.family);
    try t.expectEqual(Family.v4, four.ipFamily());
    try t.expectEqual(Family.v6, six.ipFamily());

    // The latency is the round's and is carried through untouched, and the
    // frame's own fields survive canonicalisation.
    try t.expectEqual(millis(9), four.latency);
    try t.expectEqual(millis(30), six.latency);
    try t.expectEqual(@as(u64, 1), four.sequence);
    try t.expectEqual(@as(u16, 41234), six.addr.port);
}

test "the IPv4-mapped form canonicalises to IPv4, and the frame's family does not" {
    const mapped = try canonical(frameOf(3, .{ .v6 = mapped_v6 }, 41234), millis(9));
    const plain = try canonical(frameOf(3, .{ .v4 = .{ 198, 51, 100, 7 } }, 41234), millis(9));

    // The two spellings are one value, so two relays reporting the same public
    // address cannot disagree under `Varying`'s `std.meta.eql` — a union tag is
    // part of that comparison — and invent a destination-dependent NAT out of
    // a spelling.
    try t.expectEqual(plain.addr, mapped.addr);
    try t.expectEqual(Family.v4, mapped.ipFamily());

    // The frame's declared family survives, and that is the fact a caller
    // needs in order to drop the address: `report_fold.fold` keeps the latency
    // of an address whose family does not match the probe that carried it
    // (`report_fold.zig:268-274`), which it can only do if the mismatch is
    // still visible here.
    try t.expectEqual(Family.v6, mapped.family);
    try t.expect(mapped.family != mapped.ipFamily());

    // A real v6 address is untouched: no mapped prefix, no collapse.
    const six = try canonical(frameOf(3, .{ .v6 = doc_v6 }, 41234), millis(9));
    try t.expectEqual(doc_v6, six.addr.ip.v6);
    try t.expectEqual(Family.v6, six.family);
}

test "the deprecated IPv4-compatible form stays IPv6" {
    // RFC 4291 §2.5.5.1 deprecated `::a.b.c.d` and this module does not
    // resurrect it: only the `::ffff:` prefix of §2.5.5.2 collapses. A v6 path
    // numbered from that block is a real v6 path, and collapsing it would
    // manufacture a v4 observation out of a v6 one.
    const observation = try canonical(frameOf(1, .{ .v6 = compatible_v6 }, 1), millis(9));
    try t.expectEqual(Family.v6, observation.ipFamily());
    try t.expectEqual(compatible_v6, observation.addr.ip.v6);
}

test "a mapped frame on the wire reads back as the same IPv4 address" {
    // The full path, over bytes: encode what a dual-stack relay would send,
    // decode it with the codec, then canonicalise. The codec's family bit put
    // sixteen address octets in the body, so the mapped form really does
    // arrive on a frame typed v6.
    //
    // The bytes come from `qad.encode`, not from a capture: no upstream OBSERVED_ADDRESS
    // bytes exist on this node, which is the gap `qad.zig`'s own module doc
    // names. What this pins is that the two halves compose.
    var bytes: [qad.max_frame_length]u8 = undefined;
    const length = try qad.encode(frameOf(7, .{ .v6 = mapped_v6 }, 41234), &bytes);
    const decoded = try qad.decode(bytes[0..length]);
    try t.expect(decoded.observed.addr.ip == .v6);

    const observation = try canonical(decoded.observed, millis(12));
    try t.expectEqual(Family.v6, observation.family);
    try t.expectEqual(Family.v4, observation.ipFamily());
    try t.expectEqual(@as(u16, 41234), observation.addr.port);
    try t.expectEqual(@as(u64, 7), observation.sequence);
}

test "a sequence number that does not move forward is stale, and never an error" {
    var sequence: Sequence = .{};

    // The first frame is admitted whatever it says: §4.1 requires the numbers
    // to increase and says nothing about where they start.
    try t.expectEqual(Admit.fresh, sequence.admit(0));
    try t.expectEqual(@as(?u64, 0), sequence.accepted());
    try t.expectEqual(Admit.fresh, sequence.admit(1));
    try t.expectEqual(Admit.fresh, sequence.admit(1 << 20));

    // Equal is stale and so is backward, and neither raised an error. The only
    // QAD protocol error is a peer that sends when it was not asked to
    // receive (`qad.Role.shouldReport`), which is a transport-parameter
    // violation settled at handshake time and carries no sequence number.
    try t.expectEqual(Admit.stale, sequence.admit(1 << 20));
    try t.expectEqual(Admit.stale, sequence.admit(0));
    try t.expectEqual(Admit.stale, sequence.admit(7));

    // The window did not move on any of them, so a later higher number is
    // still admitted instead of being swallowed behind the stale frames.
    try t.expectEqual(@as(?u64, 1 << 20), sequence.accepted());
    try t.expectEqual(Admit.fresh, sequence.admit((1 << 20) + 1));
    try t.expectEqual(@as(?u64, (1 << 20) + 1), sequence.accepted());
}

test "two windows are two paths, and neither is a capture" {
    // State is a parameter, so the same frames against two windows give two
    // answers. A second path that restarts the peer's numbering is a peer
    // breaking §4.1; both windows keep working and neither sees the other.
    var first: Sequence = .{};
    var second: Sequence = .{};
    try t.expectEqual(Admit.fresh, first.admit(9));
    try t.expectEqual(Admit.fresh, second.admit(1));

    try t.expectEqual(Admit.stale, first.admit(8));
    try t.expectEqual(Admit.fresh, second.admit(2));
    try t.expectEqual(@as(?u64, 9), first.accepted());
    try t.expectEqual(@as(?u64, 2), second.accepted());

    // An untouched window has accepted nothing, which is not the same answer as
    // having accepted sequence zero.
    var empty: Sequence = .{};
    try t.expectEqual(@as(?u64, null), empty.accepted());
}

test "a synthetic address is refused, not canonicalised" {
    // `ula.classify` is the only test for our own prefixes, and all three
    // subnets reach it, so a relay reporting any of them back at us cannot put
    // an unroutable dress-up address into a published report.
    const hosts = [_]ula.HostBits{
        .{0} ** 8,
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        .{0xff} ** 8,
    };
    inline for ([_]ula.Path{ .any_path, .relay, .custom }) |path| {
        for (hosts) |host| {
            try t.expectError(
                error.SyntheticAddress,
                canonical(frameOf(1, .{ .v6 = ula.ulaFor(path, host) }, 1), millis(9)),
            );
            try t.expectError(
                error.SyntheticAddress,
                canonical(
                    frameOf(1, .{ .v6 = ula.ulaFor(path, host) }, ula.mapped_port),
                    millis(9),
                ),
            );
        }
    }

    // Upstream's `DEFAULT_FAKE_ADDR` specifically: the `any_path` subnet's top
    // address, and the one synthetic address a QUIC stack is most likely to be
    // handed. Pinning which arm of `classify` it lands on, rather than only
    // that it is refused, is what says this is refused by `ula`'s own
    // spelling and not by a prefix written out a second time here.
    try t.expectEqual(ula.Path.any_path, switch (ula.classify(ula.default_fake_addr)) {
        .any_path => ula.Path.any_path,
        .relay => ula.Path.relay,
        .custom => ula.Path.custom,
        .ip => unreachable,
    });
    try t.expectError(
        error.SyntheticAddress,
        canonical(frameOf(1, ula.default_fake_addr.ip, ula.default_fake_addr.port), millis(9)),
    );
}

test "an address no peer could be dialled at is refused, per family" {
    const unspecified_v4: IpAddress = .{ .v4 = .{ 0, 0, 0, 0 } };
    const unspecified_v6: IpAddress = .{ .v6 = @splat(0) };
    var loopback_v6: [16]u8 = @splat(0);
    loopback_v6[15] = 1;

    for ([_]IpAddress{ unspecified_v4, unspecified_v6 }) |ip| {
        try t.expectError(error.NotReachable, canonical(frameOf(1, ip, 1), millis(9)));
    }

    // The whole `127.0.0.0/8` block and not only `127.0.0.1`, and `::1` beside
    // `::`. A relay on the open internet has seen us at neither.
    for ([_][4]u8{ .{ 127, 0, 0, 1 }, .{ 127, 255, 255, 254 } }) |octets| {
        try t.expectError(
            error.NotReachable,
            canonical(frameOf(1, .{ .v4 = octets }, 1), millis(9)),
        );
    }
    try t.expectError(
        error.NotReachable,
        canonical(frameOf(1, .{ .v6 = loopback_v6 }, 1), millis(9)),
    );

    // One above the loopback block's last octet is dialled, and the loopback
    // block is refused whole: the first byte is the whole difference.
    const kept = try canonical(frameOf(1, .{ .v4 = .{ 128, 0, 0, 1 } }, 1), millis(9));
    try t.expectEqual(@as([4]u8, .{ 128, 0, 0, 1 }), kept.addr.ip.v4);
}

test "a port of zero is refused with the address it belongs to" {
    // `qad.decode` reads whatever two bytes followed the address and nothing
    // above this module checked them, so a frame can name port zero. A
    // datagram cannot be sent from port zero, so publishing the pair in a
    // report is a lie a peer acts on.
    try t.expectError(
        error.NotReachable,
        canonical(frameOf(1, .{ .v4 = .{ 198, 51, 100, 7 } }, 0), millis(9)),
    );
    try t.expectError(
        error.NotReachable,
        canonical(frameOf(1, .{ .v6 = doc_v6 }, 0), millis(9)),
    );
    // One above it is kept, and the boundary that matters is the whole of a
    // `u16`'s bottom: a relay that names a port at all has named a real one.
    const kept = try canonical(frameOf(1, .{ .v4 = .{ 198, 51, 100, 7 } }, 1), millis(9));
    try t.expectEqual(@as(u16, 1), kept.addr.port);
}
