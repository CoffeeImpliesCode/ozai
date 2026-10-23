//! The gate 0-RTT passes through: what may be sent early, and what received
//! early bytes become.
//!
//! Resumption (`resumption.zig`) answers whether a ticket may open a
//! handshake; this file answers whether 0-RTT may ride on it. The two are
//! different permissions — a ticket that resumes 1-RTT perfectly well may
//! still forbid early data — so a second gate, not a flag on the first,
//! owns the difference. Everything here is pure over bytes: no socket, no
//! clock read, no allocator.
//!
//! # Where the gate lives, and why it cannot be bypassed
//!
//! The gate is this file's `Permit`, and it is unforgeable by construction:
//! its only field is not `pub`, so no code outside this file can build one,
//! destructure one, or reset one's budget — the compiler refuses, and there
//! is no runtime check to forget. The sole minter is `permit`, which mints
//! only for a ticket that is live, ours (peer), and for this connection
//! (version, whole ALPN), *and* whose issuing server advertised an early-data
//! allowance (`max_early_data_size > 0`). No valid ticket means no `Permit`
//! value exists, and the future send path takes a `Permit`: there is no call
//! to make without one.
//!
//! The budget is the second half of the gate. A permit carries exactly the
//! bytes the issuing server allowed, and `takeBytes` charges every byte sent
//! against it, refusing past exhaustion. The byte count can therefore never
//! exceed what the issuing connection's server granted, whatever the caller
//! believes.
//!
//! # Refused 0-RTT falls back automatically — but as a value, not an error
//!
//! A client whose 0-RTT is refused runs a full handshake anyway; the refusal
//! is never fatal. Three reasons, in order of force:
//!
//! - The core already does it. Every `tryProcessPsk` failure mode returns
//!   void and continues into a full handshake, and the connection
//!   retransmits refused 0-RTT as 1-RTT on `!zero_rtt_accepted`
//!   (`connection.zig`: "Handle 0-RTT rejection (RFC 9001 §4.1.2)"). An
//!   error here would abort connections the core is already saving and force
//!   every caller to reimplement the retry.
//! - Refusal is routine. Ticket rotation, server policy and ALPN drift all
//!   refuse, and RFC 8446 §4.2.10 requires servers to be able to. An error
//!   type would turn the fast path into a failure path.
//! - Fail-closed survives. Refused bytes are never *acted on* as early data;
//!   `settle` returns them for re-emission under 1-RTT keys. Nothing is
//!   dropped silently and nothing is executed speculatively.
//!
//! So `settle` maps the core's verdict to a union with one arm per outcome,
//! and the refused arm carries the bytes to re-emit. The refusal stays
//! observable — a caller can count it — but not actionable: there is no
//! branch that fails the connection.
//!
//! # What this layer assumes about `zero_rtt_accepted`
//!
//! It is read, never written: the only assignments are the constructors'
//! `false` and the core's own verdicts, and no configuration field, setter
//! or override reaches it. A `true` therefore implies all of: we offered the
//! early_data extension, the PSK opened (binder verified under the server's
//! ticket key), the sealed ALPN equals the selected ALPN, and the versions
//! matched. It is a verified fact, not a hint — `settle` trusts it without
//! re-checking any of those.
//!
//! A `true` does *not* imply freshness. 0-RTT has no anti-replay at the TLS
//! layer (RFC 8446 §8): a replayed flight still verifies, so accepted early
//! data must be treated as replayable-by-construction and only idempotent
//! operations may ride on it. That obligation belongs to the caller choosing
//! what to send, and no gate in this file can lift it.
//!
//! A `false` implies nothing about resumption: the handshake may still have
//! resumed as PSK 1-RTT. Early data refused is not resumption refused, which
//! is why `settle`'s refused arm resends rather than aborts.

const resumption = @import("resumption.zig");

/// The intended connection, as `resumption.zig` names it: the peer the
/// handshake pins, the whole protocol it proposes, and the version its first
/// flight is built with.
pub const Intent = resumption.Intent;
/// The vendored ticket, re-exported so a caller minting a permit needs one
/// import rather than two.
pub const SessionTicket = resumption.SessionTicket;

/// Why no 0-RTT permit was minted.
///
/// The first four are `resumption.Refusal`'s own, reached through
/// `resumption.accept`: a permit is strictly harder to earn than a
/// resumption, so every ticket a resumption refuses is refused here too. The
/// fifth is this file's alone.
pub const Denial = error{
    /// The ticket is past its lifetime on the caller's clock.
    Expired,
    /// The ticket was captured for another peer.
    WrongPeer,
    /// The ticket was issued on another QUIC version (RFC 9369 §5).
    WrongVersion,
    /// The ticket was issued for another protocol (RFC 8446 §4.2.10).
    WrongAlpn,
    /// The ticket resumes, but the issuing server advertised no early-data
    /// allowance: `max_early_data_size` is zero, and a client sending 0-RTT
    /// against it sends it unpermitted (see `SessionTicket`'s own warning).
    NoEarlyData,
};

/// Whether sending one more early-data byte is still allowed.
pub const BudgetError = error{
    /// The permit's budget is spent: the caller has sent all the issuing
    /// server allowed, and the rest goes as 1-RTT.
    BudgetExhausted,
};

/// The licence to send 0-RTT on one resumption: at most `budget` bytes' worth.
///
/// Unforgeable outside this file — the field is not `pub`, so only `permit`
/// builds one and only `takeBytes` spends one. A caller can hold it, pass
/// it, and exhaust it, and nothing else.
pub const Permit = struct {
    /// Bytes still unsent of what the issuing server allowed. Touched only
    /// through `takeBytes` and `remaining`.
    budget: u32,

    /// Charge `byte_count` early-data bytes against the permit.
    ///
    /// Refused past exhaustion rather than clamped: a clamped send would
    /// emit a prefix the peer did not agree to bound, while a refusal tells
    /// the caller the rest goes as 1-RTT.
    pub fn takeBytes(self: *Permit, byte_count: usize) BudgetError!void {
        if (byte_count > self.budget) return error.BudgetExhausted;
        self.budget -= @intCast(byte_count);
    }

    /// Bytes of 0-RTT this permit still allows.
    pub fn remaining(self: *const Permit) u32 {
        return self.budget;
    }
};

/// Mint the licence to send 0-RTT on `intent` under `ticket`.
///
/// `captured_for` is the peer the ticket was captured for, because the
/// ticket itself carries no peer. Refusal is `resumption.accept`'s verdict
/// first — peer, liveness, version, whole ALPN — and only then the allowance:
/// a ticket the issuing server sealed without the early_data extension
/// resumes without early data, whatever the connection negotiates.
pub fn permit(
    ticket: *const SessionTicket,
    captured_for: resumption.NodeId,
    intent: Intent,
    now_s: i64,
) Denial!Permit {
    try resumption.accept(ticket, captured_for, intent, now_s);
    if (ticket.max_early_data_size == 0) return error.NoEarlyData;
    return .{ .budget = ticket.max_early_data_size };
}

/// What became of early bytes once the core gave its verdict.
///
/// Both arms borrow the bytes they carry: processing and re-emission both
/// read them, and neither takes ownership.
pub const Settlement = union(enum) {
    /// `zero_rtt_accepted` is true: the bytes are early data under the
    /// resumption's keys and may be processed.
    accepted: []const u8,
    /// `zero_rtt_accepted` is false: the bytes were never early data. The
    /// connection continues as a full handshake and these go again as 1-RTT
    /// (the core retransmits the client's own; a server drops them and the
    /// peer re-sends per RFC 9001 §4.1.2).
    refused_resend: []const u8,
};

/// Settle early bytes against the core's verdict.
///
/// Pure routing, and total: every call returns one arm or the other, so a
/// caller cannot receive bytes and then forget to ask which kind they are.
/// `zero_rtt_accepted` is trusted as stated in the module doc — a verified
/// fact the core derived from the binder and the sealed name — and nothing
/// here second-guesses it.
pub fn settle(bytes: []const u8, zero_rtt_accepted: bool) Settlement {
    return if (zero_rtt_accepted) .{ .accepted = bytes } else .{ .refused_resend = bytes };
}

// --- tests

const t = @import("std").testing;
const base_key = @import("../base/key.zig");

const NodeId = resumption.NodeId;

/// The QUIC versions this tree speaks, spelled the way the resumption
/// policy's own tests spell them.
const quic_v1: u32 = 1;
const quic_v2: u32 = 0x6b3343cf;

const alpn_main = "ozai";
const alpn_other = "/iroh-qad/0";

/// The peer a seed names: a real ed25519 node id, for the reason the
/// resumption policy's own helper gives.
fn testNodeId(seed: u8) !NodeId {
    var secret = try base_key.SecretKey.fromSeed([_]u8{seed} ** base_key.SecretKey.seed_length);
    defer secret.deinit();
    return secret.nodeId();
}

/// A ticket as the core would have built it, with the early-data allowance
/// the issuing server's NewSessionTicket advertised.
fn ticketFor(
    alpn: []const u8,
    version: u32,
    lifetime_s: u32,
    created_s: i64,
    early_data_max: u32,
) SessionTicket {
    var built: SessionTicket = .{
        .psk = [_]u8{0xa5} ** 32,
        .lifetime = lifetime_s,
        .creation_time = created_s,
        .quic_version = version,
        .max_early_data_size = early_data_max,
    };
    @memcpy(built.alpn[0..alpn.len], alpn);
    // Every private caller supplies 4-byte `"ozai"`, fitting the 32-byte ALPN
    // array and `u8`. ZBC cannot propagate that test-only bound through `alpn`.
    // zbc-disable-next-line: index-type-narrowing-wraparound
    built.alpn_len = @intCast(alpn.len);
    return built;
}

fn intentFor(peer: NodeId, alpn: []const u8, version: u32) Intent {
    return .{ .peer = peer, .alpn = alpn, .quic_version = version };
}

test "a live allowed ticket mints a permit bounded by the server's allowance" {
    const peer = try testNodeId(1);
    const allowed = ticketFor(alpn_main, quic_v1, 3_600, 100, 1_024);
    const intent = intentFor(peer, alpn_main, quic_v1);

    // Minted, with exactly the budget the issuing server granted — no more,
    // because the budget is what the server agreed to bound.
    var pass = try permit(&allowed, peer, intent, 100);
    try t.expectEqual(@as(u32, 1_024), pass.remaining());

    // Every byte sent is charged, and the permit refuses past exhaustion
    // rather than emitting a prefix the peer never bounded.
    try pass.takeBytes(1_000);
    try t.expectEqual(@as(u32, 24), pass.remaining());
    try pass.takeBytes(24);
    try t.expectEqual(@as(u32, 0), pass.remaining());
    try t.expectError(error.BudgetExhausted, pass.takeBytes(1));
    try t.expectEqual(@as(u32, 0), pass.remaining());
}

test "a ticket without an early-data allowance resumes but mints no permit" {
    const peer = try testNodeId(1);
    // Live, ours, right protocol, right version — resumption accepts it.
    const bare = ticketFor(alpn_main, quic_v1, 3_600, 100, 0);
    const intent = intentFor(peer, alpn_main, quic_v1);
    try resumption.accept(&bare, peer, intent, 100);

    // But the issuing server advertised no allowance, so there is no 0-RTT
    // to send: the NewSessionTicket carried no early_data extension, and a
    // client sending against a zero here sends it unpermitted.
    try t.expectError(error.NoEarlyData, permit(&bare, peer, intent, 100));
}

test "a dead or foreign ticket mints no permit, naming its own reason" {
    const peer = try testNodeId(1);
    const stranger = try testNodeId(9);
    const intent = intentFor(peer, alpn_main, quic_v1);

    // Past its lifetime: dead everywhere, not just for early data.
    const dead = ticketFor(alpn_main, quic_v1, 100, 1_000, 1_024);
    try t.expectError(error.Expired, permit(&dead, peer, intent, 1_101));

    // Captured for another peer: not ours to send under.
    const live = ticketFor(alpn_main, quic_v1, 3_600, 100, 1_024);
    try t.expectError(error.WrongPeer, permit(&live, stranger, intent, 100));

    // Issued for another protocol: early data is the issuing connection's
    // own data under its own protocol, and this connection named another.
    try t.expectError(
        error.WrongAlpn,
        permit(&live, peer, intentFor(peer, alpn_other, quic_v1), 100),
    );

    // Issued on another QUIC version: RFC 9369 §5 forbids it outright.
    const future = ticketFor(alpn_main, quic_v2, 3_600, 100, 1_024);
    try t.expectError(error.WrongVersion, permit(&future, peer, intent, 100));
}

test "settlement processes accepted bytes and resends refused ones as 1-RTT" {
    const bytes = "the client's idempotent request";

    // Accepted: the core verified the binder and the sealed protocol, so
    // these are early data under the resumption's keys and may be processed.
    const ok = settle(bytes, true);
    try t.expectEqualStrings(bytes, ok.accepted);

    // Refused: the bytes were never early data. They return for re-emission
    // as 1-RTT — the fallback this file decided — rather than failing the
    // connection or being dropped silently. Refusal is routine (rotation,
    // policy, ALPN drift), so failing here would turn the fast path into a
    // failure path.
    const retry = settle(bytes, false);
    try t.expectEqualStrings(bytes, retry.refused_resend);
}
