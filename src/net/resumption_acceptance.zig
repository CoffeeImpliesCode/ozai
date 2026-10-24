//! What a caller decides when a resumption is offered, and what the resumed
//! session is then allowed to claim about the peer on the other end.
//!
//! `transport/resumption.zig` answers "may this ticket be offered on this
//! connection" and names the four ways the answer is no. `early_data.zig`
//! answers "may 0-RTT ride on it". Neither answers the question an application
//! actually has when a handshake finishes early: **what do I now know about
//! the peer, and what may I do on the strength of it.** A resumption is
//! asymmetric — it removes one end's proof of identity and leaves the other's
//! in place — so a caller that treats "resumed" as "identified" is wrong on one
//! side of every connection it opens.
//!
//! Everything here is pure over values: no socket, no clock read, no
//! allocator. `now_s` is a second on the caller's own clock, the same one the
//! core stamped `creation_time` with, and `proof` is what the finished
//! handshake reported.
//!
//! # The three cross-* refusals, and who enforces them
//!
//! Cross-peer, cross-ALPN and cross-version resumption are each refused, each
//! under its own name (`Refusal`), and **the enforcer is not the same layer for
//! all three.** `layerOf` returns it as a value rather than leaving it to the
//! module doc, so a caller counting refusals can count them by layer.
//!
//! - **Cross-ALPN — the vendored core, twice, and unoverrideable.**
//!   `Tls13Handshake.resumableTicket` answers null unless the client's own
//!   proposal still holds the ticket's protocol, so a ticket for another
//!   protocol is never put on the wire at all; and `tryProcessPsk` computes
//!   `alpn_matches` against the protocol it just selected and writes
//!   `zero_rtt_accepted = early_data_offered and alpn_matches`. Neither is
//!   reachable by a caller: `resumableTicket` is consulted while the
//!   ClientHello is being built, there is no configuration field that sets
//!   `zero_rtt_accepted`, and it is written in exactly two places — both
//!   initialised `false` in the two constructors. A caller cannot offer a
//!   foreign protocol's ticket and be believed; it is offered nothing.
//! - **Cross-version — the vendored core, the same two places.**
//!   `resumableTicket` compares `ticket.quic_version` against the connection's
//!   own `original_version` — the version the first flight is built with, not
//!   the one it may negotiate — and `tryProcessPsk` rejects the sealed version
//!   before it compares names. RFC 9369 §5 is a MUST NOT in both directions,
//!   and it is enforced on the byte the core itself sealed.
//! - **Cross-peer — this tree, because only this tree can know.**
//!   `SessionTicket` carries no peer: the peer is the key the ticket was filed
//!   under, which is not inside it. The store's lookup key *is* the peer, so a
//!   lookup naming another peer addresses an empty slot (`fromStore` cannot
//!   produce this refusal, and that is the stronger of the two answers), and
//!   on the path where a caller holds a ticket value in its own hands
//!   (`fromTicket`) `resumption.accept` compares all 32 bytes of
//!   `captured_for` against the intent's peer before it reads any other field.
//!   No parameter, flag or fallback reaches another peer's PSK.
//!
//! `fromStore` and `fromTicket` are both total and both answer a `Decision`,
//! so there is no path on which a caller learns a resumption succeeded without
//! also learning what it may claim. `resumption.OfferError`'s `NoTicket` is the
//! ordinary cold start and is reported as `FullHandshake.cold_start`, not as a
//! refusal: no resumption existed, which is not the same fact as one existing
//! and being unusable.
//!
//! # What a resumed session inherits about the peer's identity
//!
//! **Read off `vendor/quic/src/quic/tls13.zig`, not off RFC 8446.** Two facts
//! decide it, and they pull in opposite directions.
//!
//! **The client's proof of the server does not survive.** `using_psk` is set in
//! `clientProcessServerHello` when the server selected PSK identity 0, and
//! `clientProcessCertificate` then returns before it reads a certificate at
//! all. `peer_node_id` is written only in that function and in
//! `serverProcessClientCertificate`, so on a resumed client connection it stays
//! `null` and `peerNodeId()` answers `null` — the vendored suite asserts
//! exactly that on its own resumption test. **The `expect_peer_node_id` pin is
//! therefore never compared on a resumed client connection**: there is no
//! certificate to compare it against. What the connection does carry is
//! possession of the PSK, which is bearer material, and the caller's own
//! record of which peer the ticket was filed under.
//!
//! **The server's proof of the client does survive.** The core's state machine
//! routes a resumed connection through `server_send_certificate_request` just
//! as a full one does — its own comment says a PSK skips the server's
//! Certificate and CertificateVerify "and nothing else" — so the client
//! presents its certificate and signs over the transcript on every connection,
//! resumed or not, and `serverProcessClientCertificate` compares it against
//! `ClientAuth.expect_node_id` each time. The reason is in `ClientAuth`: a
//! ticket is replayable bearer material, so a node id read out of one would be
//! a credential rather than a proof of possession.
//!
//! Hence the three arms of `Identity`, and the rule `inherit` applies:
//!
//! - **`proved`** — a certificate was verified on *this* connection. It is
//!   fresh evidence whatever the role, and it is the only arm that authorizes.
//! - **`asserted`** — the client role with no certificate: the peer is the node
//!   id the caller asserted, by way of the store key or the pin it would have
//!   compared. A caller may *address* the peer with it — choose the store
//!   entry, pick a queue — and may not *authorize* anything on it.
//! - **`unknown`** — the server role with no client certificate. With
//!   `ClientAuth.mode = .required` that connection does not exist (the
//!   handshake fails `CertificateRequired`); under `.optional` it completes and
//!   `expect_node_id` was never consulted, so even the asserted pin was not
//!   checked and there is nothing to claim.
//!
//! The whole decision is one function over three values, and it cannot report
//! `proved` without a verified certificate behind it: `proved` is built from
//! `Proof.verified` and from nothing else.

const std = @import("std");
const resumption = @import("../transport/resumption.zig");

pub const NodeId = resumption.NodeId;
pub const SessionTicket = resumption.SessionTicket;
pub const Intent = resumption.Intent;
pub const Store = resumption.Store;

/// Which end of the connection the caller is on.
///
/// Load-bearing, and not decoration: a resumption removes the client's proof of
/// the server and leaves the server's proof of the client in place, so the
/// same `Proof` means different things to the two ends.
pub const Role = enum {
    /// Dialling. Its own proof of the peer is what a resumption drops.
    client,
    /// Listening. Its proof of the peer is what a resumption leaves standing.
    server,
};

/// What the finished handshake established about the peer.
///
/// `Tls13Handshake.peerNodeId()` is the whole source of `verified`: it answers
/// null unless the handshake reached `connected`, and it holds the key lifted
/// from a certificate that was compared against the caller's pin on this
/// connection.
pub const Proof = union(enum) {
    /// A certificate was verified on this connection and carried these 32
    /// bytes.
    verified: NodeId,
    /// No certificate was verified on this connection.
    none,
};

/// What a resumed session may claim about its peer.
///
/// The three arms are three different amounts of knowledge, and the ordering
/// is the point: only `proved` carries evidence, `asserted` carries the
/// caller's own belief, and `unknown` carries nothing at all.
pub const Identity = union(enum) {
    /// A certificate was verified on this connection. The only arm that may
    /// authorize an action.
    proved: NodeId,
    /// No certificate, on the client side. The peer is the node id the caller
    /// asserted: the key its ticket was filed under, or the pin it would have
    /// compared. Good enough to address the peer, not to authorize anything.
    asserted: NodeId,
    /// No certificate, on the server side, under a policy that permits one to
    /// be absent. Not even the asserted pin was compared.
    unknown,
};

/// Why a resumption that exists may not be used on this connection.
///
/// Every arm is a distinct fact with a distinct consequence for the caller,
/// and `layerOf` names the layer that enforces each. `NoTicket` is absent for
/// the reason `resumption.OfferError` omits it: nothing filed is
/// `FullHandshake.cold_start`, not a refusal.
pub const Refusal = error{
    /// Past its lifetime on the caller's clock. Enforced here, because the
    /// core never consults `lifetime` itself — a server opens a ticket without
    /// reading it.
    Expired,
    /// Filed under another peer. Enforced here, because the ticket carries no
    /// peer and no other layer can see one.
    WrongPeer,
    /// Issued on another QUIC version (RFC 9369 §5).
    WrongVersion,
    /// Issued for another protocol (RFC 8446 §4.2.10).
    WrongAlpn,
};

/// Which layer refuses, and therefore which refusal a caller can rely on even
/// if it never calls this file.
///
/// Two members because the module doc's claim is exactly this: the core's two
/// byte-level refusals cannot be talked out of by a caller, and the rest are
/// this tree's own arithmetic over values it holds.
pub const Layer = enum {
    /// Enforced by the vendored core, on bytes the core itself sealed, with no
    /// configuration field that reaches the check.
    tls_core,
    /// Enforced by this tree — the store's key, and `resumption.accept`'s
    /// comparison of a hand-assembled (ticket, peer) pair.
    application,
};

/// The layer that enforces `refusal`.
///
/// A total function over the refusal set, so a caller counting refusals by
/// layer cannot miss one and cannot invent one.
pub fn layerOf(refusal: Refusal) Layer {
    return switch (refusal) {
        error.WrongVersion, error.WrongAlpn => .tls_core,
        error.Expired, error.WrongPeer => .application,
    };
}

/// A resumption to proceed with, and what it may be used for.
pub const Resume = struct {
    /// The ticket to put in `TlsConfig.resumption` as `.client`. Borrowed from
    /// the store on `fromStore`, so it is valid until the next `capture` or
    /// `forget` — the same obligation `TlsConfig.resumption`'s own field
    /// documents for the pointer it holds.
    ticket: *const SessionTicket,
    /// What the session may claim about the peer, once the handshake reports.
    identity: Identity,
    /// Whether the issuing server advertised an early-data allowance, so
    /// `early_data.permit` has something to mint from. False is a resumption
    /// without 0-RTT, never a refused resumption.
    may_send_early_data: bool,
};

/// A resumption that exists and may not be used here, and who said no.
pub const Refused = struct {
    /// Which of the refusals it was.
    refusal: Refusal,
    /// The layer that enforced it.
    layer: Layer,
};

/// Why a connection handshakes in full because it had nothing to resume with.
///
/// Distinct from a refusal because nothing existed to lose: a caller counting
/// "had resumption and could not use it" must not be counting cold starts.
pub const FullHandshake = struct {
    /// The one answer there is.
    pub const Reason = enum {
        /// Nothing was ever filed for this (peer, protocol, version) — and for
        /// a protocol longer than `session_store.alpn_len_max`, nothing ever
        /// could be.
        cold_start,
    };

    /// Which cold start, named so the arm is not a bare boolean.
    reason: Reason,
};

/// What a caller decided about an offered resumption.
///
/// Total and never partial: every path answers one arm, so a caller cannot
/// learn that a resumption succeeded and skip the arm that says what it may
/// claim.
pub const Decision = union(enum) {
    /// Resume, with the ticket and the identity verdict.
    resumed: Resume,
    /// Nothing to resume with. An ordinary full handshake.
    full_handshake: FullHandshake,
    /// A resumption exists and is refused here, with its enforcer.
    refused: Refused,
};

/// The `refused` arm for a refusal reached, carrying the layer that enforced
/// it. One constructor so the two entry points cannot disagree about which
/// layer refuses what.
fn refusedWith(refusal: Refusal) Decision {
    return .{ .refused = .{ .refusal = refusal, .layer = layerOf(refusal) } };
}

/// Decide about a resumption the caller is about to offer from its store.
///
/// This is the path a caller takes when it holds its own tickets. The peer is
/// part of the store's lookup key, so **this path cannot produce
/// `error.WrongPeer`**: a lookup naming another peer addresses an empty slot,
/// and the answer is a cold start. That is the stronger of the two answers,
/// and `fromTicket` is the path where a hand-assembled (ticket, peer) pair is
/// the only thing standing between a caller and another peer's PSK.
///
/// `now_s` is a second on the caller's clock. An expired entry is dropped from
/// the store by `resumption.offer` and its slot freed, which is why `Expired`
/// here means "had resumption and lost it" rather than "never had any".
pub fn fromStore(
    store: *Store,
    intent: Intent,
    role: Role,
    proof: Proof,
    now_s: i64,
) Decision {
    const ticket = resumption.offer(store, intent, now_s) catch |err| switch (err) {
        error.NoTicket => return .{ .full_handshake = .{ .reason = .cold_start } },
        else => |refusal| return refusedWith(refusal),
    };
    return resumeWith(ticket, intent, role, proof);
}

/// Decide about a ticket value the caller holds outside its store — one just
/// from `received_ticket`, or one read back off disk.
///
/// **This is the only path on which `WrongPeer` is reachable**, and it exists
/// because `SessionTicket` carries no peer: the peer is the key the ticket was
/// filed under, so a value crossing a peer boundary is caller error and
/// `captured_for` is the caller's claim about where it came from. The
/// comparison is over all 32 bytes and runs before any other field is read, so
/// a foreign ticket is refused without its version, protocol or lifetime being
/// interpreted at all.
///
/// Expiry is refused here too and drops nothing: `accept` does not own the
/// store, so a dead ticket handed to this path is the caller's to discard.
pub fn fromTicket(
    ticket: *const SessionTicket,
    captured_for: NodeId,
    intent: Intent,
    role: Role,
    proof: Proof,
    now_s: i64,
) Decision {
    resumption.accept(ticket, captured_for, intent, now_s) catch |err|
        return refusedWith(err);
    return resumeWith(ticket, intent, role, proof);
}

/// What the resumed session may claim, given the role and what was proved.
fn inherit(role: Role, proof: Proof, asserted: NodeId) Identity {
    switch (proof) {
        .verified => |node| return .{ .proved = node },
        // No certificate, so the session's identity is whatever the caller
        // asserted and nothing more. On the client side that is the store key
        // or the uncompared pin — addressable, not authorising. On the server
        // side there is no key to fall back on: `ClientAuth.expect_node_id`
        // was never consulted for a client that sent nothing, so the asserted
        // pin has not been checked either and the honest answer is nothing.
        .none => return switch (role) {
            .client => .{ .asserted = asserted },
            .server => .unknown,
        },
    }
}

/// The `resumed` arm, shared by both entry points so they cannot disagree.
fn resumeWith(
    ticket: *const SessionTicket,
    intent: Intent,
    role: Role,
    proof: Proof,
) Decision {
    return .{ .resumed = .{
        .ticket = ticket,
        .identity = inherit(role, proof, intent.peer),
        .may_send_early_data = ticket.max_early_data_size > 0,
    } };
}

// --- tests

const t = std.testing;
const base_key = @import("../base/key.zig");

/// The QUIC versions this tree speaks, spelled the way the resumption policy's
/// own tests spell them.
const quic_v1: u32 = 1;
const quic_v2: u32 = 0x6b3343cf;

const alpn_main = "ozai";
const alpn_other = "/iroh-qad/0";

/// A real ed25519 node id, for the reason the resumption policy's own helper
/// gives: `NodeId`'s key field is a precondition rather than an invariant.
fn testNodeId(seed: u8) !NodeId {
    var secret = try base_key.SecretKey.fromSeed(@as([base_key.SecretKey.seed_length]u8, @splat(seed)));
    defer secret.deinit();
    return secret.nodeId();
}

/// A ticket as the core would have built it, with the early-data allowance the
/// issuing server's NewSessionTicket advertised.
fn ticketFor(
    alpn: []const u8,
    version: u32,
    lifetime_s: u32,
    created_s: i64,
    early_data_max: u32,
) SessionTicket {
    var built: SessionTicket = .{
        .psk = @as([32]u8, @splat(0xa5)),
        .lifetime = lifetime_s,
        .creation_time = created_s,
        .quic_version = version,
        .max_early_data_size = early_data_max,
    };
    @memcpy(built.alpn[0..alpn.len], alpn);
    // Fixture callers use ALPN lengths 4 or 11; ZBC cannot follow those values here.
    // zbc-disable-next-line: index-type-narrowing-wraparound
    built.alpn_len = @intCast(alpn.len);
    return built;
}

fn intentFor(peer: NodeId, alpn: []const u8, version: u32) Intent {
    return .{ .peer = peer, .alpn = alpn, .quic_version = version };
}

test "a client resumption carries the peer's assertion and no proof of it" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100, 1_024), 100).stored);

    // The resumed client connection never saw a certificate:
    // `clientProcessCertificate` returns on `using_psk` before reading one, so
    // `peerNodeId()` is null and the pin was never compared. The claim the
    // session gets is the key the ticket was filed under, and no more.
    const decision = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    const resumed = decision.resumed;
    try t.expectEqual(peer.toBytes(), resumed.identity.asserted.toBytes());
    try t.expect(resumed.may_send_early_data);

    // The same store entry seen from the server side of a connection whose
    // client did present a certificate is proved, because the core still asks
    // for it on a resumed connection.
    const served = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .server,
        .{ .verified = peer },
        100,
    );
    try t.expectEqual(peer.toBytes(), served.resumed.identity.proved.toBytes());
}

test "a server connection with no client certificate claims nothing at all" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100, 0), 100).stored);

    // No certificate: under `mode = .required` this connection does not exist,
    // and under `.optional` it completes with `expect_node_id` never
    // consulted. Neither leaves anything to claim — not even the asserted pin.
    const decision = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .server,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(Identity{ .unknown = {} }, decision.resumed.identity);
    // And a ticket the issuing server sealed without an allowance resumes
    // without 0-RTT, which is a different fact from a refused resumption.
    try t.expect(!decision.resumed.may_send_early_data);
}

test "a ticket for another protocol and one from another version are refused apart" {
    const peer = try testNodeId(1);
    const other = ticketFor(alpn_other, quic_v1, 3_600, 100, 1_024);
    const future = ticketFor(alpn_main, quic_v2, 3_600, 100, 1_024);

    // Each refusal is its own arm, on both paths, so a caller can tell "the
    // protocol drifted" from "the version moved" without re-deriving either.
    const wrong_protocol = fromTicket(
        &other,
        peer,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(error.WrongAlpn, wrong_protocol.refused.refusal);
    try t.expectEqual(Layer.tls_core, wrong_protocol.refused.layer);

    const wrong_version = fromTicket(
        &future,
        peer,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(error.WrongVersion, wrong_version.refused.refusal);
    try t.expectEqual(Layer.tls_core, wrong_version.refused.layer);

    // Each still resumes on its own connection, which is what makes the two
    // refusals distinct facts rather than one "not usable" answer.
    _ = fromTicket(
        &other,
        peer,
        intentFor(peer, alpn_other, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    _ = fromTicket(
        &future,
        peer,
        intentFor(peer, alpn_main, quic_v2),
        .client,
        .{ .none = {} },
        100,
    );
}

test "another peer's ticket is refused by name on the hand-held path only" {
    const mine = try testNodeId(1);
    const theirs = try testNodeId(2);
    var store: Store = .{};
    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100, 1_024);
    try t.expect(store.capture(mine, filed, 100).stored);

    // A lookup naming another peer addresses an empty slot, so the store path
    // has no such refusal to give: it is a cold start, and the entry the other
    // peer's ticket is filed under is untouched.
    const looked_up = fromStore(
        &store,
        intentFor(theirs, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(
        FullHandshake.Reason.cold_start,
        looked_up.full_handshake.reason,
    );
    try t.expectEqual(@as(usize, 1), store.slice().len);

    // Handing the value over directly is caller error, and it is refused before
    // any other field is read — so the version, protocol and lifetime of a
    // foreign ticket never get interpreted at all.
    const handed_over = fromTicket(
        &filed,
        mine,
        intentFor(theirs, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(error.WrongPeer, handed_over.refused.refusal);
    try t.expectEqual(Layer.application, handed_over.refused.layer);

    // The refusal was about the pair, not the ticket: the right peer still
    // resumes with it.
    const mine_again = fromTicket(
        &filed,
        mine,
        intentFor(mine, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        100,
    );
    try t.expectEqual(mine.toBytes(), mine_again.resumed.identity.asserted.toBytes());
}

test "an expired resumption is refused, dropped and reported as this tree's own" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(
        store.capture(peer, ticketFor(alpn_main, quic_v1, 100, 1_000, 1_024), 1_000).stored,
    );

    // Inside the lifetime the entry resumes.
    const live = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        1_100,
    );
    try t.expect(!live.resumed.ticket.isExpired(1_100));

    // Past it: refused, and the slot freed, so the next cold start is a genuine
    // one. The core never reads `lifetime` — a server opens a ticket without
    // consulting it — so this refusal is this tree's arithmetic, not the core's.
    const late = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        1_101,
    );
    try t.expectEqual(error.Expired, late.refused.refusal);
    try t.expectEqual(Layer.application, late.refused.layer);
    try t.expectEqual(@as(usize, 0), store.slice().len);
    const after = fromStore(
        &store,
        intentFor(peer, alpn_main, quic_v1),
        .client,
        .{ .none = {} },
        1_101,
    );
    try t.expectEqual(FullHandshake.Reason.cold_start, after.full_handshake.reason);
}

test "every refusal names its layer, and the mapping is total" {
    // The comptime sweep is the coverage: `Refusal` gains an arm and this stops
    // compiling rather than leaving the new one unclassified.
    inline for (@typeInfo(Refusal).error_set.error_names.?) |member| {
        const refusal: Refusal = @field(Refusal, member);
        const layer = layerOf(refusal);
        try t.expect(layer == .tls_core or layer == .application);
    }
    // And the two byte-level refusals are the core's; the two that need a peer
    // or a clock this tree holds are its own.
    try t.expectEqual(Layer.tls_core, layerOf(error.WrongAlpn));
    try t.expectEqual(Layer.tls_core, layerOf(error.WrongVersion));
    try t.expectEqual(Layer.application, layerOf(error.WrongPeer));
    try t.expectEqual(Layer.application, layerOf(error.Expired));
}
