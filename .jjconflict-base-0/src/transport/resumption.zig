//! When a resumption is offered, when it is accepted, and when it is refused.
//!
//! `session_store.zig` owns the tickets — the bound, the allocator-free
//! layout, the (peer, ALPN, QUIC version) keying — and answers a lookup with
//! a ticket or with null. Null does not say why, and "why not" is four
//! different outcomes with four different consequences, so this file sits on
//! the store and names them. Everything here is pure over bytes: no socket,
//! no clock read, no allocator. `now_s` is a second on the caller's own
//! clock, the same one the core stamped `creation_time` with.
//!
//! # Offered, accepted, refused
//!
//! - **Offered.** `offer` answers which ticket a connection to a peer may
//!   resume with: the pointer to put in `TlsConfig.resumption` as
//!   `.client`. It borrows the store exactly the way `take`'s pointer does,
//!   so it is valid until the next `capture` or `forget` on it.
//! - **Accepted.** `accept` checks an explicit ticket value — one the caller
//!   holds outside the store, e.g. fresh from `received_ticket` — against
//!   the connection about to be attempted. It answers void, not a boolean,
//!   so there is no forgotten check that defaults to resuming.
//! - **Refused.** Every other outcome is a named error, and the names are
//!   the point: expiry, a foreign protocol and a foreign version demand
//!   different things of the caller, so a caller must be able to tell them
//!   apart without re-deriving them.
//!
//! # The four decisions
//!
//! **Expired: refused, and dropped.** An entry past its lifetime is removed
//! and `offer` answers `Expired`. Offering it would hand the core a PSK the
//! peer has stopped accepting, which costs an extra flight and a
//! `tryProcessPsk` binder-failure log to arrive where a full handshake would
//! have arrived directly. Dropping frees the slot, exactly as `take` does.
//! This is not the same failure as never having had a ticket (`NoTicket`,
//! the ordinary cold start): one had resumption and lost it, the other never
//! did, and a caller counting either wants them separate.
//!
//! **Wrong ALPN: refused, but kept.** The entry stays filed — it is still
//! the right ticket for its own protocol — and `offer` answers `WrongAlpn`.
//! RFC 8446 §4.2.10 binds the 0-RTT parameters to the connection that
//! established the PSK, and the core enforces it twice: `resumableTicket`
//! will not offer a ticket the proposal no longer names, and `tryProcessPsk`
//! withholds early data when the sealed name differs from the selected one.
//! Refusing here rather than handing over a ticket the core would neuter
//! keeps the refusal legible instead of spreading it across a binder log.
//!
//! **Wrong version: refused, but kept.** Same shape, stronger rule: RFC 9369
//! §5 is a MUST NOT in both directions, and both ends compare against the
//! version the resuming connection *starts* on (`original_version`), not the
//! one it negotiates. A version-1 ticket is therefore still the right ticket
//! while this connection starts on version 1, even if it negotiates version
//! 2 — which is why the entry is kept and only this connection is refused.
//!
//! **Both differ: the version is named.** A same-peer entry that matches
//! neither the version nor the protocol is `WrongVersion`, because the
//! version is the refusal the core would reach first: `resumableTicket`
//! tests the version before the ALPN, and `tryProcessPsk` rejects the sealed
//! version before it ever compares names. Naming the second failure would
//! describe a check the core never gets to.
//!
//! # Why cross-peer use is impossible, not merely checked
//!
//! Through `offer` there is no check that could be forgotten because there
//! is no check at all: the peer is part of the lookup key. `offer` scans for
//! a `Key.matches` over all three fields with the peer compared over its
//! full 32 bytes, and the only pointer it can return borrows the entry that
//! matched. A ticket filed under peer A is not a candidate for a lookup
//! naming peer B — it addresses a different, empty slot — so no parameter,
//! flag or fallback exists that would hand B's connection A's PSK. That is
//! why `OfferError` has no `WrongPeer` member: the store path cannot produce
//! one, and the type says so.
//!
//! `WrongPeer` exists only on `accept`, the path where the caller assembles
//! a (ticket, peer) pair by hand from a ticket held outside the store. A
//! `SessionTicket` carries no peer — the peer is the key it was filed under,
//! not a field inside it — so a value crossing a peer boundary is caller
//! error, and `accept` refuses it before reading any other field.

const std = @import("std");
const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");
const store_mod = @import("session_store.zig");

/// The peer identity a ticket is filed under and offered to.
pub const NodeId = base_addr.NodeId;
/// The vendored ticket, re-exported so a caller wiring `offer` into a
/// `TlsConfig` needs one import rather than two.
pub const SessionTicket = store_mod.SessionTicket;
/// The store this policy sits on, re-exported for the same reason.
pub const Store = store_mod.Store;

/// The connection a ticket is about to be offered on.
///
/// Three values and no borrows beyond the protocol name, which the caller
/// owns: `offer` reads it and keeps nothing. The name must be the whole
/// protocol RFC 8446 §4.2.10 compares — a prefix is a different protocol —
/// and the version must be the one the connection starts on
/// (`original_version`), not the one it may negotiate.
pub const Intent = struct {
    /// The peer the handshake will pin, the same 32 bytes the store files
    /// under.
    peer: NodeId,
    /// The protocol the connection will propose, whole.
    alpn: []const u8,
    /// The QUIC version the connection's first flight is built with.
    quic_version: u32,
};

/// Why an explicit ticket value may not be used on an intended connection.
///
/// No `NoTicket` member: `accept` is handed a ticket, so "nothing filed" is
/// unrepresentable — that outcome belongs to `offer` alone.
pub const Refusal = error{
    /// The ticket is past its lifetime on the caller's clock. Dead
    /// everywhere, not just here: the caller keeps nothing by holding it.
    Expired,
    /// The ticket was captured for another peer. Checked before anything
    /// else: a ticket for another peer is not ours to interpret further.
    WrongPeer,
    /// The ticket was issued on another QUIC version (RFC 9369 §5). Alive
    /// but not for this connection; the caller keeps the entry.
    WrongVersion,
    /// The ticket was issued for another protocol (RFC 8446 §4.2.10). Alive
    /// but not for this connection; the caller keeps the entry.
    WrongAlpn,
};

/// Why no ticket is offered for an intended connection.
///
/// No `WrongPeer` member, and the absence is the point (see the module doc):
/// the store path looks tickets up under the intent's peer, so another
/// peer's ticket is never a candidate and there is no such refusal to
/// report. `NoTicket` is the ordinary cold start — a full handshake, not a
/// failure — while the other three name a resumption that existed and could
/// not be used.
pub const OfferError = error{
    /// The entry for this triple is past its lifetime. Dropped from the
    /// store, and the slot freed, exactly as `take` would have done.
    Expired,
    /// This peer has tickets, but none on this QUIC version.
    WrongVersion,
    /// This peer resumes on this QUIC version, but for other protocols.
    WrongAlpn,
    /// Nothing is filed for this triple — and, for a protocol longer than
    /// the store can key on, nothing ever could be.
    NoTicket,
};

/// The ticket `intent` may resume with, or the named reason it may not.
///
/// The scan is one pass over at most `max_entries` entries. An exact,
/// live hit returns the entry's ticket; an exact, expired hit is dropped
/// and refused; otherwise the widest true statement about same-peer entries
/// is reported — same version first (a live resumption on this connection's
/// version, for other protocols), then same peer (known, but not on this
/// version), then nothing.
///
/// A protocol longer than `alpn_len_max` is `NoTicket` without probing: the
/// store holds no key for it, so no entry can match. That is a storage bound
/// surfacing as a lookup miss, not a security check.
pub fn offer(store: *Store, intent: Intent, now_s: i64) OfferError!*const SessionTicket {
    if (intent.alpn.len > store_mod.alpn_len_max) return error.NoTicket;
    var saw_peer = false;
    var saw_version = false;
    for (store.slice()) |*entry| {
        if (!std.mem.eql(u8, &entry.key.peer.toBytes(), &intent.peer.toBytes())) continue;
        saw_peer = true;
        const version_ok = entry.key.quic_version == intent.quic_version;
        const alpn_ok = std.mem.eql(u8, entry.key.alpnSlice(), intent.alpn);
        if (version_ok and alpn_ok) {
            if (entry.ticket.isExpired(now_s)) {
                const key = entry.key;
                // The call first, the claim second: an assert holding the
                // only call would vanish where safety is off and keep the
                // dead entry.
                const dropped = store.forget(key);
                std.debug.assert(dropped);
                return error.Expired;
            }
            return &entry.ticket;
        }
        if (version_ok) saw_version = true;
    }
    if (saw_version) return error.WrongAlpn;
    if (saw_peer) return error.WrongVersion;
    return error.NoTicket;
}

/// Whether an explicit ticket value may be used on an intended connection.
///
/// `captured_for` is the peer the ticket was captured for — the key it was
/// filed under, or the peer `received_ticket` arrived from — because the
/// ticket itself carries no peer. The order is identity, then liveness, then
/// the core's own check order: a foreign ticket is refused before its other
/// fields are read, a dead ticket is dead everywhere (so expiry precedes the
/// two keep-the-entry refusals), and version precedes ALPN because
/// `resumableTicket` tests them in that order.
///
/// A ticket naming a protocol longer than the selection width matches
/// nothing and is `WrongAlpn`: the core compares whole names, so a name it
/// cannot hold whole is a protocol no proposal can name back.
pub fn accept(
    ticket: *const SessionTicket,
    captured_for: NodeId,
    intent: Intent,
    now_s: i64,
) Refusal!void {
    if (!std.mem.eql(u8, &captured_for.toBytes(), &intent.peer.toBytes())) return error.WrongPeer;
    if (ticket.isExpired(now_s)) return error.Expired;
    if (ticket.quic_version != intent.quic_version) return error.WrongVersion;
    if (@as(usize, ticket.alpn_len) > ticket.alpn.len) return error.WrongAlpn;
    if (!std.mem.eql(u8, ticket.getAlpn(), intent.alpn)) return error.WrongAlpn;
}

// --- tests

const t = std.testing;

/// The QUIC versions this tree speaks, spelled the way
/// `session_store.zig`'s own tests spell them: the vendored `protocol.zig`
/// constants, where version 2 is the whole reason the version is in the key.
const quic_v1: u32 = 1;
const quic_v2: u32 = 0x6b3343cf;

/// The two protocols one identity speaks: the main ALPN and the QAD one
/// beside it (`router/alpn_table.zig`), which is why a ticket must name its
/// own.
const alpn_main = "ozai";
const alpn_other = "/iroh-qad/0";

/// The peer a seed names: a real ed25519 node id, because `NodeId`'s key
/// field is a precondition rather than an invariant and a struct literal
/// would test the policy against a value the identity type never promised.
fn testNodeId(seed: u8) !NodeId {
    var secret = try base_key.SecretKey.fromSeed([_]u8{seed} ** base_key.SecretKey.seed_length);
    defer secret.deinit();
    return secret.nodeId();
}

/// A ticket as the core would have built it: a PSK, a creation stamp on the
/// caller's clock, a lifetime, the protocol the issuing connection
/// negotiated, and the version it ended on.
fn ticketFor(
    alpn: []const u8,
    version: u32,
    lifetime_s: u32,
    created_s: i64,
) SessionTicket {
    var built: SessionTicket = .{
        .psk = [_]u8{0xa5} ** 32,
        .lifetime = lifetime_s,
        .creation_time = created_s,
        .quic_version = version,
    };
    @memcpy(built.alpn[0..alpn.len], alpn);
    built.alpn_len = @intCast(alpn.len);
    return built;
}

fn intentFor(peer: NodeId, alpn: []const u8, version: u32) Intent {
    return .{ .peer = peer, .alpn = alpn, .quic_version = version };
}

test "the filed ticket is offered to its own peer and accepted for its connection" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100);
    try t.expect(store.capture(peer, filed, 100).stored);

    // Offered: the pointer names the filed PSK, so wiring it into
    // `TlsConfig.resumption` as `.client` resumes this peer's ticket.
    const offered = try offer(&store, intentFor(peer, alpn_main, quic_v1), 100);
    try t.expectEqual(filed.psk, offered.psk);

    // Accepted: the explicit value checks out against the same connection.
    try accept(offered, peer, intentFor(peer, alpn_main, quic_v1), 100);
}

test "another peer's ticket is never offered, and presenting it names the peer" {
    const first = try testNodeId(1);
    const second = try testNodeId(2);
    var store: Store = .{};
    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100);
    try t.expect(store.capture(first, filed, 100).stored);

    // A lookup naming the second peer cannot see the first peer's entry: the
    // peer is part of the key, so this addresses a different, empty slot.
    // The answer is cold-start NoTicket, never the wrong peer's PSK.
    const missed = offer(&store, intentFor(second, alpn_main, quic_v1), 100);
    try t.expectError(error.NoTicket, missed);
    try t.expectEqual(@as(usize, 1), store.slice().len);

    // The explicit-value path, where the caller assembles the pair by hand,
    // refuses it and names the dimension that failed.
    const pair_refusal = accept(&filed, first, intentFor(second, alpn_main, quic_v1), 100);
    try t.expectError(error.WrongPeer, pair_refusal);
    // And the right peer still passes: the refusal was about the pair, not
    // the ticket.
    try accept(&filed, first, intentFor(first, alpn_main, quic_v1), 100);
}

test "a ticket offered for another protocol is refused with its own error" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);

    // The entry is kept — it is still the right ticket for its own
    // protocol — but this connection is refused, on both paths.
    try t.expectError(error.WrongAlpn, offer(&store, intentFor(peer, alpn_other, quic_v1), 100));
    try t.expectEqual(@as(usize, 1), store.slice().len);
    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100);
    const refusal = accept(&filed, peer, intentFor(peer, alpn_other, quic_v1), 100);
    try t.expectError(error.WrongAlpn, refusal);

    // A prefix is a different protocol too: RFC 8446 §4.2.10 compares whole
    // names, so `ozai` does not name `ozai-blobs-2`'s ticket.
    const longer = ticketFor("ozai-blobs-2", quic_v1, 3_600, 100);
    const prefix_refusal = accept(&longer, peer, intentFor(peer, "ozai", quic_v1), 100);
    try t.expectError(error.WrongAlpn, prefix_refusal);

    // A length past the selection width matches nothing rather than reading
    // past the name: fail closed on the corrupt value instead of panicking
    // in `getAlpn`.
    var corrupt = ticketFor(alpn_main, quic_v1, 3_600, 100);
    corrupt.alpn_len = corrupt.alpn.len + 1;
    const corrupt_refusal = accept(&corrupt, peer, intentFor(peer, alpn_main, quic_v1), 100);
    try t.expectError(error.WrongAlpn, corrupt_refusal);
}
test "a ticket from another QUIC version is refused with its own error" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v2, 3_600, 100), 100).stored);

    // RFC 9369 §5 in both directions, and the entry survives: it is still
    // the right ticket for a connection starting on version 2.
    const v1 = intentFor(peer, alpn_main, quic_v1);
    try t.expectError(error.WrongVersion, offer(&store, v1, 100));
    try t.expectEqual(@as(usize, 1), store.slice().len);
    const filed = ticketFor(alpn_main, quic_v2, 3_600, 100);
    const stale_refusal = accept(&filed, peer, v1, 100);
    try t.expectError(error.WrongVersion, stale_refusal);

    // The version the entry was issued for still offers and accepts.
    _ = try offer(&store, intentFor(peer, alpn_main, quic_v2), 100);
    try accept(&filed, peer, intentFor(peer, alpn_main, quic_v2), 100);
}

test "an expired ticket is refused and its slot freed" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 100, 1_000), 1_000).stored);

    // Inside the lifetime, including its last second, the ticket offers.
    _ = try offer(&store, intentFor(peer, alpn_main, quic_v1), 1_100);
    try t.expectEqual(@as(usize, 1), store.slice().len);

    // One second past it the entry is gone and the refusal says expired —
    // not "nothing filed" and not a wrong-dimension error. Offering a PSK
    // the peer has stopped accepting would cost a flight and a binder log
    // to arrive where a full handshake arrives directly.
    const late = intentFor(peer, alpn_main, quic_v1);
    try t.expectError(error.Expired, offer(&store, late, 1_101));
    try t.expectEqual(@as(usize, 0), store.slice().len);
    const dead = ticketFor(alpn_main, quic_v1, 100, 1_000);
    const dead_refusal = accept(&dead, peer, late, 1_101);
    try t.expectError(error.Expired, dead_refusal);

    // The freed slot files again immediately.
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 100, 1_101), 1_101).stored);
}

test "when protocol and version both differ, the version is named" {
    const peer = try testNodeId(1);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v2, 3_600, 100), 100).stored);

    // Nothing here matches either dimension. The version is reported because
    // it is the refusal the core reaches first: `resumableTicket` tests the
    // version before the ALPN, so naming the protocol would describe a check
    // the core never gets to.
    const intent = intentFor(peer, alpn_other, quic_v1);
    try t.expectError(error.WrongVersion, offer(&store, intent, 100));
    const filed = ticketFor(alpn_main, quic_v2, 3_600, 100);
    try t.expectError(error.WrongVersion, accept(&filed, peer, intent, 100));
}

test "an empty store and an unholdable protocol are an ordinary full handshake" {
    const peer = try testNodeId(1);
    var store: Store = .{};

    // Nothing filed for anything: every dimension misses, and the answer is
    // the cold start rather than any of the three refusals above.
    try t.expectError(error.NoTicket, offer(&store, intentFor(peer, alpn_main, quic_v1), 100));
    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100);
    const foreign = try testNodeId(9);
    const foreign_refusal = accept(&filed, foreign, intentFor(peer, alpn_main, quic_v1), 100);
    try t.expectError(error.WrongPeer, foreign_refusal);

    // A protocol longer than the store can key on can never be filed, so it
    // can never match: same cold start, without probing.
    const too_long = "z" ** (store_mod.alpn_len_max + 1);
    try t.expectError(error.NoTicket, offer(&store, intentFor(peer, too_long, quic_v1), 100));
}
