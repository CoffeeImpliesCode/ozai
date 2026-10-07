//! One TLS session ticket per (peer identity, ALPN, QUIC version), held by
//! value in a fixed table that cannot allocate and cannot forget what it owns.
//!
//! The store's whole reason to exist is that ownership property. A store that
//! allocated per entry would have entries pointing at heap the caller had to
//! free, and the question "who owns this ticket" would have an answer that
//! differs between the entry that was filed and the one that replaced it. Here
//! every byte of every ticket lives inside the `Store` value, so a `Store` is
//! free exactly when it goes out of scope, a copied `Store` is an independent
//! snapshot, and there is no code path that can leak one.
//!
//! # What is read off the peer at capture time
//!
//! **All three, and all three at capture, never at resume.** `capture` is
//! handed a `SessionTicket` the core built, and the key is built from what that
//! ticket records about the connection it came from:
//!
//! - **Peer identity.** The 32 bytes of the node's ed25519 public key. This is
//!   the same key `TlsConfig.expect_peer_node_id` and `ClientAuth.expect_node_id`
//!   pin, so the key this store files under is the key the handshake proved.
//! - **ALPN.** `SessionTicket.getAlpn`, the protocol the issuing connection
//!   *negotiated*, which is `Tls13Handshake.selected_alpn` rather than the
//!   config's first entry: `parseNewSessionTicket` reads the selection rather
//!   than the fallback so a connection that selected nothing records nothing.
//! - **QUIC version.** `SessionTicket.quic_version`, the version the issuing
//!   connection *ended on*. RFC 9369 §5 makes this load-bearing in both
//!   directions: a version-1 ticket may not open a version-2 connection, and a
//!   client whose first flight was version 1 may still resume a version-1 ticket
//!   while negotiating version 2.
//!
//! Reading them at capture is the only correct instant, and the alternative is
//! worse than a weaker key. `resumableTicket` compares the ticket's version
//! against the *next* connection's `original_version` and its ALPN against the
//! *next* connection's proposal, so a key built at resume would be built out of
//! the thing being checked. `tls13.Tls13Handshake.resumableTicket` is the code
//! that answers "may this ticket be offered", and it does so by comparing those
//! two fields; a store that filed under anything else would be handing the core
//! a ticket it cannot offer, and the core's answer would be a full handshake
//! that looks like a bug in this file.
//!
//! ## Why a weaker key is wrong
//!
//! - **Peer alone.** `ozai` speaks several ALPNs on one connection — the
//!   router registers one handler per protocol and `qad_alpn` is a second one
//!   beside them (`router/alpn_table.zig`). Keyed on the peer alone, a ticket
//!   issued for `ozai` is offered for `qad_alpn`, or the reverse, and the two
//!   collide: the second capture evicts the first and the peer alternates
//!   between resuming and not. `parseNewSessionTicket` copies the negotiated
//!   name in for exactly this reason.
//! - **Peer and ALPN, without the version.** RFC 9369 §5 is a MUST NOT across
//!   versions, and `resumableTicket` returns null for the mismatch — so the
//!   entry is not merely unhelpful, it is a ticket that costs a full handshake
//!   every time and looks like the peer changed its mind.
//! - **Peer, ALPN and version, but with the ALPN truncated to fit.** RFC 8446
//!   §4.2.10's comparison is equality over names, and the core compares whole
//!   names (`proposalHoldsProtocol`). A prefix is a different protocol, so a
//!   store that matched prefixes would file `ozai-blobs-2` under `ozai` and
//!   offer it to a client proposing `ozai` alone. `ALPN` here is a fixed
//!   `[negotiated_alpn_len_max]u8` with a length, exactly the ticket's own
//!   shape, so a name that does not fit is refused rather than shortened.
//! - **Socket address instead of peer identity.** A peer's addresses churn with
//!   its NAT; `holepunch_target` spends a whole round learning one. A ticket
//!   keyed on an address is a ticket that stops being usable when the mapping
//!   changes, which is precisely when resumption is worth having.
//!
//! # Expiry: drop it, do not hand it out
//!
//! **`resume` drops an expired entry and answers null.** `SessionTicket.isExpired`
//! is the core's own test and is not reimplemented here; the core documents that
//! a zero `lifetime` — the default for a ticket nobody recorded a lifetime on
//! — makes a ticket expired one second past its creation, which is the safe
//! answer.
//!
//! Handing back an expired ticket would be worse than holding none. The client
//! would offer a PSK the server will reject, `tryProcessPsk` logs
//! "PSK binder verification failed, falling back to full handshake", and the
//! connection costs an extra flight and a log line to arrive where a full
//! handshake would have arrived directly. Dropping costs nothing: the entry is
//! removed and the slot freed, so the next capture has room.
//!
//! Expiry is measured in the same seconds the ticket records, on the caller's
//! own clock — `Tls13Handshake.step`'s `now_s`, which
//! `docs/PLAN.md`'s "One divergence to know before touching TLS" section says is
//! only ever differenced and never compared against an epoch. Every `now_s`
//! here comes from the same source as the one the core stamped `creation_time`
//! with, which is what makes the subtraction meaningful.
//!
//! # ALPN mismatch: refused by construction, not by a check
//!
//! **The gate lives in the vendored core, in two places, and this store adds
//! none.** `Tls13Handshake.resumableTicket` answers null unless the ticket's
//! version equals `original_version` and the client's own proposal still holds
//! the ticket's ALPN, so a ticket for another protocol is never offered and the
//! connection is a full handshake rather than a failed one. On the server,
//! `tryProcessPsk` computes `alpn_matches` against the protocol it just
//! selected and sets `zero_rtt_accepted = early_data_offered and alpn_matches`.
//!
//! It is closed by construction because the core holds no boolean a caller sets
//! to allow early data. `zero_rtt_accepted` is written in exactly two places,
//! both initialised to false in the constructors and assigned from
//! `early_data_offered and alpn_matches` — so it is false until a binder has
//! verified *and* the sealed name matches, and there is no configuration field,
//! setter or override that reaches it. A peer presenting a ticket issued for a
//! different ALPN therefore resumes without early data, and this store cannot
//! change that: it hands over bytes the core sealed and the core decides.
//!
//! What this store does do is refuse to *file* a ticket whose ALPN is longer
//! than the core can hold, which is a storage bound and not a security check.
//!
//! # At the bound
//!
//! `max_entries` is a refusal, and it refuses the newcomer: `capture` answers
//! `Stored.refused` with the key that did not fit and nothing in the table
//! moves. Evicting an existing entry would be worse in a way specific to
//! tickets — every entry is a resumption for a peer that has already paid for
//! a handshake, and a store that silently drops one drops a peer's 0-RTT with
//! no signal. The failure is loud and the peer keeps its full-handshake path;
//! the eviction is silent and the peer does not even learn why.
//!
//! A full table is therefore a *silent* loss of nothing: the peer whose ticket
//! did not fit still resumes through a full handshake, exactly as it would
//! with no store at all, and `Stored.refused` names it for a caller that wants
//! to log or to bound its own peer count.

const std = @import("std");
const quic = @import("quic");
const base_addr = @import("../base/addr.zig");

const tls13 = quic.tls13;

const NodeId = base_addr.NodeId;

/// The vendored ticket. Re-exported under this file's own name so a caller
/// building a `TlsConfig` needs one import rather than two.
pub const SessionTicket = tls13.SessionTicket;
/// The vendored `Resumption` union. Re-exported for the same reason, and it is
/// the whole of what this file hands back: a client resumes with a ticket, a
/// server seals and opens tickets under a key, and this store is the client
/// half. See the module doc on what this store does *not* hold.
pub const Resumption = tls13.Resumption;
/// The vendored `TicketKey`, named only so a reader knows where a server's key
/// would go and why it is not here.
pub const TicketKey = tls13.TicketKey;

/// The longest ALPN name this tree will key on: the core's own
/// `negotiated_alpn_len_max`, which is the width of `SessionTicket.alpn` and of
/// the selection an ALPN has to fit into. A ticket carrying a longer name could
/// not be stored and is refused rather than truncated.
pub const alpn_len_max: usize = 32;

/// How many tickets one store holds.
///
/// Eight, and the number is not this file's to tune. `docs/DECISIONS/0001`
/// records that iroh works to "up to 8 concurrent paths per connection" and
/// that the core holds two `NetworkPath`s behind one `active_path_idx`
/// (`vendor/quic/src/quic/connection.zig:626`); `path_table.max_paths` and
/// `holepunch_trigger.max_attempts` both adopt the same eight. A store is
/// per-identity and a node holds one node id, so eight entries is eight peers'
/// worth of resumption — which is the number of peers a connection's path table
/// is sized for anyway. A ninth peer's ticket is refused and that peer still
/// handshakes in full.
///
/// It is also the memory. `SessionTicket` carries an inline 512-byte `ticket`
/// array, so an entry is roughly 700 bytes and the table is about 5.6 KB of
/// stack. That is why the bound is a constant and the storage is an inline
/// array: a heap table would have made the store's ownership a question about
/// lifetimes, which is the property this file exists to remove.
pub const max_entries: usize = 8;

/// The identity, protocol and version a ticket is filed under.
///
/// Three fields and no borrows, so a `Key` is a value that can be compared, put
/// in an array and copied without any of it pointing anywhere. That matters
/// because a key holding a slice would be a key that could dangle, and the
/// ALPN in particular arrives from the caller at capture time.
pub const Key = struct {
    /// The peer's ed25519 public key, the same 32 bytes the handshake pins.
    peer: NodeId,
    /// The QUIC version the issuing connection ended on, as
    /// `SessionTicket.quic_version` records it.
    quic_version: u32,
    /// The protocol the issuing connection negotiated, whole.
    ///
    /// Inline and length-bounded rather than a slice, for the reason the module
    /// doc gives under "Why a weaker key is wrong": RFC 8446 §4.2.10's
    /// comparison is equality over names, so a name that does not fit is a
    /// protocol this store will not pretend to know.
    alpn: [alpn_len_max]u8 = .{0} ** alpn_len_max,
    /// Bytes of `alpn` in use, at or below `alpn.len`.
    alpn_len: u8 = 0,

    /// The whole protocol name, and nothing else.
    pub fn alpnSlice(self: *const Key) []const u8 {
        return self.alpn[0..self.alpn_len];
    }

    /// Whether this key names the same (peer, version, protocol) triple as
    /// `other`.
    ///
    /// Compared field by field rather than with `==`, because `NodeId` wraps a
    /// public key that is only *preconditionally* canonical (`base/key.zig` says
    /// a `NodeId` written as a struct literal may be any 32 bytes at all) and
    /// because `alpn` is compared only over `alpn_len`: the padding past it is
    /// unspecified storage and two keys that name the same protocol are the same
    /// key whatever they hold behind the name.
    pub fn matches(self: Key, other: Key) bool {
        if (self.quic_version != other.quic_version) return false;
        if (self.alpn_len != other.alpn_len) return false;
        if (!std.mem.eql(u8, self.alpnSlice(), other.alpnSlice())) return false;
        return std.mem.eql(u8, &self.peer.toBytes(), &other.peer.toBytes());
    }

    /// The key a ticket is filed under, or null when the ticket's protocol is
    /// longer than this store can hold.
    ///
    /// Everything comes off the ticket itself. Reading the ALPN from the
    /// ticket rather than from the caller's config is what makes the two
    /// sides of the store agree: a caller that filed under the protocol it
    /// *proposes* would file a ticket from a connection that negotiated a
    /// different one, and `resumableTicket` would refuse it on the next dial.
    ///
    /// `ticket.alpn_len` is not re-checked against `ticket.alpn.len`; the core
    /// documents that as the writer's obligation and `getAlpn` does not
    /// re-check it either. This store is not the writer.
    pub fn of(peer: NodeId, ticket: SessionTicket) ?Key {
        if (ticket.alpn_len > alpn_len_max) return null;
        var key: Key = .{ .peer = peer, .quic_version = ticket.quic_version };
        @memcpy(key.alpn[0..ticket.alpn_len], ticket.alpn[0..ticket.alpn_len]);
        key.alpn_len = ticket.alpn_len;
        return key;
    }
};

/// What one `capture` did.
pub const Stored = struct {
    /// Whether the table carries this key once the call returns. False means
    /// the table is full of keys none of which may be displaced, and the ticket
    /// that was handed over is dropped with it: a ticket nobody can see is a
    /// ticket nobody may claim to have been issued.
    stored: bool,
    /// The key that did not fit, when `stored` is false. Named rather than
    /// counted, so a caller logging the refusal says which peer it was.
    refused: ?Key,
};

/// One identity's resumption tickets, held by value.
///
/// Inline storage and no allocator, which is the property: there is no
/// allocation to fail, no `deinit` to forget, and no path by which a ticket
/// outlives the store that owns it. Entries past `len` are never written and
/// never read, so a default `Store` is a valid empty store rather than a broken
/// one — read it through `slice` rather than by indexing.
pub const Store = struct {
    /// The tickets, first `len` of them. A slot is a whole `SessionTicket`
    /// including its 512-byte opaque array.
    entries: [max_entries]Entry = undefined,
    /// How many entries are live. Never above `entries.len`, because `capture`
    /// counts what does not fit rather than growing past the bound.
    len: usize = 0,

    /// The entries, for a caller reading what is held: exactly
    /// `entries[0..len]`.
    pub fn slice(self: *const Store) []const Entry {
        return self.entries[0..self.len];
    }

    /// The ticket to offer on a connection to `peer` speaking `alpn` on
    /// `quic_version`, or null when there is none to offer.
    ///
    /// Null is an ordinary full handshake rather than a failure, and it is the
    /// answer in three cases a caller must not confuse: nothing has ever been
    /// captured for this triple, the one that was has expired, or this store is
    /// not the one that captured it. The core's own `resumableTicket` covers a
    /// fourth — a ticket for another version or another protocol — by answering
    /// null itself, so this file never hands over a ticket the core would
    /// refuse.
    ///
    /// **An expired ticket is dropped and the slot freed.** Handing one back
    /// would offer a PSK the peer has stopped accepting, which costs an extra
    /// flight and a `tryProcessPsk` binder-failure log to arrive where a full
    /// handshake would have arrived directly. See the module doc.
    ///
    /// `now_s` is a second on the caller's clock, the same one the core stamped
    /// `creation_time` with. The returned pointer borrows the store, so it is
    /// valid until the next `capture` or `forget` on it — which is exactly the
    /// obligation `TlsConfig.resumption`'s own field documents for the pointer
    /// it holds.
    pub fn take(
        self: *Store,
        peer: NodeId,
        alpn: []const u8,
        quic_version: u32,
        now_s: i64,
    ) ?*const SessionTicket {
        // A name this store cannot hold is a protocol it has no key for, so the
        // lookup cannot match rather than matching something shorter.
        if (alpn.len > alpn_len_max) return null;
        var wanted: Key = .{ .peer = peer, .quic_version = quic_version };
        @memcpy(wanted.alpn[0..alpn.len], alpn);
        wanted.alpn_len = @intCast(alpn.len);

        const index = self.indexOf(wanted) orelse return null;
        if (self.entries[index].ticket.isExpired(now_s)) {
            _ = self.forget(wanted);
            return null;
        }
        return &self.entries[index].ticket;
    }

    /// Record `ticket` under the key it names for `peer`, and answer whether
    /// the table carries it.
    ///
    /// A key the table already holds has its ticket replaced, keeping its
    /// position: a second ticket for a peer is a newer one for the same
    /// (peer, ALPN, version), and keeping both would spend two slots on one
    /// peer's most recent handshake.
    ///
    /// Null from `Key.of` — a protocol longer than this store can hold — is a
    /// refusal with the key named, because the core cannot have issued such a
    /// ticket and a caller that built one has a bug rather than a long name.
    pub fn capture(
        self: *Store,
        peer: NodeId,
        ticket: SessionTicket,
        now_s: i64,
    ) Stored {
        const key = Key.of(peer, ticket) orelse {
            // The refused key names the peer and the version the ticket claims,
            // and leaves the name empty: a name this store cannot hold has no
            // key, and a key naming an empty protocol is not the key that did
            // not fit. The version still travels, because a caller logging the
            // refusal is otherwise left saying a peer dropped its v1 ticket.
            return .{
                .stored = false,
                .refused = .{ .peer = peer, .quic_version = ticket.quic_version },
            };
        };
        // An already-expired ticket is not filed. The core documents a zero
        // `lifetime` as expired one second after creation, so a ticket with no
        // recorded lifetime would otherwise occupy a slot until somebody looked.
        if (ticket.isExpired(now_s)) return .{ .stored = false, .refused = key };
        if (self.indexOf(key)) |index| {
            self.entries[index] = .{ .key = key, .ticket = ticket };
            return .{ .stored = true, .refused = null };
        }
        if (self.len == self.entries.len) return .{ .stored = false, .refused = key };
        self.entries[self.len] = .{ .key = key, .ticket = ticket };
        self.len += 1;
        return .{ .stored = true, .refused = null };
    }

    /// Drop the entry `key` names and answer whether it was there.
    ///
    /// The last entry moves into the gap, so the order `slice` reports is not
    /// the order it had. A caller holding an index across one is reading the
    /// wrong entry, which is why `take` looks the key up again on every call
    /// rather than caching a slot.
    pub fn forget(self: *Store, key: Key) bool {
        const index = self.indexOf(key) orelse return false;
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// Where `key` is, or null. A scan, for `node/conn_index.zig`'s reason: the
    /// table is `max_entries` entries, so the walk is bounded by the storage it
    /// walks and cannot run away, and a hash would need an allocator this file
    /// exists to avoid.
    fn indexOf(self: *const Store, key: Key) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].key.matches(key)) return index;
        }
        return null;
    }
};

/// One filed ticket and the key it was filed under.
///
/// Both by value. The ticket's opaque array is inline inside it, so an `Entry`
/// owns every byte it holds and nothing in a `Store` points into a `Store`.
pub const Entry = struct {
    /// The triple this ticket is offered on.
    key: Key,
    /// The ticket as the core built it. Copied whole: the store never edits a
    /// field, because a field the core writes and this file rewrites is a field
    /// the two disagree about, and the core is what reads it.
    ticket: SessionTicket,
};

// --- tests

const t = std.testing;

/// The QUIC versions this tree speaks, named from the vendored `protocol.zig`
/// constants rather than spelled: RFC 9369's version 2 is the whole reason the
/// version is in the key.
const quic_v1: u32 = 1;
const quic_v2: u32 = 0x6b3343cf;

/// The one ALPN a filed ticket carries by default. `router/alpn_table.qad_alpn`
/// is the second protocol this tree speaks on the same identity, and the test
/// below files both.
const alpn_main = "ozai";
const alpn_other = "/iroh-qad/0";

/// Distinct canonical node ids, so a key collision test has real points and not
/// one point written twice.
///
/// Built at comptime by searching for the next byte pattern that *is* a
/// canonical ed25519 point, because `NodeId.fromBytes` refuses a
/// non-canonical encoding and "all bytes equal" is not one. A fixed table is
/// therefore the only honest form: every entry is checked when the module is
/// compiled, and a pattern that stopped being a point would fail the build
/// rather than a test.
const peer_count: usize = 16;
const peers: [peer_count]NodeId = blk: {
    var found: [peer_count]NodeId = undefined;
    var seed: u8 = 1;
    var index: usize = 0;
    // Bounded by the seed type rather than by `peer_count`, because the search
    // skips non-points and an unbounded loop over a wrapping counter is a hang
    // if the day comes when too few patterns are points. Every one of the 256
    // is tried before the guard fires, so the table is complete or the build
    // fails — never a truncated table and never a spin.
    var searched: usize = 0;
    while (index < peer_count and searched < std.math.maxInt(u8) + 1) : (searched += 1) {
        seed +%= 1;
        const point = NodeId.fromBytes([_]u8{seed} ** 32) catch continue;
        found[index] = point;
        index += 1;
    }
    if (index < peer_count) @compileError("fewer uniform-byte ed25519 points than peers");
    break :blk found;
};

/// `peers[index]`, for a test that wants a peer and does not care which.
///
/// Asserted rather than wrapped: every caller passes a literal index, and a
/// wrapped index would name a different peer than the test meant and make the
/// key assertions pass for the wrong reason.
fn otherPeer(index: usize) NodeId {
    std.debug.assert(index < peers.len);
    return peers[index];
}

/// A ticket as the core would have built it: a lifetime, a creation stamp on
/// the caller's clock, a protocol the connection negotiated, and a version it
/// ended on.
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
        .ticket_len = @intCast(alpn.len),
    };
    @memcpy(built.ticket[0..alpn.len], alpn);
    @memcpy(built.alpn[0..alpn.len], alpn);
    built.alpn_len = @intCast(alpn.len);
    return built;
}

/// The psk of the entry a `take` returned, so a test can say which ticket it
/// got without comparing three hundred bytes of opaque array.
fn pskOf(found: ?*const SessionTicket) ?u8 {
    const held = found orelse return null;
    return held.psk[0];
}

test "a ticket is filed and offered under the key it names" {
    const peer = otherPeer(0);
    var store: Store = .{};
    try t.expectEqual(@as(usize, 0), store.slice().len);
    try t.expect(store.take(peer, alpn_main, quic_v1, 100) == null);

    const filed = ticketFor(alpn_main, quic_v1, 3_600, 100);
    const stored = store.capture(peer, filed, 100);
    try t.expect(stored.stored);
    try t.expect(stored.refused == null);
    try t.expectEqual(@as(usize, 1), store.slice().len);

    // The key is the peer's identity, the protocol the issuing connection
    // negotiated and the version it ended on — read off the ticket, not off
    // the config the next connection will use.
    const entry = store.slice()[0];
    try t.expectEqualStrings(alpn_main, entry.key.alpnSlice());
    try t.expectEqual(quic_v1, entry.key.quic_version);
    try t.expect(std.mem.eql(u8, &peer.toBytes(), &entry.key.peer.toBytes()));

    // And the same triple reads the ticket back. The pointer borrows the store,
    // which is the obligation `TlsConfig.resumption` documents for the one it
    // holds.
    const offered = store.take(peer, alpn_main, quic_v1, 100);
    try t.expect(offered != null);
    try t.expectEqual(@as(?u8, 0xa5), pskOf(offered));
    try t.expectEqual(@as(u16, @intCast(alpn_main.len)), offered.?.ticket_len);
}

test "the peer, the protocol and the version are all part of the key" {
    const peer = otherPeer(0);
    const second = otherPeer(2);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);
    try t.expect(store.capture(peer, ticketFor(alpn_other, quic_v1, 3_600, 100), 100).stored);
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v2, 3_600, 100), 100).stored);
    try t.expect(store.capture(second, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);
    try t.expectEqual(@as(usize, 4), store.slice().len);

    // Four keys, and every one of the three fields is load-bearing: each of
    // these is a different (peer, protocol, version) and a lookup that moved
    // any one of the three fields would hand over the wrong ticket.
    try t.expect(store.take(peer, alpn_main, quic_v1, 100) != null);
    try t.expect(store.take(peer, alpn_other, quic_v1, 100) != null);
    try t.expect(store.take(peer, alpn_main, quic_v2, 100) != null);
    try t.expect(store.take(second, alpn_main, quic_v1, 100) != null);

    // A protocol nobody captured, a version nobody captured and a peer nobody
    // captured all answer null — a full handshake, not a wrong ticket.
    try t.expect(store.take(peer, "ozai-blobs-2", quic_v1, 100) == null);
    try t.expect(store.take(peer, alpn_main, quic_v2 ^ 1, 100) == null);
    try t.expect(store.take(otherPeer(3), alpn_main, quic_v1, 100) == null);
}

test "a ticket offered for another protocol is never handed back" {
    const peer = otherPeer(0);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);

    // A prefix of the protocol is a different protocol: RFC 8446 §4.2.10's
    // comparison is equality over whole names and `proposalHoldsProtocol`
    // compares them whole. A store that matched prefixes would offer this
    // ticket to a client proposing `ozai` alone.
    try t.expect(store.take(peer, "ozai", quic_v1, 100) != null);
    try t.expect(store.take(peer, alpn_main[0..2], quic_v1, 100) == null);
    try t.expect(store.take(peer, "ozai-blobs-2", quic_v1, 100) == null);
    try t.expect(store.take(peer, "", quic_v1, 100) == null);

    // And a name longer than the core's own selection cannot be held, so there
    // is no key for it: the lookup refuses rather than matching a truncation.
    const too_long = "z" ** (alpn_len_max + 1);
    try t.expectEqual(@as(usize, alpn_len_max + 1), too_long.len);
    try t.expect(store.take(peer, too_long, quic_v1, 100) == null);
    // The entry is untouched by any of those lookups.
    try t.expectEqual(@as(usize, 1), store.slice().len);
}

test "a ticket for another QUIC version is never handed back" {
    const peer = otherPeer(0);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v2, 3_600, 100), 100).stored);

    // RFC 9369 §5 is a MUST NOT in both directions, and `resumableTicket`
    // returns null on the mismatch. A store keyed without the version would
    // hand this over and the peer would pay a full handshake for it every time.
    try t.expect(store.take(peer, alpn_main, quic_v2, 100) != null);
    try t.expect(store.take(peer, alpn_main, quic_v1, 100) == null);
    try t.expectEqual(@as(usize, 1), store.slice().len);
}

test "an expired ticket is dropped rather than offered" {
    const peer = otherPeer(0);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 100, 1_000), 1_000).stored);

    // Inside the lifetime, including the last second of it.
    try t.expect(store.take(peer, alpn_main, quic_v1, 1_099) != null);
    try t.expect(store.take(peer, alpn_main, quic_v1, 1_100) != null);
    try t.expectEqual(@as(usize, 1), store.slice().len);

    // One second past it the ticket is gone, and gone means *gone*: the entry
    // is dropped so the slot is free, rather than kept to be handed over and
    // rejected. A binder the peer will not accept costs an extra flight and a
    // `tryProcessPsk` failure log to arrive where a full handshake would have
    // arrived directly.
    try t.expect(store.take(peer, alpn_main, quic_v1, 1_101) == null);
    try t.expectEqual(@as(usize, 0), store.slice().len);

    // And the freed slot is immediately usable.
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 100, 1_101), 1_101).stored);
    try t.expectEqual(@as(usize, 1), store.slice().len);
}

test "a ticket with no recorded lifetime is refused one second past its creation" {
    const peer = otherPeer(0);
    var store: Store = .{};
    // A zero `lifetime` is the core's default for a ticket nobody recorded one
    // on, and `isExpired` reads it as expired one second past `creation_time`:
    // it asks whether `now - creation` is *past* the lifetime, so the one
    // second this ticket is live in closes at its own creation stamp. Filing it
    // would fill the table with tickets that can only ever miss.
    const recorded = ticketFor(alpn_main, quic_v1, 0, 1_000);
    const refused = store.capture(peer, recorded, 1_001);
    try t.expect(!refused.stored);
    try t.expect(refused.refused != null);
    try t.expectEqual(@as(usize, 0), store.slice().len);
    // Still refused as the clock runs on, and the table is still empty.
    try t.expect(store.capture(peer, recorded, 1_100).stored == false);
    try t.expectEqual(@as(usize, 0), store.slice().len);
}

test "a second capture for the same key replaces the ticket in place" {
    const peer = otherPeer(0);
    var store: Store = .{};
    try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);

    // A newer ticket for the same peer, protocol and version is the same key.
    // Keeping both would spend two slots on one peer's most recent handshake,
    // and the older one would then be the one a lookup found.
    const newer = ticketFor(alpn_main, quic_v1, 3_600, 200);
    var updated = newer;
    updated.psk = [_]u8{0x5a} ** 32;
    try t.expect(store.capture(peer, updated, 200).stored);
    try t.expectEqual(@as(usize, 1), store.slice().len);
    try t.expectEqual(@as(?u8, 0x5a), pskOf(store.take(peer, alpn_main, quic_v1, 200)));
}

test "at the bound the store refuses the newcomer and names it" {
    var store: Store = .{};
    try t.expectEqual(@as(usize, 8), max_entries);
    for (0..max_entries) |offset| {
        const peer = otherPeer(offset);
        try t.expect(store.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);
    }
    try t.expectEqual(@as(usize, max_entries), store.slice().len);

    // A ninth peer's ticket does not fit. Evicting an existing one would be
    // worse in a way specific to tickets: every entry is a resumption for a peer
    // that has already paid for a handshake, and a store that silently drops
    // one drops that peer's 0-RTT with no signal at all.
    const ninth = otherPeer(15);
    const refused = store.capture(ninth, ticketFor(alpn_main, quic_v1, 3_600, 100), 100);
    try t.expect(!refused.stored);
    try t.expect(refused.refused != null);
    try t.expect(std.mem.eql(u8, &ninth.toBytes(), &refused.refused.?.peer.toBytes()));
    try t.expectEqual(@as(usize, max_entries), store.slice().len);

    // Every peer that was already in is still in, still resumable. The ninth
    // peer still handshakes in full, exactly as it would with no store at all.
    for (0..max_entries) |offset| {
        const peer = otherPeer(offset);
        try t.expect(store.take(peer, alpn_main, quic_v1, 100) != null);
    }
    try t.expect(store.take(ninth, alpn_main, quic_v1, 100) == null);

    // A key the table already holds is still replaceable at the bound: it
    // needs no new slot, so the bound is not a reason to refuse it.
    const replaced = store.capture(otherPeer(0), ticketFor(alpn_main, quic_v1, 3_600, 200), 100);
    try t.expect(replaced.stored);
    // Whereas a *new* key for a peer already in the table does need one, and is
    // refused the same way a ninth peer would be.
    const second_key = store.capture(otherPeer(0), ticketFor(alpn_main, quic_v2, 3_600, 100), 100);
    try t.expect(!second_key.stored);
    try t.expectEqual(@as(usize, max_entries), store.slice().len);
}

test "forget removes one entry and leaves the rest" {
    var store: Store = .{};
    for (0..4) |offset| {
        _ = store.capture(otherPeer(offset), ticketFor(alpn_main, quic_v1, 3_600, 100), 100);
    }
    // The middle entry goes, because forgetting the last one would move it into
    // its own gap and prove nothing about the move.
    const gone = otherPeer(1);
    try t.expect(store.forget(Key.of(gone, ticketFor(alpn_main, quic_v1, 3_600, 100)).?));
    try t.expectEqual(@as(usize, 3), store.slice().len);
    try t.expect(store.take(gone, alpn_main, quic_v1, 100) == null);
    // The last entry moved into the gap rather than everything shifting down,
    // so the other three are all still here, in an order `slice` does not
    // report as the order they were filed.
    for ([_]usize{ 0, 2, 3 }) |kept| {
        try t.expect(store.take(otherPeer(kept), alpn_main, quic_v1, 100) != null);
    }
    // And a key the table never held is not found, twice or otherwise.
    try t.expect(!store.forget(Key.of(otherPeer(14), ticketFor(alpn_main, quic_v1, 3_600, 100)).?));
}

test "a copied store is an independent snapshot" {
    const peer = otherPeer(0);
    var original: Store = .{};
    try t.expect(original.capture(peer, ticketFor(alpn_main, quic_v1, 3_600, 100), 100).stored);
    var copy = original;
    try t.expectEqual(original.len, copy.len);
    try t.expectEqual(@as(?u8, 0xa5), pskOf(copy.take(peer, alpn_main, quic_v1, 100)));

    // Every byte of a ticket lives inside the store, so nothing in a `Store`
    // points into a `Store` and the two cannot read each other's bytes.
    try t.expect(original.forget(Key.of(peer, ticketFor(alpn_main, quic_v1, 3_600, 100)).?));
    try t.expectEqual(@as(usize, 0), original.slice().len);
    try t.expectEqual(@as(usize, 1), copy.slice().len);
    try t.expect(copy.take(peer, alpn_main, quic_v1, 100) != null);

    // The bound is a value, not a property of the type's size: a store's
    // memory is fixed at `max_entries` whole tickets, so nothing here can fail
    // to allocate and there is nothing to leak.
    comptime {
        if (@sizeOf(Store) < @sizeOf(SessionTicket) * max_entries) {
            @compileError("the store is smaller than the entries it claims to hold");
        }
    }
}

test "a key compares over the protocol it names and not over its padding" {
    const peer = otherPeer(0);
    // Two keys naming the same protocol, with different bytes behind the name.
    // The padding past `alpn_len` is unspecified storage, so comparing it would
    // make two identical keys differ for no reason a caller could act on.
    var clean: Key = .{ .peer = peer, .quic_version = quic_v1 };
    @memcpy(clean.alpn[0..alpn_main.len], alpn_main);
    clean.alpn_len = @intCast(alpn_main.len);
    var dirty = clean;
    @memset(dirty.alpn[alpn_main.len..], 0xff);

    try t.expect(clean.matches(dirty));
    try t.expect(dirty.matches(clean));
    try t.expect(clean.matches(clean));

    // The same key rebuilt from a ticket is the key the ticket was filed
    // under, which is what makes `take` and `capture` agree.
    try t.expect(clean.matches(Key.of(peer, ticketFor(alpn_main, quic_v1, 3_600, 100)).?));

    // Every field moves the answer, and the peer comparison is over the 32
    // bytes rather than over the wrapper. Written out field by field rather
    // than as an anonymous literal, because a 130-column line is a line
    // nobody can review.
    var other_identity = clean;
    other_identity.peer = otherPeer(2);
    try t.expect(!clean.matches(other_identity));

    var other_version = clean;
    other_version.quic_version = quic_v2;
    try t.expect(!clean.matches(other_version));

    // A shorter name is a different protocol too, and so is a longer one.
    const shorter = Key{
        .peer = peer,
        .quic_version = quic_v1,
        .alpn = clean.alpn,
        .alpn_len = @intCast(alpn_main.len - 1),
    };
    try t.expect(!clean.matches(shorter));
    // And a ticket claiming more name than the core's own field can hold has no
    // key at all, so there is nothing for a lookup to match. The length is set
    // past the array rather than written into it: `Key.of` answers from
    // `alpn_len` alone and refuses before it reads a byte.
    var over_long = ticketFor(alpn_main, quic_v1, 3_600, 100);
    over_long.alpn_len = @intCast(alpn_len_max + 1);
    try t.expect(Key.of(peer, over_long) == null);

    // A `capture` handed one refuses and names it, carrying both fields it
    // knows: the key that did not fit is the peer's and the version's, or a
    // caller logging the refusal is left saying a peer dropped an unnamed
    // ticket.
    var store: Store = .{};
    const refused = store.capture(peer, over_long, 100);
    try t.expect(!refused.stored);
    try t.expectEqual(quic_v1, refused.refused.?.quic_version);
    try t.expect(std.mem.eql(u8, &peer.toBytes(), &refused.refused.?.peer.toBytes()));
    try t.expectEqual(@as(usize, 0), store.slice().len);
}
