//! What an application may do with early data, which is a narrower question
//! than whether it may send it.
//!
//! `transport/early_data.zig` owns the send side: it mints a `Permit` bounded
//! by the issuing server's allowance, and `settle` routes the bytes once the
//! core has given its verdict. Neither is a replay defence, and the core has
//! none to give — RFC 8446 §8 puts anti-replay outside TLS, because a replayed
//! 0-RTT flight verifies exactly as well as the first one did. `early_data`'s
//! own module doc says so and passes the obligation to "the caller choosing
//! what to send". This file is where that obligation is paid: it remembers the
//! early-data requests a peer has been admitted for, and its whole job is to
//! answer one question — has this exact request been admitted already.
//!
//! # Admission is duplicate suppression, not authentication
//!
//! **`admit` says a request is new. It does not say who sent it.** A peer that
//! replays a captured 0-RTT flight is admitted for the *first* time on this
//! connection, because nothing in the flight says it is the second: the PSK
//! opens, the binder verifies, `zero_rtt_accepted` is true, and the bytes are
//! indistinguishable from a first delivery. So an application that acts on an
//! admitted request is acting on unauthenticated input, and three things
//! remain the caller's, none of which any gate here can perform:
//!
//! - **The act must be idempotent.** This file bounds how long a duplicate is
//!   remembered, and a bound is not a proof that no duplicate ever arrives.
//!   See "After the window" for the case this file genuinely cannot catch.
//! - **The peer must be proved once the handshake finishes.** `tls13.zig`
//!   writes `peer_node_id` in exactly two places — the client's certificate
//!   handling and `serverProcessClientCertificate` — and a PSK reaches neither
//!   on the client side. `resumption_acceptance.zig` is the file that spells
//!   out what a resumption therefore does and does not prove, and which acts
//!   may be taken before it.
//! - **The identity must be one the caller chose.** See below: a request id a
//!   peer picks per delivery defeats this file entirely, and it does so
//!   without any error anywhere.
//!
//! # The request id must identify the request, not the delivery
//!
//! **`RequestId` is a function of what the request asks for.** The whole file
//! rests on that: a replayed flight is byte-for-byte the first flight, so it
//! must land on the record the first flight wrote. A counter, a timestamp, a
//! stream id or a per-connection nonce is not that — each differs between a
//! first delivery and its replay, so the replay walks past every record here
//! and the table fills with requests that were all new. A blob hash, a request
//! digest, a signed-at value: something the second delivery cannot vary.
//!
//! The id need not be secret, and it is not compared in constant time, because
//! it is not a credential — it is a name. What it must not be is *attacker
//! chosen per attempt*.
//!
//! # Inside the window, and after it
//!
//! **A second arrival inside the window is `.replayed`, and the caller must
//! not act on it.** The record is left exactly where it is and its timestamp
//! is *not* rewritten: refreshing it on a duplicate would let a peer that
//! replays on a loop keep a record alive forever, which turns a bounded
//! memory into a permanent blacklist of one request id.
//!
//! **A second arrival after the window is `.first` again, and this file says
//! plainly that it cannot tell the difference.** `live` is `now_s - at` at or
//! below `window_s`, so a record ages out and the same id is then admitted as
//! new. That is the honest limit of a bounded table: it remembers a duplicate
//! for `window_s` and not one second longer. Catching it longer needs storage
//! that grows with the number of requests ever seen, which is the unbounded
//! table `max_entries` exists to refuse. The answer is therefore not a longer
//! window but the idempotence obligation above: a request whose second
//! execution would be harmful has no business arriving in early data at all.
//!
//! `window_s` is a constant rather than a parameter for the same reason it is
//! not longer than it is: a parameter is a value a caller can pass to get the
//! answer it wants. It is five minutes, which covers the handshake a 0-RTT
//! admission is racing — the caller learns the verdict and settles the request
//! well inside that — and it is the ceiling a server's own ticket lifetime must
//! respect, because a ticket that stays resumable for longer than the window
//! keeps the replay opportunity open past the only point this file is watching.
//!
//! # At the bound
//!
//! **`max_entries` refuses the newcomer and evicts nothing.** A record inside
//! its window is the one thing standing between a replay and a second
//! execution, and it is held for a peer whose connection is in flight right
//! now. Dropping it to make room for a request that arrived a moment ago
//! trades a guard against a live duplicate for a slot, and the newcomer is the
//! cheaper loss: `.no_room` is an answer the caller can act on, because
//! `early_data.settle`'s `refused_resend` arm already exists for it — the
//! request goes again as 1-RTT, authenticated, and costs one flight.
//!
//! Records that have aged out are not evicted, they are reclaimed: `admit`
//! compacts them before it decides there is no room, which is expiry, not the
//! eviction the bound refuses. What reaches `.no_room` is a table whose every
//! record is still live.

const std = @import("std");

/// The name of one early-data request, as the caller derives it.
///
/// Thirty-two bytes because every other name in this tree is thirty-two bytes
/// — `NodeId`, `gossip.TopicId`, a blob hash — and this one is the same kind of
/// thing: a content-derived identifier, compared for equality and never
/// interpreted.
pub const RequestId = [32]u8;

/// How many early-data requests this endpoint remembers at once.
///
/// A ceiling, not a target: `forget` frees a record as soon as the handshake
/// that admitted it has settled, and `forgetExpired` reclaims the rest, so a
/// live table is only as large as the requests admitted inside one
/// `window_s`. Sixty-four is room for a node serving its handful of concurrent
/// peers at a request each per round trip. A node that reaches it is a node
/// whose peers are replaying to it, or whose 0-RTT is failing to settle, and
/// both are worth the named refusal `.no_room` rather than a silent eviction.
pub const max_entries: usize = 64;

/// How long an admitted request is remembered, in seconds on the caller's
/// clock — the same `now_s` `SessionTicket.creation_time` is stamped with, so
/// the two ages are differences of one epoch and nothing here depends on what
/// zero means.
pub const window_s: i64 = 300;

/// One early-data request this endpoint has admitted.
pub const Entry = struct {
    /// The request's name, as `RequestId` documents it must be built.
    id: RequestId,
    /// The second it was admitted on the caller's clock.
    at: i64,

    /// Whether this record still suppresses a duplicate at `now_s`.
    ///
    /// Live while the age is at or below `window_s`, which matches
    /// `SessionTicket.isExpired`'s own boundary rather than inventing a second
    /// one for the same kind of question. A clock that has gone backwards makes
    /// the age negative and the record live, so a record never expires early.
    pub fn live(self: Entry, now_s: i64) bool {
        return now_s - self.at <= window_s;
    }
};

/// What one `admit` did. Three arms, and the caller cannot act on the first
/// without knowing which one it got.
pub const Admission = union(enum) {
    /// The request was not on record, or its record had aged out. The caller
    /// may act, under the three obligations the module doc names.
    first,
    /// The request is already on record and that record is still live. This is
    /// a replay, and the caller must not act on it: the operation has been
    /// admitted once already.
    replayed,
    /// The table holds `max_entries` live records and nothing was evicted. The
    /// caller must not act on the request, and `early_data.settle`'s
    /// `refused_resend` arm is how it goes again as 1-RTT.
    no_room,
};

/// The early-data requests this endpoint has admitted, as a value.
///
/// Inline storage and no allocator, so a `Window` is a value a caller holds
/// without naming an owner, a copied `Window` is an independent snapshot, and
/// there is no `deinit` to forget. Only `[0..len]` is ever read or written, so
/// a default `Window` is a valid empty window rather than a broken one.
pub const Window = struct {
    /// The records, first `len` of them. Never written past `len` and never
    /// read past it, which is what makes the bound a refusal instead of a
    /// truncation.
    entries: [max_entries]Entry = undefined,
    /// How many entries of `entries` are in use, never a capacity.
    ///
    /// Not a count of live records: one that has aged out is still in use
    /// until `admit` or `forgetExpired` reclaims it, so this is the table's
    /// occupancy and not how much memory is still suppressing a duplicate.
    len: usize = 0,

    /// A window with nothing remembered.
    pub fn init() Window {
        return .{};
    }

    /// How many requests are on record, live or not.
    ///
    /// A caller logging a `.no_room` reads this to say how loaded the table
    /// was, which is the one number that makes the refusal diagnosable rather
    /// than merely reported.
    pub fn remembered(self: *const Window) usize {
        return self.len;
    }

    /// Whether `id` is on record and that record still suppresses a duplicate
    /// at `now_s`, without recording anything.
    ///
    /// The read-only question, for a caller that has to decide something
    /// before it is ready to admit. It changes nothing, so calling it twice
    /// answers the same thing twice — the record it finds is the record
    /// `admit` would refuse on.
    pub fn suppressing(self: *const Window, id: RequestId, now_s: i64) bool {
        const index = self.find(id) orelse return false;
        return self.entries[index].live(now_s);
    }

    /// Admit `id` as an early-data request, and say whether it is new.
    ///
    /// An id already on record and still live is `.replayed` and its timestamp
    /// is left alone. An id whose record has aged out is `.first` again and its
    /// slot is rewritten in place, so a table of long-dead records compacts
    /// itself as it is used rather than needing a sweep to make room.
    ///
    /// `.no_room` means every record is live and none was dropped; see the
    /// module doc for why the newcomer is the right one to refuse.
    pub fn admit(self: *Window, id: RequestId, now_s: i64) Admission {
        if (self.find(id)) |index| {
            if (self.entries[index].live(now_s)) return .replayed;
            self.entries[index].at = now_s;
            return .first;
        }
        // Expired records are reclaimed, not evicted: their memory has run out
        // and no duplicate they could still stop is being stopped.
        _ = self.forgetExpired(now_s);
        if (self.len == self.entries.len) return .no_room;
        self.entries[self.len] = .{ .id = id, .at = now_s };
        self.len += 1;
        return .first;
    }

    /// Drop the record for `id`, and answer whether there was one.
    ///
    /// What a caller calls once the connection that admitted the request has
    /// settled: the act is either done or abandoned, and the table is for
    /// requests still in flight. It is not a way to make a replay acceptable —
    /// a caller that forgets a record it never acted on has only widened the
    /// window to zero for that id.
    pub fn forget(self: *Window, id: RequestId) bool {
        const index = self.find(id) orelse return false;
        // find returns only live indices; ZBC cannot carry its scan proof to this swap.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// Drop every record whose window has run out, and answer how many went.
    ///
    /// Compaction rather than a tombstone, and a forward walk: live records
    /// are copied down over the dead ones and `len` shrinks, so the array
    /// stays dense and no state has to say which slots are holes.
    pub fn forgetExpired(self: *Window, now_s: i64) usize {
        var kept: usize = 0;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (!self.entries[index].live(now_s)) continue;
            self.entries[kept] = self.entries[index];
            kept += 1;
        }
        const dropped = self.len - kept;
        self.len = kept;
        return dropped;
    }

    /// Where `id` is on record, live or not, or null when it is not there.
    ///
    /// A scan, for `node/topic_table.zig`'s reason: the table is `max_entries`
    /// thirty-two-byte names, so a lookup costs less than the request it is
    /// about, and a hash would need an allocator this file exists not to have.
    /// The loop is bounded by the storage it walks.
    fn find(self: *const Window, id: RequestId) ?usize {
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (!std.mem.eql(u8, &entry.id, &id)) continue;
            return index;
        }
        return null;
    }
};

// --- tests

const t = std.testing;

/// Thirty-two: the width of every other content name in this tree, asserted
/// at comptime so the field and the helper that fills it cannot drift.
const request_id_len = @sizeOf(RequestId);
comptime {
    std.debug.assert(request_id_len == 32);
}

/// A request name, differing in its first byte. The bytes stand for whatever
/// the caller derives the name from, so only the difference is load-bearing.
fn requestId(tag: u8) RequestId {
    var id: RequestId = @splat(0);
    id[0] = tag;
    return id;
}

test "a first admission is new and the same request again is a replay" {
    var window = Window.init();
    const first = requestId(1);

    // Nothing is on record, so the first arrival is admitted and remembered.
    try t.expectEqual(Admission.first, window.admit(first, 1_000));
    try t.expectEqual(@as(usize, 1), window.remembered());

    // The same request inside the window is a replay, and the caller is told
    // so rather than being handed a second admission: the operation has been
    // admitted once already.
    try t.expectEqual(Admission.replayed, window.admit(first, 1_000));
    try t.expectEqual(Admission.replayed, window.admit(first, 1_000 + window_s));
    try t.expectEqual(@as(usize, 1), window.remembered());

    // A second, different request is not a replay of the first: distinct
    // names are distinct records.
    try t.expectEqual(Admission.first, window.admit(requestId(2), 1_000));
    try t.expectEqual(@as(usize, 2), window.remembered());
}

test "a duplicate does not refresh its record and a settled request is dropped" {
    var window = Window.init();
    const request = requestId(7);
    try t.expectEqual(Admission.first, window.admit(request, 1_000));

    // A replay inside the window leaves the timestamp where it was. If a
    // duplicate refreshed it, a peer replaying on a loop would hold one record
    // alive forever and turn a bounded memory into a permanent blacklist.
    try t.expectEqual(Admission.replayed, window.admit(request, 1_200));
    try t.expectEqual(Admission.replayed, window.admit(request, 1_250));

    // Dropped only once the handshake that admitted it has settled, and only
    // when it was really there.
    try t.expect(!window.forget(requestId(8)));
    try t.expectEqual(@as(usize, 1), window.remembered());
    try t.expect(window.forget(request));
    try t.expectEqual(@as(usize, 0), window.remembered());
    try t.expect(!window.suppressing(request, 1_250));
}

test "a record ages out at the window boundary and admits the name again" {
    var window = Window.init();
    const request = requestId(3);
    try t.expectEqual(Admission.first, window.admit(request, 1_000));

    // At exactly `window_s` the record is still live — the boundary is
    // `SessionTicket.isExpired`'s, not a second one for the same question.
    try t.expect(window.suppressing(request, 1_000 + window_s));
    try t.expectEqual(Admission.replayed, window.admit(request, 1_000 + window_s));

    // One second past it, the record is gone and this file can no longer tell
    // a replay from a first delivery. It admits, and says `first`; the
    // idempotence obligation is what makes that tolerable.
    try t.expectEqual(Admission.first, window.admit(request, 1_001 + window_s));
    try t.expectEqual(@as(usize, 1), window.remembered());

    // The read-only question tracks the record without recording anything.
    try t.expect(window.suppressing(request, 1_001 + window_s));
    try t.expect(!window.suppressing(requestId(9), 1_001 + window_s));

    // And a sweep reclaims exactly the aged-out records, leaving the rest. The
    // record just rewritten is current, so the first sweep drops nothing.
    try t.expectEqual(@as(usize, 0), window.forgetExpired(1_001 + window_s));
    try t.expectEqual(@as(usize, 1), window.remembered());
    _ = window.admit(requestId(4), 1_001 + window_s);
    _ = window.admit(requestId(5), 1_001 + window_s);
    try t.expectEqual(@as(usize, 3), window.remembered());
    try t.expectEqual(@as(usize, 3), window.forgetExpired(1_002 + 2 * window_s));
    try t.expectEqual(@as(usize, 0), window.remembered());
}

test "a full window refuses the newcomer and keeps every live record" {
    var window = Window.init();
    for (0..max_entries) |index| {
        const tag: u8 = @intCast(index);
        try t.expectEqual(Admission.first, window.admit(requestId(tag), 1_000));
    }
    try t.expectEqual(@as(usize, max_entries), window.remembered());

    // One past the bound. Nothing was evicted, so every record the table held
    // is still holding its request.
    const overflow = requestId(0xff);
    try t.expectEqual(Admission.no_room, window.admit(overflow, 1_000));
    try t.expectEqual(@as(usize, max_entries), window.remembered());
    for (0..max_entries) |index| {
        const tag: u8 = @intCast(index);
        try t.expect(window.suppressing(requestId(tag), 1_000));
        try t.expectEqual(Admission.replayed, window.admit(requestId(tag), 1_000));
    }

    // Settling one request frees its slot and the newcomer is admitted into
    // it, which is the refusal's answer: the caller resends as 1-RTT and the
    // table keeps serving the requests still in flight.
    try t.expect(window.forget(requestId(3)));
    try t.expectEqual(Admission.first, window.admit(overflow, 1_000));
    try t.expectEqual(@as(usize, max_entries), window.remembered());
}

test "aged-out records are reclaimed rather than occupying the bound" {
    var window = Window.init();
    for (0..max_entries) |index| {
        const tag: u8 = @intCast(index);
        try t.expectEqual(Admission.first, window.admit(requestId(tag), 1_000));
    }

    // Every record has run out, so this is not a full table and the newcomer
    // is admitted. Expiry is reclamation; the bound only ever sees records
    // that are still stopping a duplicate.
    const later = 1_001 + window_s;
    try t.expectEqual(Admission.first, window.admit(requestId(0xfe), later));
    try t.expectEqual(@as(usize, 1), window.remembered());
    try t.expect(!window.suppressing(requestId(0), later));
}
