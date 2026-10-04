//! Pre-accept Retry: the token a client comes back with, and the filter that
//! answers one this node has already spent without touching the cipher.
//!
//! # What Retry is, and what this file is not
//!
//! RFC 9000 §17.2.5 lets a server answer an Initial it has no state for with
//! a Retry: one small packet carrying an opaque token, sent back to the source
//! address the Initial came from. A client that gets one re-sends its Initial
//! with the token in it, and the server now knows the address is real — which
//! is the whole of what Retry buys, and the reason it exists: a server that
//! spent handshake state on a spoofed source is spending it on an attacker.
//!
//! **The decision is not this file's.** The vendored core decides it from two
//! manager-wide fields, `require_retry` and `retry_threshold`, inside the same
//! call that accepts the connection
//! (`vendor/quic/src/quic/connection_manager.zig:606-662`), and
//! `endpoint/endpoint.zig` records at length why an application verdict
//! cannot arrive earlier than that. What is missing from ozai is not the
//! decision — it is that nothing under `src/` ever set either field, so
//! pre-accept Retry was unreachable, and that a replayed Initial costs a full
//! AEAD open and a fresh Retry every time it arrives.
//!
//! So there are two things here:
//!
//!   * `issue` and `check` — this project's own names for minting a token and
//!     for answering one, in the core's format and under the core's key,
//!   * `Gate`, the bounded table of tokens this node has already answered, and
//!     the filter that reads it.
//!
//! # The filter, and why skipping the cipher is sound
//!
//! `Gate.check` can answer `spent` — "this node already validated that exact
//! token, for that exact address, under that exact key" — without opening the
//! AEAD. Three facts make that a fact rather than a guess:
//!
//!   1. a Retry token is **single use per attempt**. RFC 9000 §8.1.2 makes a
//!      client generate a fresh one per attempt, and §17.2.5 is explicit that
//!      a client which receives a second Retry for one Initial must treat the
//!      address as having failed validation. What §17.2.5 does *not* say is
//!      that the token appears once: it has the client put it in every Initial
//!      that carries the rest of that ClientHello, so a second arrival of the
//!      same bytes is a retransmission, a later packet of the same
//!      ClientHello, or a replay — and only the last of those is one this
//!      gate exists to stop. A token alone cannot tell them apart; what can is
//!      the destination connection id the datagram arrived on, because a
//!      datagram naming a connection this node already holds belongs to that
//!      connection rather than to admission. That answer is in the core's
//!      routing table and not in here, so `spent` is a fact about the token
//!      and the caller decides what a spent token on a datagram means.
//!   2. the answer is **deterministic**. Same token, same key, same address,
//!      same instant-epoch: the AEAD either opened or it did not, and the
//!      first answer stands.
//!   3. the address is compared too. The token is already bound to it by the
//!      seal; skipping the seal means comparing it by hand, so the comparison
//!      is in the record and in the loop.
//!
//! **A NEW_TOKEN is deliberately not recorded.** It is the opposite of a Retry
//! token: RFC 9000 §8.1.3 has a client present the same one on every
//! connection for as long as it is valid, so recording one would drop every
//! connection the second onwards. `check` therefore records only what
//! `validateRetryToken` opened.
//!
//! # The bound, and what running out costs
//!
//! `max_tracked` records, no more: a fixed table, never grown, overwritten
//! round-robin once it is full. It is a bound and not a budget — a token this
//! node minted is recorded at the moment it is issued, so a table smaller than
//! the number of attempts in flight is the only way to lose one, and losing
//! one costs a cipher open and nothing else. Nothing here can refuse a
//! datagram on capacity: a full table overwrites its oldest record and the
//! next `check` for an evicted token takes the authoritative path, which is
//! the behaviour the table is standing in front of.
//! # Purity
//!
//! No clock, no entropy, no allocator and no socket. `now` and `random` are
//! parameters, the table is inline storage, and a token is a value.

const std = @import("std");
const quic = @import("quic");

const packet = quic.packet;
const core_address = quic.address;

/// The width of the secret both sides seal a token with: the core's own
/// `crypto.key_len` — AES-128, RFC 9001 §5.2 — read here rather than written
/// down a second time, so this file is the only place the width is spelled.
///
/// **The value needs no assertion of its own.** Every key this file takes is
/// a `[key_length]u8` and every one of them is handed straight to the core's
/// token seals, which take `[crypto.key_len]u8`
/// (`vendor/quic/src/quic/packet.zig:886`, `965`, `1030`, `1073`). A core that
/// changed the width would make those calls a type mismatch, so the width
/// cannot drift here without the tree failing to build — which is a stronger
/// guarantee than an assertion bolted onto this one line.
pub const key_length = quic.crypto.key_len;

/// The largest token this format can produce, and the room one needs.
pub const max_token_length = packet.TOKEN_MAX_LEN;

/// The shortest token the format can produce: a nonce, a tag, and the two
/// length bytes of the smallest legal plaintext. Shorter than this is not one
/// of ours, and the core refuses it before any key is touched.
pub const min_token_length = packet.TOKEN_NONCE_LEN + packet.TOKEN_TAG_LEN + 2;

/// The length of a NEW_TOKEN, written out rather than read: the core keeps
/// `NEW_TOKEN_MAX_LEN` private and this file needs the room to seal one into.
/// It is the same format as a Retry token — a nonce, a timestamp and the whole
/// address under the seal, and a tag — which is what tells the two apart by
/// length alone, and it is why `check` can validate one without mistaking it
/// for the other.
pub const new_token_length =
    packet.TOKEN_NONCE_LEN + 8 + quic.address.identity_length + packet.TOKEN_TAG_LEN;

/// The longest a connection id can be, and so the longest a token's two
/// connection ids can be. RFC 9000 §17.2.2.
pub const max_connection_id = 20;

/// How long a token stays valid, and therefore how long a record of it is
/// worth keeping. Past this the core's own age check refuses the token, so a
/// record that outlived it would be a record of something no longer valid.
pub const max_age: i64 = 60 * std.time.ns_per_s;

/// How many tokens this node remembers at once. See the module doc: a bound
/// and not a budget, and overrunning it costs a cipher open rather than a
/// datagram.
pub const max_tracked = 32;

/// The long-header bit: a first byte with it clear is a short header, which
/// carries no token field at all.
const long_header_bit: u8 = 0x80;
/// The fixed bit every valid QUIC packet sets. A long header without it is not
/// one, whatever its other bits say.
const fixed_bit: u8 = 0x40;
/// The packet-type field of a long header's first byte, masked to its two
/// bits: Initial is `0b00`.
const packet_type_mask: u8 = 0x30;
const initial_packet_type: u8 = 0x00;
/// The version field's width, which nothing here reads and everything here has
/// to step over.
const version_length: usize = 4;
/// The shortest datagram whose Initial token field can even be located: the
/// first byte, the version, and the two connection-id lengths.
const min_header: usize = 1 + version_length + 1 + 1;

/// What this file refuses. Both arms are checked before the cipher is asked,
/// so neither costs an AEAD open.
pub const Error = error{
    /// A connection id over 20 bytes. No token can carry it, and the core
    /// would cast the length to a byte and trap rather than refuse.
    ConnectionIdTooLong,
    /// The core refused to seal the token for a reason this file cannot name.
    /// Logged before it is refused, so nothing is dropped on the floor.
    TokenRefused,
};

/// What a token was, when a gate was asked about it.
pub const Verdict = enum {
    /// Not a token this format can carry: its length is outside
    /// `[min_token_length, max_token_length]`, so it is somebody else's bytes
    /// and the core is the only thing that should have an opinion.
    unknown,
    /// Opened just now, and recorded — so the next copy of these exact bytes
    /// for this exact address answers `spent`.
    recorded,
    /// This node already validated that exact token, for that exact address.
    /// The cipher's answer is on file and cannot have changed, so this is the
    /// whole of what the cipher would have said.
    ///
    /// **A fact about the token, not about the datagram carrying it.** The
    /// same ClientHello arrives in as many Initials as it needs packets, and
    /// every one of them presents this token, so a spent token is what a
    /// legitimate second packet of a handshake in progress looks like here.
    /// Only the caller can tell that one from a replay, because the difference
    /// is whether the connection this datagram is addressed to exists.
    spent,
    /// Did not open: a forged token, one issued for another address, or one
    /// past its age. Nothing is recorded, so the core gets to answer it.
    invalid,
};

/// A sealed Retry token, by value.
///
/// The core's `generateRetryToken` takes a buffer and a length because its
/// plaintext is variable; a caller that had to hold the length beside the
/// bytes would be one more way to read past them. This is the pair.
pub const RetryToken = struct {
    bytes: [max_token_length]u8 = undefined,
    length: usize = 0,

    /// The token, and nothing else. Good for as long as this value is.
    pub fn slice(self: *const RetryToken) []const u8 {
        return self.bytes[0..self.length];
    }
};

/// One answered token: enough of it to recognise the same one again, and the
/// two facts the comparison has to make on top of the bytes.
const Record = struct {
    /// The AEAD nonce the token was sealed under. Never reused under one key,
    /// so two tokens with different nonces are different tokens.
    nonce: [packet.TOKEN_NONCE_LEN]u8 = @splat(0),
    /// The authentication tag, which is what makes the whole token
    /// unguessable; the nonce alone would be a guessable identifier.
    tag: [packet.TOKEN_TAG_LEN]u8 = @splat(0),
    /// The address the token is bound to, whole: family, address, port and
    /// scope. A token presented from anywhere else is a different token.
    identity: [quic.address.identity_length]u8 = @splat(0),
    /// The token's total length. A different length is a different token, and
    /// the tag sits at the end of it.
    length: usize = 0,
    /// When it was recorded, on this gate's clock epoch.
    at: i64 = 0,
    /// Whether this gate has already answered it. False is the window between
    /// issuing a token and the client echoing it back, which is the one moment
    /// a matching record must not answer `spent`.
    spent: bool = false,
};

/// The tokens this node has sealed or answered, and the filter that reads
/// them.
///
/// A value, not a pointer: the table is inline storage and `Bridge` holds one
/// beside the key it seals with, so there is nothing to allocate and nothing to
/// release. `init` is the identity on zeroed storage, so a bridge that never
/// issues a token never touches it either.
pub const Gate = struct {
    records: [max_tracked]Record = [_]Record{.{}} ** max_tracked,
    /// Where the next record goes once every slot is taken.
    next: usize = 0,

    /// Seal a Retry token for `from`, bound to `odcid` and `retry_scid`.
    ///
    /// The two connection ids are the ones RFC 9000 §17.2.5 puts in the Retry
    /// packet's header: the destination connection id the client chose, and
    /// the source connection id this token will authenticate. The token is
    /// recorded on the way out, marked unspent, so the echo that follows is
    /// recognised without a cipher open — see `check`.
    ///
    /// `random` must be a real CSPRNG in production: the nonce is drawn from
    /// it, and two tokens sealed under one nonce and key leak the keystream.
    /// The engine is borrowed for the call.
    ///
    /// Nothing is recorded and nothing is drawn on a refusal.
    pub fn issue(
        self: *Gate,
        key: [key_length]u8,
        odcid: []const u8,
        retry_scid: []const u8,
        from: core_address.Address,
        now: i64,
        random: std.Random,
    ) Error!RetryToken {
        if (odcid.len > max_connection_id) return error.ConnectionIdTooLong;
        if (retry_scid.len > max_connection_id) return error.ConnectionIdTooLong;
        var token: RetryToken = .{};
        const length = packet.generateRetryToken(
            &token.bytes,
            odcid,
            retry_scid,
            from,
            key,
            now,
            random,
        ) catch |err| {
            std.log.warn("retry: the core refused to seal a token: {t}", .{err});
            return error.TokenRefused;
        };
        token.length = length;
        self.record(nonceOf(token.slice()), tagOf(token.slice()), length, from, now, false);
        return token;
    }

    /// What `token` is, for a datagram that arrived from `from`.
    ///
    /// Three paths, and the expensive one is the last: a record this gate
    /// already holds answers without the cipher — `spent` if it was answered
    /// and `recorded` if this gate sealed it and is seeing it come back — and
    /// only a token no record matches is put to the AEAD. That last path also
    /// covers a token a *sibling* node minted under the same key, which is
    /// why one cipher open per token this node did not mint is the price and
    /// not a copy of the core's own work on the same datagram.
    ///
    /// **What it answers is the token and nothing else.** Whether the datagram
    /// that carried it names a connection this node already holds is a
    /// question about the core's routing table, and a caller that has one asks
    /// it before acting on `spent` — a spent token on a datagram this node
    /// owns is the rest of a handshake, and one on a datagram it does not is a
    /// replay this gate is standing in front of.
    ///
    /// A NEW_TOKEN is answered `unknown` on success, never `recorded`: it is
    /// reusable and dropping the second connection that presents it would be
    /// a bug dressed as a filter.
    pub fn check(
        self: *Gate,
        key: [key_length]u8,
        token: []const u8,
        from: core_address.Address,
        now: i64,
    ) Verdict {
        if (token.len < min_token_length or token.len > max_token_length) {
            return .unknown;
        }
        if (self.find(token, from, now)) |slot_index| {
            if (self.records[slot_index].spent) return .spent;
            // This gate sealed these bytes and the client has come back with
            // them. The seal was ours, the address is the one we sealed for and
            // the age is inside the window the seal names, so the cipher has
            // nothing left to say.
            self.records[slot_index].spent = true;
            return .recorded;
        }
        const opened = packet.validateRetryToken(token, from, key, now) catch null;
        if (opened != null) {
            self.record(nonceOf(token), tagOf(token), token.len, from, now, true);
            return .recorded;
        }
        // A NEW_TOKEN answers without being recorded, so the only thing left to
        // distinguish is a token that is not one of ours at all.
        if (packet.validateNewToken(token, from, key, now)) return .unknown;
        return .invalid;
    }

    /// Whether `token` was recorded already, read without the cipher.
    ///
    /// The same answer `check` would give on its second path, and separate so
    /// that a caller can ask the question without sealing anything. An
    /// unrecorded token is false, which is what a gate that has never seen one
    /// says.
    ///
    /// The same limits: a fact about the token, and whether the connection it
    /// arrived on is this node's is not a question this table can answer.
    pub fn spent(
        self: *const Gate,
        token: []const u8,
        from: core_address.Address,
        now: i64,
    ) bool {
        const slot_index = self.find(token, from, now) orelse return false;
        return self.records[slot_index].spent;
    }

    /// How many slots hold a record. A caller with a bound to keep an eye on
    /// reads it here rather than reaching into the table.
    ///
    /// **Every record, not only the answered ones.** A token this gate issued
    /// and is still waiting to see come back fills its slot the moment it is
    /// sealed, and a caller watching the bound has to see that slot as taken —
    /// `Bridge.retryTokensTracked` is documented as a count against
    /// `max_tracked`, and a table that is full of tokens still in flight reads
    /// as empty otherwise. A slot holds nothing until `record` writes it, and
    /// `record` only ever writes a real token's length, so the zero length of
    /// an untouched slot is what says "free" and nothing else has to.
    pub fn tracked(self: *const Gate) usize {
        var count: usize = 0;
        for (self.records) |slot| count += @intFromBool(slot.length != 0);
        return count;
    }

    /// The slot holding `token`, or null when no record matches.
    ///
    /// Every record that does not match is skipped rather than returned, so the
    /// loop is over the whole table and is bounded by `max_tracked`. A record
    /// past its age does not match: the token it names is no longer valid, and
    /// a filter that outlived its subject would drop datagrams the cipher would
    /// have accepted.
    ///
    /// **A record this gate issued but has not yet answered matches here**, and
    /// that is the whole of `check`'s `recorded` verdict: a token this node
    /// minted is recognised by hand, off the record `issue` wrote, rather than
    /// by a second cipher open. `spent` is therefore an answer this function
    /// returns the state of, never a filter on the search — skipping unspent
    /// slots would leave the `recorded` branch of `check` unreachable and every
    /// issued token's record dead on arrival. An untouched slot matches
    /// nothing either way: its length is zero, and `token` is at least
    /// `min_token_length`.
    fn find(self: *const Gate, token: []const u8, from: core_address.Address, now: i64) ?usize {
        if (token.len < min_token_length or token.len > max_token_length) return null;
        const identity = from.identity();
        const nonce = nonceOf(token);
        const tag = tagOf(token);
        for (self.records, 0..) |slot, index| {
            if (slot.length != token.len) continue;
            // The age has to be *inside* the window, not merely under its end.
            // A record stamped after `now` has a negative age, and the
            // saturating subtraction of one is not a number any comparison
            // against `max_age` can catch — so the future is refused by name.
            // This is the check that refuses a token carrying a clock an
            // attacker chose, and it only bites once a record this gate
            // issued is findable at all.
            if (slot.at > now or now -| slot.at > max_age) continue;
            if (!std.mem.eql(u8, &slot.identity, &identity)) continue;
            const same_nonce = std.crypto.timing_safe.eql(
                [packet.TOKEN_NONCE_LEN]u8,
                slot.nonce,
                nonce,
            );
            if (!same_nonce) continue;
            const same_tag = std.crypto.timing_safe.eql(
                [packet.TOKEN_TAG_LEN]u8,
                slot.tag,
                tag,
            );
            if (!same_tag) continue;
            return index;
        }
        return null;
    }

    /// Take a slot and fill it.
    ///
    /// A free slot first, so a table that has not filled up never overwrites
    /// anything, and `next` round-robin past that. `next` moves before the
    /// write rather than after so that a full table takes every slot in turn
    /// rather than the one it found first.
    fn record(
        self: *Gate,
        nonce: [packet.TOKEN_NONCE_LEN]u8,
        tag: [packet.TOKEN_TAG_LEN]u8,
        length: usize,
        from: core_address.Address,
        now: i64,
        spent_already: bool,
    ) void {
        for (&self.records) |*slot| {
            if (slot.spent) continue;
            slot.* = .{
                .nonce = nonce,
                .tag = tag,
                .identity = from.identity(),
                .length = length,
                .at = now,
                .spent = spent_already,
            };
            return;
        }
        const index = self.next;
        self.next = (self.next + 1) % max_tracked;
        self.records[index] = .{
            .nonce = nonce,
            .tag = tag,
            .identity = from.identity(),
            .length = length,
            .at = now,
            .spent = spent_already,
        };
    }
};

/// The AEAD nonce a token was sealed under: its first `TOKEN_NONCE_LEN` bytes.
///
/// Length-checked by the callers, which refuse anything outside
/// `[min_token_length, max_token_length]` before asking.
fn nonceOf(token: []const u8) [packet.TOKEN_NONCE_LEN]u8 {
    return token[0..packet.TOKEN_NONCE_LEN].*;
}

/// The authentication tag a token carries: the last `TOKEN_TAG_LEN` bytes.
fn tagOf(token: []const u8) [packet.TOKEN_TAG_LEN]u8 {
    const at = token.len - packet.TOKEN_TAG_LEN;
    return token[at..][0..packet.TOKEN_TAG_LEN].*;
}

/// The two fields of an Initial's header this project reads before the core is
/// asked: who the datagram is addressed to, and what token it carries.
pub const InitialHeader = struct {
    /// The destination connection id, borrowed from the datagram.
    ///
    /// **A caller must not match this by a prefix.** RFC 9000 §17.2.2 caps a
    /// connection id at `max_connection_id` bytes, and the core's own routing
    /// key truncates a longer one rather than refusing it
    /// (`connection_manager.zig:38-41`), so an id over the cap can name a
    /// registered connection by its first twenty bytes alone. A caller asking
    /// whether this node owns the destination has to refuse an over-long id
    /// itself; this reader preserves the entire declared id for that decision.
    dcid: []const u8,
    /// The token field, or null when the Initial asked for none — which is
    /// every first flight a client sends, and is not a token to have an
    /// opinion about.
    token: ?[]const u8,
};

/// Read an Initial's prefix through its token field, or null if it is incomplete
/// or its first byte does not identify an Initial with the fixed bit set.
///
/// The walk bounds the version bytes, both declared connection ids, the token
/// length varint, and the complete token. It does not validate the version,
/// packet-length field, packet number, or protected payload: the core owns
/// those checks. In particular, a complete zero-token prefix returns a header
/// even if the later packet-length field is absent or truncated.
///
/// **One walk, because there is one question.** Whether a datagram names a
/// connection this node owns and whether its token is one this node already
/// answered are not two questions about two packets: the second means anything
/// only once the first is settled, so a caller asking both would read the same
/// header twice to answer once. The token is null rather than the whole header
/// being null for a first flight that asked for none, because the connection
/// such a datagram is addressed to is exactly what a caller needs to know
/// about it.
///
/// Pure over bytes, and it allocates nothing: the answer borrows `datagram`.
pub fn initialHeader(datagram: []const u8) ?InitialHeader {
    if (datagram.len < min_header) return null;
    if (datagram[0] & long_header_bit == 0) return null;
    if (datagram[0] & fixed_bit == 0) return null;
    if (datagram[0] & packet_type_mask != initial_packet_type) return null;
    // The destination connection id's length byte is the one after the
    // four-byte version, so it is at `1 + version_length` and not one past it —
    // the offset `packet.parseQuicHeader` takes for the same field
    // (`packet.zig:647`). A length byte read one byte late is a byte of the
    // destination id, so every connection id after it is read from the wrong
    // place too.
    var at: usize = 1 + version_length;
    // Both lengths are bytes off the wire, and the datagram is whatever
    // arrived at this socket, so each is widened before it is added: a `u8` of
    // 255 plus one traps in a release-safe build's Debug mode too, and a
    // datagram carrying one is a packet this reader must answer with null
    // rather than the loss of the process that received it.
    const destination_len = datagram[at];
    const dcid_at = at + 1;
    at = dcid_at + @as(usize, destination_len);
    // The id is cut here, where the length byte that bounds it has just been
    // read: a datagram claiming a 255-byte destination id and carrying twenty
    // is null here rather than a slice of whatever followed it. The `at + 1`
    // is the source id's length byte, which has to exist for the walk to go on.
    if (at > datagram.len) return null;
    if (at + 1 > datagram.len) return null;
    const dcid = datagram[dcid_at..at];
    const source_len = datagram[at];
    at += 1 + @as(usize, source_len);
    if (at > datagram.len) return null;
    const length = readVarint(datagram[at..]) orelse return null;
    at += length.width;
    // A zero-length token is an Initial that asked for none, which is every
    // first flight a client sends; it is not a token to have an opinion about,
    // and the connection it is addressed to is still worth naming.
    if (length.value == 0) return .{ .dcid = dcid, .token = null };
    if (length.value > datagram.len - at) return null;
    return .{ .dcid = dcid, .token = datagram[at..][0..@intCast(length.value)] };
}

/// A QUIC varint and the width it was read at, for RFC 9000 §16's two-bit
/// length prefix.
const Varint = struct {
    value: u64,
    width: usize,
};

/// Read one varint, or null when `bytes` does not hold all of it.
///
/// The width is the top two bits read as `1 << bits`, so a byte with `11` in
/// them asks for eight bytes and there is no way to ask for fewer than one. The
/// shift is on a `u8` cast rather than on the byte itself, which is why this
/// cannot read a shift wider than the type.
fn readVarint(bytes: []const u8) ?Varint {
    if (bytes.len == 0) return null;
    const prefix: u2 = @truncate(bytes[0] >> 6);
    const width: usize = @as(usize, 1) << prefix;
    if (bytes.len < width) return null;
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..width]) |byte| value = (value << 8) | byte;
    return .{ .value = value, .width = width };
}

const t = std.testing;

/// Fixed seeds, so a run draws the same nonces and therefore the same tokens.
const Prng = std.Random.DefaultPrng;

/// Where virtual time starts, so nothing in a test is at an age boundary by
/// accident.
const start: i64 = 1_000 * std.time.ns_per_s;

/// The key both ends of these tests seal under, named for what it is so a
/// parameter called `key` does not shadow it.
const token_key: [key_length]u8 = @splat(0x5a);

/// A client address, in the core's vocabulary.
const client: core_address.Address = .initIpv4(.{ 127, 0, 0, 1 }, 4433);
/// A different host, one port over.
const other: core_address.Address = .initIpv4(.{ 127, 0, 0, 2 }, 4433);

/// A token sealed for `client`, from a seeded generator.
fn issueToken(
    gate: *Gate,
    random: std.Random,
    at: i64,
    from: core_address.Address,
) !RetryToken {
    return gate.issue(token_key, "original-dcid", "retry-scid-01", from, at, random);
}

test "an Initial's token field is read out of the long header" {
    // RFC 9000 §17.2.2's order: header(1) version(4) dcid_len(1) dcid(4)
    // scid_len(1) scid(4) = 15 bytes, then a one-byte varint length and the
    // token itself. The two length bytes are therefore at index 5 and index 10
    // and the varint at index 15, which is the layout
    // `packet.parseQuicHeader` walks and the one `initialHeader` has to agree
    // with byte for byte — a reader that steps over the wrong count here
    // reports a token nobody sent.
    var datagram = [_]u8{0} ** 32;
    datagram[0] = long_header_bit | fixed_bit | initial_packet_type;
    datagram[version_length + 1] = 4; // destination id length, at index 5
    datagram[6] = 0xc1; // the destination id's first byte
    // The source id's length byte is where the destination id's four bytes
    // end, and the token's varint is where the source id's four bytes end; both
    // are named so the offsets below cannot drift from the header they stand
    // for.
    const source_len_at: usize = version_length + 1 + 1 + 4;
    datagram[source_len_at] = 4; // source id length
    datagram[source_len_at + 1] = 0xc1; // the source id's first byte
    const at: usize = source_len_at + 1 + 4;
    datagram[at] = 3; // a one-byte varint length of three
    @memcpy(datagram[at + 1 ..][0..3], &[_]u8{ 0xaa, 0xbb, 0xcc });

    try t.expectEqualStrings(&.{ 0xaa, 0xbb, 0xcc }, initialHeader(&datagram).?.token.?);
    // **The destination id out of the same walk**, and not a prefix of it: the
    // four bytes the length byte at index 5 covers, of which only the first was
    // written above. This is the field a caller matches a connection on, so a
    // reader that returned a shorter or longer slice would route a datagram
    // that this one would have refused.
    try t.expectEqualSlices(u8, &.{ 0xc1, 0, 0, 0 }, initialHeader(&datagram).?.dcid);

    // The four ways a long header is not an Initial, each of which a wrong
    // reader would walk into the payload for.
    var short_header = datagram;
    short_header[0] = short_header[0] & ~long_header_bit;
    try t.expect(initialHeader(&short_header) == null);

    var unfixed = datagram;
    unfixed[0] = unfixed[0] & ~fixed_bit;
    try t.expect(initialHeader(&unfixed) == null);

    var handshake = datagram;
    handshake[0] = handshake[0] | 0x20; // packet type 0b10
    try t.expect(initialHeader(&handshake) == null);

    // A token length that runs past the datagram, which is what a spoofed one
    // looks like before anything has been decrypted. Two hundred needs the
    // two-byte form: a bare `200` is `0b11` in its prefix, so it reads as an
    // eight-byte varint the datagram is too short to hold, which is a
    // different refusal than the one named here.
    var overlong = datagram;
    overlong[at] = 0x40;
    overlong[at + 1] = 200;
    try t.expect(initialHeader(&overlong) == null);

    // A connection id length of 255, in either position. No QUIC connection id
    // is longer than twenty bytes (RFC 9000 §17.2.2), so both are malformed
    // and the answer is null — but these two bytes are the reason this reader
    // widens before it adds. `at += 1 + length` in a `u8` traps on 255, and a
    // datagram carrying one is a byte off the wire, so the trap was reachable
    // by anything that could send a packet and it took the whole process down
    // with it rather than dropping the packet.
    var widest_destination = datagram;
    widest_destination[version_length + 1] = 0xff;
    try t.expect(initialHeader(&widest_destination) == null);

    var widest_source = datagram;
    widest_source[source_len_at] = 0xff;
    try t.expect(initialHeader(&widest_source) == null);

    // And the one every first flight sends: no token at all. The header still
    // parses — this is an Initial, addressed to a connection — so it is the
    // token that is absent rather than the whole answer, which is what lets a
    // caller ask who owns a first flight before it carries anything to check.
    var empty = datagram;
    empty[at] = 0;
    try t.expect(initialHeader(&empty).?.token == null);
    try t.expectEqualSlices(u8, &.{ 0xc1, 0, 0, 0 }, initialHeader(&empty).?.dcid);
}

test "a token this gate issued comes back, and the second copy is spent" {
    var engine = Prng.init(1);
    const random = engine.random();
    var gate: Gate = .{};

    const token = try issueToken(&gate, random, start, client);
    try t.expect(token.length > min_token_length);
    try t.expect(token.length <= max_token_length);
    // Issued and not yet echoed, so it is not spendable: a client that has not
    // had its token back yet has not been answered.
    try t.expect(!gate.spent(token.slice(), client, start));

    // The echo. This gate sealed these bytes for this address inside the age
    // window, so it recognises them without a cipher open.
    try t.expectEqual(Verdict.recorded, gate.check(token_key, token.slice(), client, start));

    // And the same bytes again: a retransmission or a replay, and the one
    // answer a Retry token gets twice.
    try t.expectEqual(Verdict.spent, gate.check(token_key, token.slice(), client, start));
    try t.expect(gate.spent(token.slice(), client, start));
    try t.expectEqual(@as(usize, 1), gate.tracked());
}

test "a token is spent for the address it was sealed for, and no other" {
    var engine = Prng.init(2);
    const random = engine.random();
    var gate: Gate = .{};
    const token = try issueToken(&gate, random, start, client);
    try t.expectEqual(Verdict.recorded, gate.check(token_key, token.slice(), client, start));

    // The same bytes from another host. The seal binds the address, so this is
    // not a token this client holds: it is not spent, and it does not open.
    try t.expect(!gate.spent(token.slice(), other, start));
    try t.expectEqual(Verdict.invalid, gate.check(token_key, token.slice(), other, start));

    // Which is what stops a captured token from being replayed at a third host
    // by anyone at all. And it cost this address nothing while doing it: a
    // presentation from another host matched no record, so it neither answered
    // one nor disturbed the record this client is holding. The gate answered
    // this token for this client on line above, so the next copy is the second
    // one and is spent — a Retry token is single use (RFC 9000 §17.2.5), and
    // that holds however many hosts present it in between.
    try t.expectEqual(Verdict.spent, gate.check(token_key, token.slice(), client, start));
}

test "a record past the token's age stops answering" {
    var engine = Prng.init(3);
    const random = engine.random();
    var gate: Gate = .{};
    const token = try issueToken(&gate, random, start, client);
    try t.expectEqual(Verdict.recorded, gate.check(token_key, token.slice(), client, start));

    // Just inside the window the seal names, still spent.
    try t.expectEqual(
        Verdict.spent,
        gate.check(token_key, token.slice(), client, start + max_age),
    );
    // And past it: the core would refuse the token on its age alone, so a
    // record that outlived its subject would be dropping datagrams the cipher
    // would have let through.
    try t.expectEqual(
        Verdict.invalid,
        gate.check(token_key, token.slice(), client, start + max_age + 1),
    );
}

test "a NEW_TOKEN is not spent, because a client presents it every time" {
    var engine = Prng.init(4);
    var sealed: [new_token_length]u8 = undefined;
    const length = try packet.generateNewToken(&sealed, client, token_key, start, engine.random());
    const token = sealed[0..length];

    var gate: Gate = .{};
    // It opens, and it is not recorded: RFC 9000 §8.1.3 has the same token on
    // every connection for as long as it is valid.
    try t.expectEqual(Verdict.unknown, gate.check(token_key, token, client, start));
    try t.expectEqual(@as(usize, 0), gate.tracked());

    // So the second connection is answered exactly like the first.
    try t.expectEqual(Verdict.unknown, gate.check(token_key, token, client, start));
    try t.expectEqual(Verdict.unknown, gate.check(token_key, token, client, start + 1));
}

test "bytes that are not a token are answered without the cipher" {
    var gate: Gate = .{};

    // Too short to be one: the core refuses it on length before any key work.
    try t.expectEqual(Verdict.unknown, gate.check(token_key, &[_]u8{0} ** 8, client, start));
    // Too long for the format to produce.
    try t.expectEqual(
        Verdict.unknown,
        gate.check(token_key, &[_]u8{0} ** (max_token_length + 1), client, start),
    );
    // The right length and nothing behind it.
    const noise = [_]u8{0x5a} ** (min_token_length + 4);
    try t.expectEqual(Verdict.invalid, gate.check(token_key, &noise, client, start));
    // And nothing was recorded for any of them, so a forged token cannot fill
    // the table and evict the real ones.
    try t.expectEqual(@as(usize, 0), gate.tracked());
}

test "a connection id no token can carry is refused before anything is drawn" {
    var engine = Prng.init(5);
    const random = engine.random();
    var gate: Gate = .{};
    const long_id = [_]u8{0} ** (max_connection_id + 1);
    try t.expectError(
        error.ConnectionIdTooLong,
        gate.issue(token_key, &long_id, "retry-scid-01", client, start, random),
    );
    try t.expectError(
        error.ConnectionIdTooLong,
        gate.issue(token_key, "original-dcid", &long_id, client, start, random),
    );
    try t.expectEqual(@as(usize, 0), gate.tracked());
}

test "a full table records the next token rather than refusing it" {
    var engine = Prng.init(6);
    const random = engine.random();
    var gate: Gate = .{};

    // More distinct tokens than the table holds, each echoed once. The first
    // `max_tracked` are recorded; the rest evict the oldest, and none is
    // refused — a table that could refuse would be a table that could drop a
    // datagram on capacity.
    var passes: usize = 0;
    while (passes < max_tracked + 8) : (passes += 1) {
        const token = try issueToken(&gate, random, start, client);
        try t.expectEqual(Verdict.recorded, gate.check(token_key, token.slice(), client, start));
        try t.expectEqual(Verdict.spent, gate.check(token_key, token.slice(), client, start));
    }
    try t.expectEqual(@as(usize, max_tracked), gate.tracked());
}

test "every Varint width reads, and a truncated one does not" {
    // 0b00 is one byte, 0b01 two, 0b10 four, 0b11 eight. The prefix is the
    // width and the low six bits of the first byte are the top of the value,
    // so a first byte is `prefix << 6 | value >> (8 * (width - 1))`.
    try t.expectEqual(Varint{ .value = 0x3f, .width = 1 }, readVarint(&.{0x3f}).?);
    try t.expectEqual(Varint{ .value = 0x1234, .width = 2 }, readVarint(&.{ 0x52, 0x34 }).?);
    try t.expectEqual(Varint{ .value = 0x00ff_ffff, .width = 4 }, readVarint(&.{
        0x80, 0xff, 0xff, 0xff,
    }).?);
    try t.expectEqual(Varint{ .value = 0x1234, .width = 8 }, readVarint(&.{
        0xc0, 0, 0, 0, 0, 0, 0x12, 0x34,
    }).?);
    // Every prefix wider than one byte asks for more than it was given. `0b00`
    // is not in that set: one byte is all it ever asks for, and one byte is
    // what it was given.
    for ([_]u8{ 0x40, 0x80, 0xc0 }) |first| {
        try t.expect(readVarint(&.{first}) == null);
    }
    try t.expect(readVarint(&.{}) == null);
}
