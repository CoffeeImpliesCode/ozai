//! The QUIC connection state machine: one `Connection` per peer connection.
//!
//! `acceptInto` and `connectInto` are the two ways to build one, both in place
//! in storage the caller owns and keeps at that address. One `deinit` releases
//! it, and a construction that returns an error has already released itself.
//!
//! This module owns no socket, timer or thread. `handleDatagram` and `recv`
//! are the ingress, `sendAt` the egress, and `nextTimeoutNs` and `onTimeout`
//! the timer, so a caller runs the whole connection itself — and may run it in
//! virtual time, because every one of those calls takes the instant and, where
//! it draws entropy, the generator from the caller. Transport parameter
//! encoding lives in `transport_params.zig` and packet layout in `packet.zig`;
//! neither is reachable through this module.
const std = @import("std");
const io = @import("../io_compat.zig");
const limits = @import("limits.zig");
const address = @import("../address.zig");
const tls = std.crypto.tls;

const protocol = @import("protocol.zig");
const packet = @import("packet.zig");
const tls13 = @import("tls13.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const FrameType = frame_mod.FrameType;
const TransportError = frame_mod.TransportError;
const ack_handler = @import("ack_handler.zig");
const congestion = @import("congestion.zig");
const flow_control = @import("flow_control.zig");
const rtt = @import("rtt.zig");
const stream_mod = @import("stream.zig");
const crypto_stream = @import("crypto_stream.zig");
const transport_params = @import("transport_params.zig");
const packet_packer = @import("packet_packer.zig");
const quic_crypto = @import("crypto.zig");
const mtu_mod = @import("mtu.zig");
const stateless_reset = @import("stateless_reset.zig");
const ecn = @import("ecn.zig");
const quic_lb = @import("quic_lb.zig");
const native_path = @import("native_path_state.zig");
const native_nat_state = @import("native_nat_state.zig");
const observed = @import("observed_address.zig");

fn validateNativeConfig(config: ConnectionConfig) error{InvalidTransportParameter}!void {
    if (config.initial_max_path_id) |maximum| {
        if (maximum > 1) return error.InvalidTransportParameter;
    }
    if (config.max_remote_nat_traversal_addresses) |maximum| {
        if (maximum == 0 or maximum > 32) return error.InvalidTransportParameter;
    }
}

/// Where a connection is in RFC 9000 §10's lifecycle, as one value.
///
/// The order is the order states are entered and, except for `terminated`,
/// left: `first_flight` while the Initial is outstanding, `handshake` once a
/// handshake key is installed, `connected` when the handshake is confirmed,
/// then `closing` (a close is outstanding), `draining` (the peer's close was
/// acknowledged and the 3×PTO is running) and `terminated`. A connection
/// never returns to an earlier state, which is what lets a caller read this
/// instead of tracking its own copy of the transitions.
///
pub const State = enum(u8) {
    first_flight = 0,
    handshake = 1,
    connected = 2,
    closing = 3,
    draining = 4,
    terminated = 5,
};

/// One path challenge's progress (RFC 9000 §8.2.2).
///
/// `idle` is a path nobody has proposed or one that has finished validating;
/// `validated` is where a path's address is proved and stays until a
/// migration proposes a new one, so a caller reading only this cannot tell
/// "never tried" from "already proved" — `PathValidator` is the thing that
/// can.
///
pub const PathValidationState = enum {
    idle,
    pending,
    validated,
    failed,
};

/// One outstanding path challenge: the value that was sent, when, and how
/// many times it has been retried.
///
/// The challenge is drawn from the caller's generator and kept here, because a
/// response is only a response to the value that was asked for. Retries are
/// bounded and the state is per path, so a connection can have one candidate
/// validating while its active path is long since proved.
///
pub const PathValidator = struct {
    /// The eight bytes the last `startChallenge` drew, and the only value
    /// `handleResponse` will accept. All zero until one runs, which no response
    /// can match.
    challenge_data: [8]u8 = .{0} ** 8,
    /// Where this validation stands. `.idle` is both "never tried" and
    /// "finished", so this field alone cannot tell a path that was never
    /// challenged from one that is proved.
    state: PathValidationState = .idle,
    /// Nanoseconds on the caller's clock, stamped by `startChallenge` and by
    /// every `retry`. `needsRetry` and `checkTimeout` measure from it, so
    /// every instant must come from the same clock.
    challenge_sent_time: i64 = 0,
    /// How many resends the current challenge has had, 0 to `MAX_RETRIES`.
    /// `startChallenge` sets it back to 0, so a fresh challenge is a fresh
    /// budget of three.
    retries: u8 = 0,

    const MAX_RETRIES: u8 = 3;

    /// Draws eight fresh challenge bytes, moves the validator to `.pending` and
    /// returns the bytes to send in PATH_CHALLENGE.
    ///
    /// `retries` goes back to 0, so a new challenge is a new budget of three
    /// retries whatever the previous one spent. The returned array is a copy,
    /// so the caller may keep it; the same bytes stay in `challenge_data` for
    /// `handleResponse` to compare against. `now` is the caller's instant and
    /// `random` the caller's generator: a challenge that cannot be reproduced
    /// is not one a test can assert on.
    pub fn startChallenge(self: *PathValidator, now: i64, random: std.Random) [8]u8 {
        random.bytes(&self.challenge_data);
        self.state = .pending;
        self.challenge_sent_time = now;
        self.retries = 0;
        return self.challenge_data;
    }

    /// Whether `data` answers the challenge that was sent, moving `.pending`
    /// to `.validated` on a match.
    ///
    /// False in every other state, and false for a response that does not
    /// match, which leaves the challenge pending: a wrong answer neither
    /// proves nor fails a path. `data` is the eight bytes read out of the
    /// PATH_RESPONSE frame and nothing borrows it afterwards.
    pub fn handleResponse(self: *PathValidator, data: [8]u8) bool {
        if (self.state != .pending) return false;
        if (std.mem.eql(u8, &data, &self.challenge_data)) {
            self.state = .validated;
            return true;
        }
        return false;
    }

    /// Fails a challenge that has used all three retries and then waited one
    /// more `pto_ns`.
    ///
    /// Only a spent challenge can fail: below `MAX_RETRIES` it stays `.pending`
    /// however long it has waited, and `needsRetry` is what asks for the
    /// resend. `pto_ns` is a duration in nanoseconds, not an instant, and both
    /// it and `now` come from the caller's clock.
    pub fn checkTimeout(self: *PathValidator, now: i64, pto_ns: i64) void {
        if (self.state != .pending) return;
        if (self.retries >= MAX_RETRIES) {
            const elapsed = now - self.challenge_sent_time;
            if (elapsed > pto_ns) {
                self.state = .failed;
            }
        }
    }

    /// Whether the challenge has waited longer than `pto_ns` since it was sent
    /// and still has retries left, which is when the caller should resend it.
    ///
    /// False in any state but `.pending` and false once `retries` has reached
    /// `MAX_RETRIES`, so a spent challenge falls to `checkTimeout` rather than
    /// being retried for ever. Reads only; `retry` is what records a resend.
    pub fn needsRetry(self: *const PathValidator, now: i64, pto_ns: i64) bool {
        if (self.state != .pending) return false;
        if (self.retries >= MAX_RETRIES) return false;
        const elapsed = now - self.challenge_sent_time;
        return elapsed > pto_ns;
    }

    /// Records one resend: `retries` up by one and the clock restarted at
    /// `now`. The challenge bytes are unchanged, so the caller sends the value
    /// `startChallenge` returned and only the deadline moves. Calling it past
    /// `MAX_RETRIES` wraps `retries`, after which `needsRetry` and
    /// `checkTimeout` stop reading the count they bound it with.
    pub fn retry(self: *PathValidator, now: i64) void {
        self.retries += 1;
        self.challenge_sent_time = now;
    }
};

/// One path: the local and peer addresses a datagram arrived between, and the
/// validation and byte counters that belong to them.
///
/// A connection holds two — one active, one migration candidate — and indexes
/// one active; a candidate that has not been proposed is `unset` on both
/// addresses rather than absent, which is why an unset path compares equal to
/// itself and does not read as a migration. `bytes_received` and
/// `bytes_sent` are the anti-amplification ledger: `canSend` is the only
/// thing that consults them, and a server may not answer with three times what
/// it has received until a path is validated (RFC 9000 §8.1).
///
pub const NetworkPath = struct {
    /// `unset` until a caller names the path, which is what a second
    /// `NetworkPath` is: a connection carries one active path and one
    /// candidate, and a candidate that has not been proposed has no address.
    local_addr: address.Address = .unset,
    peer_addr: address.Address = .unset,
    /// Whether this is the path the connection started on. Only `acceptInto`
    /// and `connectInto` set it, on the one path they establish; a path a
    /// migration proposes arrives unset.
    is_initial: bool = false,

    /// Bytes received on this path (for amplification limit).
    bytes_received: u64 = 0,

    /// Bytes sent on this path.
    bytes_sent: u64 = 0,

    /// Whether the path has been validated (e.g., by Retry or handshake completion).
    is_validated: bool = false,

    /// Path validation state machine.
    validator: PathValidator = .{},

    /// A path between two addresses, with every counter at zero and the path
    /// unvalidated.
    ///
    /// An unvalidated path is bound by `canSend`, which is the state a server
    /// must start in: nothing validates a path until a Retry, the handshake or
    /// a PATH_RESPONSE does. Both addresses are copied, so nothing is borrowed.
    pub fn init(
        local_addr: address.Address,
        peer_addr: address.Address,
        is_initial: bool,
    ) NetworkPath {
        return .{
            .local_addr = local_addr,
            .peer_addr = peer_addr,
            .is_initial = is_initial,
        };
    }

    /// Check if we can send `size` bytes without exceeding the amplification limit.
    /// Before address validation, servers can only send 3x what they've received.
    pub fn canSend(self: *const NetworkPath, size: u64) bool {
        return self.is_validated or (self.bytes_sent + size) <= 3 * self.bytes_received;
    }
};

/// One connection id the peer issued for this connection, in the pool that
/// holds them.
///
/// Owns its bytes: `cid_buf` is 20 bytes and `cid_len` says how many of them
/// this id has, so `getCid` is a view into the entry and never a dangling
/// slice. `stateless_reset_token` is the token the peer advertised beside this
/// id, and the stateless reset that retires the connection arrives carrying
/// it. `in_use` is whether this side has taken it as the destination id it
/// sends to, and `occupied` whether the slot holds a live id at all.
///
pub const ConnectionIdEntry = struct {
    cid_buf: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    seq_num: u64 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    in_use: bool = false,
    occupied: bool = false,

    /// The id's bytes as `cid_buf[0..cid_len]`, borrowed from this entry.
    ///
    /// An entry no pool operation has filled returns an empty slice, and any
    /// pool operation that resets this entry resets the bytes behind the view,
    /// so a caller that keeps one past a `retirePriorTo` or `removeBySeq` reads
    /// zeroes.
    pub fn getCid(self: *const ConnectionIdEntry) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
};

/// The connection ids the peer issued and this side has not retired, at most
/// `MAX_POOL_SIZE` of them — the ids this side sends *to*, where `LocalCidPool`
/// is the other half: the ids this side issued and advertised.
///
/// A fixed array, not a heap: the count is a protocol constant (RFC 9000 §5.1.1
/// lets a peer limit it, and this tree honours a lower limit) and a server
/// that allocated per connection would pay for ids it never issues. Entries
/// are added with `addPeerCid`, handed out with `consumeUnused`, and dropped by
/// `removeBySeq`/`retirePriorTo` — the last of which is what a
/// NEW_CONNECTION_ID's retire_prior_to asks for, applied here rather than in
/// the packet path. A RETIRE_CONNECTION_ID naming a sequence number retires an
/// id this side issued and so lands in `LocalCidPool`, never here.
///
pub const ConnectionIdPool = struct {
    const MAX_POOL_SIZE: usize = 8;

    /// Inline slots, one per connection id the peer may have issued. The pool
    /// allocates nothing, so a value copied out of `Connection` carries its
    /// whole set with it.
    entries: [MAX_POOL_SIZE]ConnectionIdEntry = .{ConnectionIdEntry{}} ** MAX_POOL_SIZE,
    /// Bumped by every call that can change the set — `addPeerCid`,
    /// `retirePriorTo`, `removeBySeq` — whether or not that call changed
    /// anything, so a watcher sees one new generation per operation.
    /// `consumeUnused` marks an entry in use without changing which entries
    /// there are, and does not bump it. `ConnectionManager.syncCids` compares
    /// it against the generation its stateless-reset token index was built
    /// from, and rebuilds that index when they differ.
    generation: u32 = 0,

    /// Registers a connection id the peer issued for this connection to send
    /// to, under `seq_num`, with the reset token that lets a stateless reset
    /// naming it be recognised.
    ///
    /// `cid` is copied and not retained, and must be at most
    /// `packet.CONNECTION_ID_MAX_SIZE` bytes: a longer id is written past the
    /// entry's inline buffer, which the bounds check in the safe modes turns
    /// into a panic and in `ReleaseFast` and `ReleaseSmall` does not. A pool
    /// with no free slot drops the id and reports nothing, so a peer that
    /// issues more ids than the pool holds has the surplus ignored until
    /// `retirePriorTo` or `removeBySeq` frees a slot. `seq_num` is not checked
    /// against what is already stored, so registering one id twice leaves two
    /// entries carrying the same number.
    pub fn addPeerCid(self: *ConnectionIdPool, seq_num: u64, cid: []const u8, reset_token: [16]u8) void {
        self.generation +%= 1;
        // Find a free slot
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.in_use = false;
                entry.seq_num = seq_num;
                entry.cid_len = @intCast(cid.len);
                @memcpy(entry.cid_buf[0..cid.len], cid);
                entry.stateless_reset_token = reset_token;
                return;
            }
        }
        // Pool full — drop silently
    }

    /// Takes the first issued id this side is not already sending to, marks it
    /// in use, and returns it; `null` when the peer has issued none.
    ///
    /// The pointer names storage inside this pool, not a copy: it stays valid
    /// until the entry is reset or overwritten, and it dangles in the sense
    /// that a later `retirePriorTo` or `removeBySeq` may zero it under the
    /// caller. Each id is handed out once — the in-use mark is what stops a
    /// second call returning the same entry.
    pub fn consumeUnused(self: *ConnectionIdPool) ?*ConnectionIdEntry {
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.in_use) {
                entry.in_use = true;
                return entry;
            }
        }
        return null;
    }

    /// Drops every id below `seq`, as a peer's retire_prior_to asks.
    ///
    /// Each dropped entry is reset whole, so its bytes, its token and its
    /// sequence number all go with it and the slot becomes free for
    /// `addPeerCid`. An id at or above `seq` is untouched.
    pub fn retirePriorTo(self: *ConnectionIdPool, seq: u64) void {
        self.generation +%= 1;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num < seq) {
                entry.* = ConnectionIdEntry{};
            }
        }
    }

    /// Whether an occupied entry carries `seq`, whether or not this side sends
    /// to it.
    pub fn contains(self: *const ConnectionIdPool, seq: u64) bool {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num == seq) return true;
        }
        return false;
    }

    /// Drops the entry at `seq` if there is one and leaves every other entry
    /// alone. A `seq` the pool does not hold does nothing.
    pub fn removeBySeq(self: *ConnectionIdPool, seq: u64) void {
        self.generation +%= 1;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num == seq) {
                entry.* = ConnectionIdEntry{};
                return;
            }
        }
    }

    /// How many entries are occupied, from 0 to `MAX_POOL_SIZE`.
    pub fn count(self: *const ConnectionIdPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }
};

/// Tracks a locally-issued connection ID (RFC 9000 §5.1).
///
/// Like `ConnectionIdEntry` this owns its bytes inline, so `getCid` borrows the
/// entry and nothing here is released separately. `occupied` is whether the
/// slot holds a live id; `retired` is set by `retireBySeq`, which clears
/// `occupied` and leaves `retired` set so the two states stay distinguishable.
pub const LocalCidEntry = struct {
    path_id: u32 = 0,
    cid_buf: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    seq_num: u64 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    occupied: bool = false,
    retired: bool = false,

    /// The id's bytes as `cid_buf[0..cid_len]`, borrowed from this entry and
    /// invalidated by whatever next writes the entry.
    ///
    /// A pool that never filled this entry returns an empty slice rather than
    /// the zero bytes, because `cid_len` starts at 0.
    pub fn getCid(self: *const LocalCidEntry) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
};

/// Pool of locally-issued connection IDs (RFC 9000 §5.1).
///
/// Seq 0 = initial SCID. New CIDs issued via issueNewCid().
///
/// Like `ConnectionIdPool` this is a fixed inline array: it allocates nothing,
/// holds at most `MAX_POOL_SIZE` ids, and every id it hands out stays inside
/// it. The pool owns no allocator and is not read from the packet path.
pub const LocalCidPool = struct {
    const MAX_POOL_SIZE: usize = 8;

    /// Inline slots. A full pool is not an error to the issuer: `issueNewCid`
    /// and `issueNewCidLb` answer `null`, and `registerPreferredCid` drops the
    /// id silently, so the cap is a limit a deployment sizes around.
    entries: [MAX_POOL_SIZE]LocalCidEntry = .{LocalCidEntry{}} ** MAX_POOL_SIZE,
    /// The sequence number the next issued id gets. It starts at 1 because
    /// sequence 0 is the initial SCID, and `registerPreferredCid` raises it to
    /// 2 so a preferred-address id is never handed out twice. It only ever
    /// increases, including for ids that are later retired.
    next_seq_num: u64 = 1,
    /// The lowest sequence number this side still issues below, as a peer's
    /// retire_prior_to set it.
    retire_prior_to: u64 = 0,

    /// Stores `cid` as sequence 0, the initial SCID, and derives its reset
    /// token.
    ///
    /// With `static_key` the token is computed from that key and `cid`, so the
    /// same key and id always give the same token; without it the token is
    /// drawn from `random`, which the caller owns. Nothing is drawn for the id
    /// itself, which is why this takes no length: `cid` is copied into the
    /// entry's inline buffer and must be at most
    /// `packet.CONNECTION_ID_MAX_SIZE` bytes. This overwrites slot 0 whatever
    /// was there, so it is a one-time setup rather than something to repeat.
    pub fn registerInitialCid(
        self: *LocalCidPool,
        cid: []const u8,
        static_key: ?[16]u8,
        random: std.Random,
    ) void {
        self.entries[0] = LocalCidEntry{
            .occupied = true,
            .retired = false,
            .seq_num = 0,
            .cid_len = @intCast(cid.len),
        };
        @memcpy(self.entries[0].cid_buf[0..cid.len], cid);
        if (static_key) |key| {
            self.entries[0].stateless_reset_token = stateless_reset.computeToken(key, cid);
        } else {
            random.bytes(&self.entries[0].stateless_reset_token);
        }
    }

    /// Registers the preferred_address CID at sequence number 1 (RFC 9000
    /// §5.1.1), in the first free slot, with a reset token the caller has
    /// already drawn. A full pool drops it silently.
    pub fn registerPreferredCid(self: *LocalCidPool, cid: []const u8, reset_token: [16]u8) void {
        // Find a free slot for seq 1
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.seq_num = 1;
                entry.cid_len = @intCast(cid.len);
                @memcpy(entry.cid_buf[0..cid.len], cid);
                entry.stateless_reset_token = reset_token;
                // Ensure next_seq_num is at least 2
                if (self.next_seq_num <= 1) self.next_seq_num = 2;
                return;
            }
        }
    }

    /// Draws a fresh random id of `cid_len` bytes, stores it at
    /// `next_seq_num` and returns the entry; `null` when every slot is
    /// occupied.
    ///
    /// `cid_len` is bytes and must be at most `packet.CONNECTION_ID_MAX_SIZE`:
    /// the id is written into the entry's inline buffer, which the safe modes
    /// check and `ReleaseFast` and `ReleaseSmall` do not. With `static_key`
    /// the reset token is computed from that key and the new id; without it
    /// the token is drawn from `random`, which the caller owns and this call
    /// advances.
    ///
    /// The returned pointer names storage inside this pool. `retireBySeq`
    /// frees the slot without touching the bytes, and a later issue into that
    /// slot overwrites them, so a caller that keeps the pointer must copy what
    /// it needs first.
    pub fn issueNewCid(
        self: *LocalCidPool,
        cid_len: u8,
        static_key: ?[16]u8,
        random: std.Random,
    ) ?*LocalCidEntry {
        // Find a free slot
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.path_id = 0;
                entry.seq_num = self.next_seq_num;
                entry.cid_len = cid_len;
                generateConnectionId(entry.cid_buf[0..cid_len], random);
                if (static_key) |key| {
                    entry.stateless_reset_token = stateless_reset.computeToken(key, entry.cid_buf[0..cid_len]);
                } else {
                    random.bytes(&entry.stateless_reset_token);
                }
                self.next_seq_num += 1;
                return entry;
            }
        }
        return null;
    }

    /// As `issueNewCid`, but the id is encoded under `lb_config` and its length
    /// is whatever `quic_lb.cidLength` computes from that config rather than a
    /// caller's `cid_len`. Returns the same entry pointer with the same
    /// lifetime.
    pub fn issueNewCidLb(
        self: *LocalCidPool,
        lb_config: *const quic_lb.Config,
        static_key: ?[16]u8,
        random: std.Random,
    ) ?*LocalCidEntry {
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.path_id = 0;
                entry.seq_num = self.next_seq_num;
                const cid_len = quic_lb.cidLength(lb_config);
                entry.cid_len = cid_len;
                quic_lb.generateCid(lb_config, entry.cid_buf[0..cid_len], random);
                if (static_key) |key| {
                    entry.stateless_reset_token = stateless_reset.computeToken(key, entry.cid_buf[0..cid_len]);
                } else {
                    random.bytes(&entry.stateless_reset_token);
                }
                self.next_seq_num += 1;
                return entry;
            }
        }
        return null;
    }

    /// Retires the entry at `seq`, so this side stops offering it: `occupied`
    /// goes false and `retired` true, and the slot becomes free for the next
    /// `issueNewCid`. A `seq` the pool does not hold does nothing. Retiring is
    /// not removing — the bytes and the token stay in the entry, which is why
    /// `activeCount` and a reset-token check must both read `occupied`.
    pub fn retireBySeq(self: *LocalCidPool, seq: u64) void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.path_id == 0 and entry.seq_num == seq) {
                entry.occupied = false;
                entry.retired = true;
                return;
            }
        }
    }

    /// Count active (occupied, non-retired) entries.
    pub fn activeCount(self: *const LocalCidPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.path_id == 0 and !entry.retired) n += 1;
        }
        return n;
    }
};

/// Fixed-capacity ring of queued QUIC DATAGRAM payloads (RFC 9221), with an
/// optional max-age and a configurable high water mark.
///
/// Every entry is at most `MAX_DATAGRAM_SIZE` bytes and `push` copies into it,
/// so a datagram is kept whole rather than as a borrow and nothing the caller
/// passes has to stay alive. A queue that was never `resize`d uses inline
/// storage for `DEFAULT_MAX_ITEMS` entries and allocates nothing; one that was
/// stores the allocator `resize` was given and owns what it allocated, which
/// `deinitQueue` frees exactly once. The ring is single-producer and
/// single-consumer: one writer pushing, one reader popping or peeking, and no
/// two of either at once.
pub const DatagramQueue = struct {
    /// Entries the inline storage holds, 32. A queue at this size allocates
    /// nothing; one above it is grown by `resize`.
    pub const DEFAULT_MAX_ITEMS: usize = limits.datagram_static_items;
    /// Bytes one queued datagram may take, 1200. It bounds the whole entry, not
    /// the application payload: `maxDatagramPayloadSize` on a `Connection`
    /// reports what is left of it after header, tag and frame overhead.
    pub const MAX_DATAGRAM_SIZE: usize = 1200;

    /// The allocator `resize` was given, borrowed and stored for
    /// `deinitQueue`; `null` on a queue that never grew. It is not released
    /// here and it stays the caller's after `deinitQueue`.
    allocator: ?std.mem.Allocator = null,
    bufs_static: [DEFAULT_MAX_ITEMS][MAX_DATAGRAM_SIZE]u8 = undefined,
    lens_static: [DEFAULT_MAX_ITEMS]usize = @splat(0),
    times_static: [DEFAULT_MAX_ITEMS]i64 = @splat(0),
    bufs_dynamic: ?[][MAX_DATAGRAM_SIZE]u8 = null,
    lens_dynamic: ?[]usize = null,
    times_dynamic: ?[]i64 = null,
    /// Ring capacity in entries, which `resize` raises and `head`/`tail` index
    /// modulo. Every operation walks the ring this long, so a `resize` after
    /// entries are queued would read storage those entries were not written
    /// into.
    max_items: usize = DEFAULT_MAX_ITEMS,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,

    /// Max age in nanoseconds. Datagrams older than this are dropped on read.
    /// null = no age limit (default).
    max_age_ns: ?i64 = null,

    /// Queued entries the queue holds before `push` refuses, in entries.
    /// `null` means `max_items`. Read on every `push`, so a caller may lower it
    /// after the fact; raising it above `max_items` does not add storage, it
    /// only makes the index arithmetic wrap later than the arrays do.
    high_water_mark: ?usize = null,

    /// Grows the queue to `capacity` entries, allocating from `alloc`, which is
    /// borrowed and stored for `deinitQueue`.
    ///
    /// `capacity` at or below `DEFAULT_MAX_ITEMS` returns without allocating
    /// and without storing `alloc`: the inline buffer serves every entry and
    /// `deinitQueue` has nothing to release. `error.OutOfMemory` leaves
    /// whatever this call did allocate reachable through `self`, so
    /// `deinitQueue` still frees it, and leaves `max_items` unchanged.
    ///
    /// Call it before anything is queued: it neither carries entries over from
    /// the inline buffer nor releases what an earlier `resize` allocated.
    pub fn resize(self: *DatagramQueue, alloc: std.mem.Allocator, capacity: usize) !void {
        if (capacity <= DEFAULT_MAX_ITEMS) return; // static buffer is enough
        self.allocator = alloc;
        self.bufs_dynamic = try alloc.alloc([MAX_DATAGRAM_SIZE]u8, capacity);
        self.lens_dynamic = try alloc.alloc(usize, capacity);
        self.times_dynamic = try alloc.alloc(i64, capacity);
        @memset(self.lens_dynamic.?, 0);
        @memset(self.times_dynamic.?, 0);
        self.max_items = capacity;
    }

    /// Frees the storage `resize` allocated from the allocator `resize` was
    /// given, and nothing else — the inline buffer needs no release, and the
    /// allocator itself stays the caller's.
    ///
    /// Exactly once: the fields are not cleared, so a second call frees the
    /// same three allocations again. Entries still queued are dropped with the
    /// storage, and a queue may still be used afterwards only through the
    /// inline buffer.
    pub fn deinitQueue(self: *DatagramQueue) void {
        if (self.allocator) |alloc| {
            if (self.bufs_dynamic) |b| alloc.free(b);
            if (self.lens_dynamic) |l| alloc.free(l);
            if (self.times_dynamic) |t| alloc.free(t);
        }
    }

    fn getBuf(self: *DatagramQueue, idx: usize) *[MAX_DATAGRAM_SIZE]u8 {
        if (self.bufs_dynamic) |b| return &b[idx];
        return &self.bufs_static[idx];
    }

    fn getLen(self: *DatagramQueue, idx: usize) *usize {
        if (self.lens_dynamic) |l| return &l[idx];
        return &self.lens_static[idx];
    }

    fn getTime(self: *DatagramQueue, idx: usize) *i64 {
        if (self.times_dynamic) |t| return &t[idx];
        return &self.times_static[idx];
    }

    fn effectiveCapacity(self: *const DatagramQueue) usize {
        return self.high_water_mark orelse self.max_items;
    }

    /// Copies `data` into the ring and stamps it with `now`, returning whether
    /// it was stored.
    ///
    /// False, with nothing stored and nothing changed, when the queue is at its
    /// effective capacity or `data.len` is over `MAX_DATAGRAM_SIZE`; both are
    /// the caller's to avoid, because `push` neither blocks nor grows. `data`
    /// is copied rather than borrowed and need not outlive the call, and
    /// `now` is nanoseconds on the same clock `popSkipExpired` and
    /// `peekDataSkipExpired` read to age it.
    pub fn push(self: *DatagramQueue, data: []const u8, now: i64) bool {
        if (self.count >= self.effectiveCapacity() or data.len > MAX_DATAGRAM_SIZE) return false;
        @memcpy(self.getBuf(self.tail)[0..data.len], data);
        self.getLen(self.tail).* = data.len;
        self.getTime(self.tail).* = now;
        self.tail = (self.tail + 1) % self.max_items;
        self.count += 1;
        return true;
    }

    /// Copies the head entry into `out` and drops it, returning its length.
    ///
    /// `null` when the queue is empty, and also when `out` is shorter than the
    /// entry: nothing is copied and nothing is dropped, so the entry stays at
    /// the head and a caller with a small buffer can call again with a larger
    /// one. `out` is untouched past the returned length. Does not read
    /// `max_age_ns`; use `popSkipExpired` for that.
    pub fn pop(self: *DatagramQueue, out: []u8) ?usize {
        if (self.count == 0) return null;
        const len = self.getLen(self.head).*;
        if (out.len < len) return null;
        @memcpy(out[0..len], self.getBuf(self.head)[0..len]);
        self.head = (self.head + 1) % self.max_items;
        self.count -= 1;
        return len;
    }

    /// Copies the head entry into `out` and drops it, returning its length,
    /// after dropping every entry ahead of it that `max_age_ns` has expired.
    ///
    /// `null` when nothing is left that has not expired, or when `out` is
    /// shorter than the entry that is due — the same leave-it-queued answer
    /// `pop` gives. Expired entries are discarded either way, so this is not a
    /// retry of the same call. With `max_age_ns` null this is exactly `pop`.
    pub fn popSkipExpired(self: *DatagramQueue, out: []u8, now: i64) ?usize {
        const max_age = self.max_age_ns orelse return self.pop(out);
        while (self.count > 0) {
            const age = now - self.getTime(self.head).*;
            if (age <= max_age) {
                return self.pop(out);
            }
            // Expired — skip this entry
            self.head = (self.head + 1) % self.max_items;
            self.count -= 1;
        }
        return null;
    }

    /// Whether nothing is queued. Reads `count`, so an entry that expired is
    /// still counted until something reads it.
    pub fn isEmpty(self: *const DatagramQueue) bool {
        return self.count == 0;
    }

    /// Whether `push` would refuse for want of capacity. That is the
    /// high water mark rather than the ring's own size when one is set, so it
    /// can be true while slots remain.
    pub fn isFull(self: *const DatagramQueue) bool {
        return self.count >= self.effectiveCapacity();
    }

    /// Queued entries, from 0 to the effective capacity.
    pub fn queueLen(self: *const DatagramQueue) usize {
        return self.count;
    }

    /// The length of the head entry without removing it; `null` when the queue
    /// is empty. Reads no clock, so an entry `max_age_ns` has expired is still
    /// reported.
    pub fn peekLen(self: *DatagramQueue) ?usize {
        if (self.count == 0) return null;
        return self.getLen(self.head).*;
    }

    /// The head entry's bytes, borrowed from the ring rather than copied, and
    /// `null` when the queue is empty. Invalidated by the next `pop`,
    /// `popSkipExpired` or `consume`, and by a `resize`; read no clock, so an
    /// expired entry is still returned.
    pub fn peekData(self: *DatagramQueue) ?[]const u8 {
        if (self.count == 0) return null;
        const len = self.getLen(self.head).*;
        return self.getBuf(self.head)[0..len];
    }

    /// The head entry's bytes as `peekData` returns them, after dropping every
    /// entry ahead of it that `max_age_ns` has expired. `null` when nothing is
    /// left that has not expired. The expired entries are gone either way;
    /// `now` is the same clock `push` stamps with.
    pub fn peekDataSkipExpired(self: *DatagramQueue, now: i64) ?[]const u8 {
        const max_age = self.max_age_ns orelse return self.peekData();
        while (self.count > 0) {
            const age = now - self.getTime(self.head).*;
            if (age <= max_age) {
                return self.peekData();
            }
            // Expired — skip this entry
            self.head = (self.head + 1) % self.max_items;
            self.count -= 1;
        }
        return null;
    }

    /// Drops the head entry without reading it, the other half of `peekData`.
    ///
    /// A no-op on an empty queue. It does not copy, does not read `max_age_ns`
    /// and does not free anything: the bytes stay in the ring until a later
    /// `push` overwrites that slot, so a caller holding a `peekData` slice must
    /// be done with it before calling this.
    pub fn consume(self: *DatagramQueue) void {
        if (self.count == 0) return;
        self.head = (self.head + 1) % self.max_items;
        self.count -= 1;
    }
};

/// One close, and the code and reason it carries.
///
/// `is_app` says which space `code` is in. An application close reports
/// `0x1c` — application error — and a transport close reports a code the
/// protocol defines, which is why the two need this flag rather than a
/// magnitude comparison.
///
/// Nothing here is owned: `reason` is borrowed, and its lifetime is the
/// producer's. `Connection.local_err` gets one from three places, and a caller
/// reading it must know which. A peer CONNECTION_CLOSE frame hands over
/// `reason` borrowed from the decoded packet, good until the next packet is
/// parsed — long enough to log, not long enough to keep.
/// `Connection.close` and `Connection.closeWithTransportError` instead store
/// the caller's own slice, which stays valid as long as the caller keeps it and
/// must outlive any read of `local_err`. A stateless reset stores a literal.
///
/// Copy `reason` if it has to outlive that.
pub const ConnectionError = struct {
    /// Whether `code` is an application error or a transport error.
    is_app: bool,
    /// The error code, in the space `is_app` names.
    code: u64,
    /// Human-readable reason, borrowed from whoever produced this value.
    reason: []const u8,
};

/// The four ECN codepoints, as the two low bits of an IP header carry them.
///
/// They are the values `RecvInfo.ecn` holds and `getEcnMark` answers with, and
/// the wire type is `u2` because two bits are all a codepoint takes. `ECT1` and
/// `ECT0` are the two marks a sender chooses between; `CE` is what a router
/// sets when it cannot forward the marking, and a path that sees one fails
/// validation (RFC 9000 §13.4.2.1).
pub const ECN_NOT_ECT: u2 = 0b00;
pub const ECN_ECT1: u2 = 0b01;
pub const ECN_ECT0: u2 = 0b10;
pub const ECN_CE: u2 = 0b11;

/// What one received datagram was, as the connection is told about it.
///
/// A value the caller fills in per datagram: where it came from and where it
/// was sent to are the two addresses the connection's path logic compares
/// against, `ecn` is the codepoint the IP header carried, and `datagram_size`
/// is how many bytes the *datagram* was, not this packet.
///
/// That last field is why it exists: a datagram may carry several coalesced
/// packets, and the anti-amplification ledger counts the datagram once. It
/// must therefore be the full size on the first packet and zero on the ones
/// after it, which `handleDatagram` does and a caller driving `recv` directly
/// has to do itself.
///
pub const RecvInfo = struct {
    to: address.Address,
    from: address.Address,
    // ECN codepoint from IP header (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
    ecn: u2 = ECN_NOT_ECT,
    // Size of the UDP datagram (for amplification limit accounting).
    // Set to the datagram size for the first packet; 0 for subsequent coalesced packets.
    datagram_size: u64 = 0,
};

/// What one connection is configured with, taken by value and read once at
/// construction.
///
/// Nothing here borrows: every field is an integer, a bool, an inline byte
/// array, or a struct of those, so a caller may release whatever it built the
/// value from as soon as the constructor returns. Both constructors copy what
/// they keep — the connection ids into the connection's own inline buffers,
/// `quic_lb` and `preferred_address` into fields of their own — so nothing in
/// this struct needs to outlive the call.
///
/// Durations are in milliseconds, matching the transport parameters that
/// carry them; the connection converts to nanoseconds and reconciles against
/// the peer's values once the handshake produces them. `null` on an optional
/// field means this side does not advertise that feature at all, which is a
/// different answer from advertising it with a value of zero: a zero idle
/// timeout advertises no limit while still running one locally.
///
/// Every field has a default, so `.{}` is a complete configuration: one that
/// advertises no datagrams, no preferred address and no tokens, offers
/// compatible version negotiation to no one, and probes no path MTU.
pub const ConnectionConfig = struct {
    /// Milliseconds advertised as `max_idle_timeout`, and the local idle timer
    /// a constructor starts with. Zero advertises no limit — but it does not
    /// disable the local timer: only a non-zero value overwrites the 30 s
    /// default this field also carries, and a connection that advertised zero
    /// still closes on its own idle timeout. After the handshake the effective
    /// value is the smaller of this and the peer's, or the peer's alone when
    /// this side advertised none (RFC 9000 §10.1).
    max_idle_timeout: u64 = 30_000,

    /// Bytes of connection-level flow control credit this side grants the peer
    /// (RFC 9000 §18.2), and the send window this side starts from. The
    /// peer's `initial_max_data` replaces it during the handshake, so this is
    /// the window in force before then and what the peer is told.
    initial_max_data: u64 = 16_777_216,

    /// Bytes the peer may send on each bidirectional stream this side opens
    /// (RFC 9000 §18.2). Local because those are the streams this side
    /// initiates, whichever side writes into them.
    initial_max_stream_data_bidi_local: u64 = 6_291_456,

    /// Bytes this side may send on each bidirectional stream the peer opens.
    /// Remote because those are the streams the peer initiates.
    initial_max_stream_data_bidi_remote: u64 = 6_291_456,

    /// Bytes this side may send on each unidirectional stream the peer opens.
    initial_max_stream_data_uni: u64 = 1_048_576,

    /// How many peer-initiated bidirectional streams may be open at once, and
    /// how many this side advertises it will open. The peer's value replaces
    /// it during the handshake for what this side may open, so this is the
    /// limit in force before then.
    initial_max_streams_bidi: u64 = 100,

    /// As `initial_max_streams_bidi`, for the peer's unidirectional streams.
    initial_max_streams_uni: u64 = 100,

    /// Bytes this side advertises for a DATAGRAM frame, its type and length
    /// fields included (RFC 9221). `null` does not advertise it, and support
    /// comes up only when both sides advertise a value — so with `null` here
    /// `sendDatagram` fails with `error.DatagramsNotEnabled` for the whole
    /// connection and `maxDatagramPayloadSize` answers null.
    ///
    /// This bounds the frame, not the application payload: what this side may
    /// actually send is `maxDatagramPayloadSize`, which takes the smaller of
    /// this and the peer's after subtracting packet-header, tag and frame
    /// overhead, and which `sendDatagram` does not enforce.
    max_datagram_frame_size: ?u64 = null,

    /// Enables the implemented two-path MP profile (path IDs zero and one).
    initial_max_path_id: ?u32 = null,
    max_remote_nat_traversal_addresses: ?u8 = null,
    address_discovery_role: observed.Role = .disabled,
    /// Pure caller policy for physical candidates and observed reports, never route ownership.
    candidateAdmission: ?*const fn (address.Address) bool = null,
    /// Lifted from the sending socket; IPv4-only sockets cannot probe IPv6.
    supportedIPv6: bool = true,

    /// The address a server offers the peer to migrate to, with the connection
    /// id and reset token that go with it (RFC 9000 §9.6). `null` offers none.
    /// Read only when the connection is a server, and only the connection id
    /// and token are used: an offer whose `getCid` is empty is not registered.
    /// Copied into the connection, so the caller keeps nothing.
    preferred_address: ?transport_params.PreferredAddress = null,

    /// The 16-byte key NEW_TOKEN frames are sealed under, on a server. `null`
    /// issues no token at all: `newTokenFrame` answers null and the peer is
    /// given nothing to reuse.
    ///
    /// Must be the key the receiving side validates with, which is
    /// `ConnectionManager`'s `retry_token_key` — it checks both Retry and
    /// NEW_TOKEN against that one key. A token sealed under a different key
    /// never validates, so the peer's address has to be validated the slow way
    /// again on every connection. Nothing sets this for you from
    /// `ConnectionManager.init`; setting it there is the caller's job.
    token_key: ?[16]u8 = null,

    /// Whether to offer Compatible Version Negotiation towards QUIC v2
    /// (RFC 9368/9369). On, this side advertises the Version Information
    /// transport parameter and adopts a supported version read off a peer
    /// packet through `switchVersion`; off, a packet of another version is
    /// left alone.
    ///
    /// A client that holds a resumption ticket for a later version it can
    /// speak starts that connection on the ticket's version, which is why a
    /// client turns this on to reach v2 at all.
    enable_v2: bool = false,

    /// Whether to leave Path MTU Discovery off (RFC 8899). On, the connection
    /// never starts DPLPMTUD once the handshake completes and so never sends a
    /// probe. Set it where the path MTU is known and probing would only spend
    /// the connection packets.
    disable_pmtud: bool = false,

    /// Server-side QUIC-LB encoding for the connection ids this side issues
    /// (RFC 9308), which a load balancer has to be able to read a routing
    /// prefix out of. `null` issues randomly drawn eight-byte ids.
    ///
    /// Read only by `acceptInto`, where it fixes the length of the initial
    /// SCID and of every id issued later; `connectInto` ignores it. Copied by
    /// value, so nothing is borrowed, and the key it carries is this side's
    /// alone — a peer decoding an id needs the same config out of band.
    quic_lb: ?quic_lb.Config = null,

    /// Milliseconds of silence after which a PING is sent, 0 for none. The
    /// period is converted to nanoseconds and clamped to half the idle timeout
    /// in force when it is computed, then clamped again once the negotiated
    /// idle timeout is known — so a period above that half never keeps a
    /// connection alive on its own. The PING itself is only sent after the
    /// handshake is confirmed, and a real deadline in `nextTimeoutNs` arms it;
    /// `sendKeepAlive` queues one by hand.
    keep_alive_period: u64 = 0,

    /// Entries per direction in the DATAGRAM queues, each holding at most one
    /// `MAX_DATAGRAM_SIZE` payload. At or below 32 the queues use their inline
    /// storage and this connection allocates nothing for them; above it both
    /// queues are grown from the connection's allocator during construction
    /// and `deinit` releases them.
    ///
    /// This is the ring's capacity, not the high water mark:
    /// `setIncomingDatagramHighWaterMark` and `setOutgoingDatagramHighWaterMark`
    /// lower how much of it is used without changing what is allocated.
    datagram_queue_capacity: usize = DatagramQueue.DEFAULT_MAX_ITEMS,

    /// Whether to close the connection with application error code 0 once
    /// every bidirectional stream this side opened has its FIN queued and
    /// nothing is left to retransmit.
    ///
    /// That is when the data has been handed to the sender, not when the peer
    /// has acknowledged it, and the close is coalesced with or follows the
    /// data so the peer receives both. It also needs at least one
    /// bidirectional stream to exist: a connection that opened none, or only
    /// unidirectional ones, never auto-closes this way and runs until the
    /// peer closes it or the idle timeout fires. Off, the connection never
    /// closes itself.
    close_when_idle: bool = false,

    /// The 16-byte key every stateless reset token this side advertises is
    /// derived from, which is what lets one listener's resets be recognised
    /// across the connections it issues. `null` draws a key per connection
    /// from the constructor's generator, which keeps the tokens unguessable
    /// but makes them differ on every connection.
    ///
    /// Must be the key the sending side signs its resets with — a reset naming
    /// a connection id whose token was derived under another key is not
    /// recognised as a reset. `ConnectionManager.init` overwrites this with
    /// its own `static_reset_key`, so set it there for a managed connection.
    ///
    /// Read only by `acceptInto`; `connectInto` draws a key from its generator
    /// whatever this says, because a client issues no resets.
    static_reset_key: ?[16]u8 = null,
};

// General queue for packets that can't be decrypted yet because the keys
// for their encryption level aren't installed (0-RTT before the early-data
// key, Handshake/1-RTT before those keys — e.g. a multi-Initial ClientHello
// or reordering). Mirrors quic-go's single `undecryptablePackets` queue
// (RFC 9001 §4.1.4); replayed when any read key is installed. Bounded for
// anti-amplification — cap matches quic-go's protocol.MaxUndecryptablePackets.
const UNDECRYPTABLE_MAX_PKTS = limits.undecryptable_max_pkts;
const UNDECRYPTABLE_BUF_LEN = limits.undecryptable_buf_len;

const UndecryptablePackets = struct {
    buf: [UNDECRYPTABLE_BUF_LEN]u8 = undefined,
    off: [UNDECRYPTABLE_MAX_PKTS]u32 = undefined,
    plen: [UNDECRYPTABLE_MAX_PKTS]u16 = undefined,
    info: RecvInfo = undefined,
    used: u32 = 0,
    count: u8 = 0,

    fn reset(self: *UndecryptablePackets) void {
        self.used = 0;
        self.count = 0;
    }

    /// Store a raw packet to replay later. Bounded; excess silently dropped
    /// (RFC 9001 §4.1.4 allows dropping when the buffer is full).
    fn push(self: *UndecryptablePackets, bytes: []const u8, rinfo: RecvInfo) void {
        if (self.count >= UNDECRYPTABLE_MAX_PKTS) return;
        if (self.used + bytes.len > UNDECRYPTABLE_BUF_LEN) return;
        @memcpy(self.buf[self.used..][0..bytes.len], bytes);
        self.off[self.count] = self.used;
        self.plen[self.count] = @intCast(bytes.len);
        if (self.count == 0) self.info = rinfo;
        self.used += @intCast(bytes.len);
        self.count += 1;
    }
};

/// This is the central state machine that manages the QUIC protocol.
/// Following quic-go's architecture, the connection runs an event-driven
/// loop that processes received packets, handles timers, and sends data.
///
/// It is a value about 185 KB across and it borrows inside itself:
/// `local_params` and the handshake's transport parameters point at its own
/// connection-id arrays. So its address is fixed for its whole life —
/// `acceptInto` and `connectInto` build one in place, a caller that keeps one
/// owns the storage by pointer, and moving the value afterwards leaves every
/// one of those borrows naming bytes that are no longer this connection's. See
/// `local_params` for which parameters those are.
///
/// `allocator` is stored: it is the one every allocation comes from and the
/// one `deinit` frees into, and a caller must keep it alive for the
/// connection's whole life. One `deinit`, on storage the caller owns, releases
/// everything above it.
///
/// A constructor that returns an error releases what it built and leaves `conn`
/// torn down rather than half-built, so the caller has nothing to release —
/// the value it was building was never returned — and must not call `deinit`
/// for a construction that failed.
///
/// Two parameters rather than four: `now` is an argument of every ingress,
/// egress and timer pass and `random` of every draw, so the whole state
/// machine can be driven in virtual time from a seeded generator with no clock
/// and no entropy source behind it.
pub const Connection = struct {
    /// The QUIC version this connection is speaking, as the four bytes of a
    /// long header carry it. It starts as the version the first flight was
    /// built with and moves only when `switchVersion` adopts a negotiated one;
    /// 0-RTT packets keep the first-flight version whatever this says.
    version: u32 = undefined,
    /// Whether this side accepted rather than dialled. `acceptInto` sets it
    /// from its `comptime` argument and `connectInto` leaves it false, and
    /// several protocol rules branch on it, so it is fixed for the connection's
    /// life rather than a mode that can change.
    is_server: bool,
    /// Where the connection is in its lifecycle; `State` documents the order
    /// and that it never moves back. Every ingress and egress entry point
    /// reads it rather than tracking transitions itself.
    state: State = .first_flight,
    /// Stored, not owned: every allocation this connection makes comes from
    /// this allocator and `deinit` frees into it, so it must stay valid until
    /// after `deinit`. A constructor takes it by value and never releases it.
    allocator: std.mem.Allocator,

    // Connection IDs
    /// Inline storage for the destination connection id, which is the id this
    /// side sends to and the peer receives. Owned by the connection:
    /// `local_params`, the packer and `peerAddress` reach it through views, so
    /// a copy of the struct that moves the bytes out from under them is the
    /// one way to invalidate all three. Only `dcid[0..dcid_len]` is the id.
    dcid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    /// Bytes of `dcid` that are the id, 0 to
    /// `packet.CONNECTION_ID_MAX_SIZE`. A 1-RTT packet carries no peer id, so
    /// zero is a real value here and not an uninitialised one.
    dcid_len: u8 = 0,
    /// Inline storage for this side's own connection id, as
    /// `local_params.initial_source_connection_id` and every long header
    /// report it. Owned on the same terms as `dcid`. Only `scid[0..scid_len]`
    /// is the id.
    scid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    /// Bytes of `scid` that are the id, 0 to
    /// `packet.CONNECTION_ID_MAX_SIZE`.
    scid_len: u8 = 0,

    // TLS 1.3 handshake (null if not configured with TlsConfig)
    /// Heap-allocated: the handshake state is ~52 KB, which by value made it
    /// the single largest member of Connection. It cannot be released early —
    /// advanceHandshake still reads it after handshake_confirmed to process
    /// NewSessionTicket — so this buys size, not lifetime.
    tls13_hs: ?*tls13.Tls13Handshake = null,

    // Network paths (active + candidate for migration)
    /// The active path and the migration candidate. Both start unset; the
    /// constructor fills one and leaves the other alone until a migration
    /// proposes a path.
    paths: [2]NetworkPath = .{ .{}, .{} },
    /// Which of `paths` is active, 0 or 1. `peerAddress`, `localAddress` and
    /// the amplification ledger all read through it, so it is what makes a
    /// migration visible to them.
    active_path_idx: u8 = 0,
    /// Whether a constructor has established the initial path. False only on a
    /// value no constructor built, where both paths are unset and every
    /// address read through `paths` is `address.Address.unset`.
    path_initialized: bool = false,

    native_paths: native_path.State = .{},
    path1_transport: ?*PathTransport = null,
    transport_path: u8 = 0,
    receive_path: u8 = 0,
    send_path: u8 = 0,
    path_control: [2]frame_mod.PendingFrameQueue = .{ .{}, .{} },
    nat_state: ?native_nat_state.State = null,
    candidateAdmission: ?*const fn (address.Address) bool = null,
    supportedIPv6: bool = true,
    observed_paths: [2]observed.PathState = .{ .{}, .{} },
    observed_next_sequence: u64 = 0,
    last_send_peer: address.Address = .unset,
    last_send_local: address.Address = .unset,
    last_send_ecn: u2 = 0,
    received_peer: address.Address = .unset,
    received_local: address.Address = .unset,
    nat_reply: ?NatReply = null,
    direct_ready: ?struct { local: address.Address, peer: address.Address } = null,
    challenge_queued: [2]bool = .{ false, false },
    challenge_retry_queued: [2]bool = .{ false, false },
    challenge_full_size_sent: [2]bool = .{ false, false },
    last_send_off_path: bool = false,
    receiving_packet: bool = false,
    local_path_status: [2]native_path.Status = .{ .available, .backup },
    local_path_status_seq: [2]u64 = .{ 0, 0 },
    observed_queued: [2]?u64 = .{ null, null },
    received_cid: [20]u8 = .{0} ** 20,
    received_cid_len: u8 = 0,

    // Packet number spaces and crypto
    /// The three packet number spaces, indexed by `packet.Epoch`: Initial,
    /// Handshake and Application. 0-RTT is not one of them — a 0-RTT packet
    /// carries Application packet numbers and is opened with the early-data
    /// key instead, so `early_data_open` is what distinguishes it.
    pkt_num_spaces: [3]packet.PacketNumSpace = .{
        packet.PacketNumSpace{},
        packet.PacketNumSpace{},
        packet.PacketNumSpace{},
    },

    // New subsystems
    pkt_handler: ack_handler.PacketHandler = undefined,
    /// Reused by every ACK frame: a fresh one regrew its lists each time.
    ack_result: ack_handler.AckResult = .{},
    cc: congestion.Cubic = congestion.Cubic.init(),
    pacer: congestion.Pacer = congestion.Pacer.init(),
    conn_flow_ctrl: flow_control.ConnectionFlowController = undefined,
    streams: stream_mod.StreamsMap = undefined,
    crypto_streams: crypto_stream.CryptoStreamManager = undefined,
    /// Builds packets through `sendAt`, which applies the congestion window,
    /// pacer and amplification budget. Its inline CID copies do not make the
    /// enclosing connection movable or safe to copy.
    packer: packet_packer.PacketPacker = undefined,

    // Transport parameters
    /// This side's transport parameters.
    ///
    /// The three CID slices borrow this connection's inline buffers, and the
    /// handshake keeps the same views. Constructors copy all incoming CID bytes
    /// and bind these views after `conn` occupies its final address. Neither the
    /// connection nor these views may move or outlive `deinit`.
    ///
    local_params: transport_params.TransportParams = .{},
    /// The peer's transport parameters, or `null` until the handshake
    /// delivers them and `null` for good on a connection that closed first.
    /// Unlike `local_params` these are owned by value, except for the three
    /// connection-id slices, which borrow the peer's bytes held elsewhere in
    /// this struct.
    peer_params: ?transport_params.TransportParams = null,

    // Pending control frames queue
    pending_frames: frame_mod.PendingFrameQueue = .{},
    /// Frames the peer must see that found `pending_frames` full. Moved over
    /// before each send; bounded by what we have in flight or have issued.
    control_retry: std.ArrayListUnmanaged(frame_mod.PendingControlFrame) = .empty,

    // Pool of peer-issued connection IDs for migration
    peer_cid_pool: ConnectionIdPool = .{},
    /// Sequence numbers we have sent RETIRE_CONNECTION_ID for and the peer
    /// has not yet acknowledged. Capped at twice our
    /// active_connection_id_limit; a peer pushing past it gets
    /// CONNECTION_ID_LIMIT_ERROR.
    retiring_cids: std.ArrayListUnmanaged(u64) = .empty,

    // Pool of locally-issued connection IDs (RFC 9000 §5.1)
    local_cid_pool: LocalCidPool = .{},

    // Static key for deterministic stateless reset tokens (RFC 9000 §10.3)
    static_reset_key: [16]u8 = .{0} ** 16,

    // QUIC-LB CID encoding config (server-side, for load balancer routing)
    /// The QUIC-LB config this connection issues ids under, copied from
    /// `ConnectionConfig.quic_lb` by a server; `null` without it. Read when the
    /// connection replaces a retired id, so it is what decides whether the
    /// replacement carries a routing prefix.
    quic_lb_config: ?quic_lb.Config = null,

    // Key update manager for 1-RTT key rotation (RFC 9001 Section 6)
    key_update: ?quic_crypto.KeyUpdateManager = null,

    // Whether PMTUD is disabled
    /// Whether this connection skips Path MTU Discovery, copied from
    /// `ConnectionConfig.disable_pmtud`. Read once, when the handshake
    /// completes and would otherwise have started it.
    disable_pmtud: bool = false,

    /// The keep-alive interval actually in force, in nanoseconds, or 0 when
    /// none is. Derived from `ConnectionConfig.keep_alive_period` clamped to
    /// half the idle timeout, then re-clamped once the negotiated idle timeout
    /// is known, so it is a value the caller supplied only indirectly.
    keep_alive_interval_ns: i64 = 0,
    /// Whether a keep-alive PING is outstanding. Cleared by every received
    /// packet, which is what makes silence measurable from
    /// `last_packet_received_time` rather than from the last ping.
    keep_alive_ping_sent: bool = false,
    /// Whether to close the connection once every bidirectional stream has its
    /// FIN queued, copied from `ConnectionConfig.close_when_idle`. A
    /// connection with no bidirectional stream never auto-closes.
    close_when_idle: bool = false,
    /// Consecutive PTO fires that found nothing to send, reset by the next one
    /// that does. Unlike the packet handler's PTO count it survives received
    /// ACKs, so it measures an idle connection rather than a lossy one. Nothing
    /// in this connection reads it to make a decision; it is a counter a
    /// caller watching `Connection` can use.
    idle_pto_count: u32 = 0,

    // Path MTU Discovery (DPLPMTUD, RFC 8899)
    mtu_discoverer: mtu_mod.MtuDiscoverer = .{},
    /// The last MAX_STREAM_DATA scan stopped early on a full frame queue.
    window_scan_pending: bool = false,

    // HANDSHAKE_DONE delivery tracking (server only)
    // True from handshake completion until the client ACKs a packet carrying HANDSHAKE_DONE.
    // Used to re-arm packer.send_handshake_done on PTO/loss retransmission.
    handshake_done_pending: bool = false,

    // QUIC DATAGRAM support (RFC 9221)
    datagram_recv_queue: DatagramQueue = .{},
    datagram_send_queue: DatagramQueue = .{},
    /// Whether both sides advertised a DATAGRAM frame size, which is what
    /// makes `sendDatagram` and `recvDatagram` work. Set during the handshake
    /// and never by a caller: with it false, `sendDatagram` answers
    /// `error.DatagramsNotEnabled` and `maxDatagramPayloadSize` answers null.
    datagrams_enabled: bool = false,

    // Connection-level statistics counters
    /// Packets `sendAt` has emitted, across every epoch. It counts packets,
    /// not datagrams and not bytes; `getStats` reports bytes per path.
    total_packets_sent: u64 = 0,
    /// Packets this side has received and accepted, all epochs.
    total_packets_received: u64 = 0,
    /// Packets declared lost by loss detection, all epochs.
    total_packets_lost: u64 = 0,
    /// Received DATAGRAM frames dropped because the receive queue was full or
    /// the frame was too large for one entry.
    datagrams_dropped_incoming: u64 = 0,
    /// Packets that carried a datagram and were then declared lost, counted
    /// per packet rather than per datagram, so one lost packet can take several
    /// queued datagrams with it.
    datagrams_lost_outgoing: u64 = 0,

    /// Optional zero-copy datagram callback, `null` to copy into the ring
    /// instead. Set, each incoming DATAGRAM frame is handed over during packet
    /// processing inside `recv` rather than queued, which is what removes the
    /// copy on the receive path.
    ///
    /// `data` points into the decrypted packet buffer, so it is valid only for
    /// the duration of the call and a callee that keeps it must copy. It runs
    /// on the thread that called `recv`, before that call returns, which means
    /// it may reenter the connection only through calls that do not mutate the
    /// packet being processed. Nothing is retained: a callback that outlives
    /// this connection has to hold what it needs itself.
    datagram_recv_callback: ?*const fn (data: []const u8, ctx: ?*anyopaque) void = null,
    /// Passed to `datagram_recv_callback` unchanged and never dereferenced by
    /// this connection, so it may be `null`. Whatever it points at must stay
    /// live for as long as the callback is installed.
    datagram_recv_ctx: ?*anyopaque = null,

    // draft-ietf-quic-ack-frequency
    /// Whether the peer's transport parameters carry `min_ack_delay`, which is
    /// how it says it will send ACK_FREQUENCY frames. This side advertises its
    /// own unconditionally, so the flag is the peer's answer alone, and it
    /// stays false until those parameters arrive: an ACK_FREQUENCY frame read
    /// while it is false closes the connection as a protocol violation, since
    /// nothing was ever negotiated for one.
    peer_supports_ack_freq: bool = false,

    // 0-RTT (early data) keys
    /// The key 0-RTT packets are opened with, `null` before the handshake
    /// produces one and after it completes. Both directions are labelled for
    /// the version the first flight was built with, and neither key moves when
    /// `switchVersion` adopts a negotiated version — that is why a 0-RTT
    /// packet keeps the first-flight version in its long header.
    early_data_open: ?quic_crypto.Open = null,
    /// The key this side seals 0-RTT packets with, `null` on a connection that
    /// offered no early data and after the handshake completes.
    early_data_seal: ?quic_crypto.Seal = null,

    // Packets received before the keys for their encryption level were
    // available. Buffered (not dropped) and replayed once a read key is
    // installed. See UndecryptablePackets above.
    undecryptable: UndecryptablePackets = .{},
    pending_replay_undecryptable: bool = false,
    replaying_undecryptable: bool = false,

    /// The session ticket the peer issued, for an application that wants to
    /// keep one across connections; `null` until a NewSessionTicket arrives and
    /// on a connection that never completed. It is the connection's own copy,
    /// not a borrow, so it stays readable until the next one replaces it or
    /// `deinit` runs.
    session_ticket: ?tls13.SessionTicket = null,
    /// The transport parameters remembered from the ticket this connection
    /// resumed, which is what 0-RTT limits are checked against (RFC 9000
    /// §7.4.1); `null` on a connection that is not resuming.
    remembered_params: ?tls13.SessionTicket = null,

    /// Inline storage for the NEW_TOKEN the peer sent, copied in so the token
    /// outlives the packet that carried it. Only `new_token_buf[0..new_token_len]`
    /// is the token, and a token longer than the buffer is not one this
    /// connection keeps at all.
    new_token_buf: [packet.TOKEN_MAX_LEN]u8 = .{0} ** packet.TOKEN_MAX_LEN,
    /// Bytes of `new_token_buf` holding a token; 0 when none was received,
    /// which is what makes `getNewToken` answer null.
    new_token_len: u8 = 0,

    /// The key this side seals NEW_TOKENs under, on a server. Null means it
    /// has none, and it issues no token at all: a token sealed under a key
    /// every reader could guess proves nothing and outlives the connection
    /// that issued it. Shared with the Retry token key; see
    /// `ConnectionConfig.token_key`.
    token_key: ?[16]u8 = null,

    // ECN validation: peer-reported ECN counts from ACK_ECN frames
    // (RFC 9000 §13.4.2.1). Each array is indexed by the same three packet
    // number spaces as `pkt_num_spaces`, and the counts only ever increase —
    // that is what tells validation that a path really carried the marking.
    peer_ecn_ect0: [3]u64 = .{ 0, 0, 0 },
    peer_ecn_ect1: [3]u64 = .{ 0, 0, 0 },
    peer_ecn_ce: [3]u64 = .{ 0, 0, 0 },

    // ECN validation state machine (RFC 9000 §13.4.2.1)
    ecn_validator: ecn.EcnValidator = .{},

    // Connection state
    got_peer_conn_id: bool = false,
    peer_max_cid_seq: u64 = 0,
    active_cid_seq: u64 = 0,
    /// Sequence number of the peer CID we send to; 0 is the handshake DCID.
    dcid_seq: u64 = 0,
    /// Why this side closed the connection, or `null` while it is still open.
    /// Set by `close`, by `closeWithTransportError`, by any transport error
    /// the state machine raises, and by a stateless reset, and never cleared
    /// afterwards. `reason` inside it is borrowed — see `ConnectionError` for
    /// whose lifetime applies in each case.
    local_err: ?ConnectionError = null,
    /// The peer ended the connection with a stateless reset (RFC 9000 §10.3).
    received_stateless_reset: bool = false,
    handshake_confirmed: bool = false,
    /// The value last sent in a 1-RTT header, toggled so a peer that echoes it
    /// can measure its own RTT (RFC 9000 §17.4).
    spin_bit: bool = false,
    /// Largest 1-RTT packet number received, or `null` before the first one.
    /// The spin bit is toggled against its parity, which is why the exact value
    /// matters and not just its low bit.
    largest_pn_received: ?u64 = null,
    /// Whether Compatible Version Negotiation was enabled, copied from
    /// `ConnectionConfig.enable_v2`. Read on every packet to decide whether a
    /// peer version may move the connection through `switchVersion`.
    enable_v2: bool = false,
    /// Inline storage for the DCID the Initial keys were derived from, kept
    /// because `switchVersion` has to re-derive them from the same id. Unlike
    /// `dcid` this does not change when the connection moves to another peer
    /// id: it is the first flight's, for the whole life.
    initial_dcid_buf: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    /// Bytes of `initial_dcid_buf` holding that id.
    initial_dcid_len: u8 = 0,

    /// Probes a PTO owes, 0 to 2, each of which bypasses congestion control for
    /// one packet (RFC 9002 §6.2.4). It is a count of packets still to send, not
    /// a deadline, and it is spent by `sendAt` rather than by the clock.
    pto_probe_pending: u2 = 0,

    // Connection close state (RFC 9000 Section 10)
    /// Nanoseconds on the caller's clock at which the close began, 0 before
    /// one does. The draining deadline is this plus three PTOs, so it is what
    /// a caller reads to know when a closed connection will give up.
    closing_start_time: i64 = 0,
    /// The CONNECTION_CLOSE packet built once and kept, so a retransmission is
    /// a copy rather than a rebuild. Only `close_pkt_buf[0..close_pkt_len]` is
    /// the packet, and 0 in `close_pkt_len` says there is none kept: either
    /// none has been built, or the flight that was built did not fit these 256
    /// bytes and is rebuilt on the next send instead. A closing connection also
    /// owes the CRYPTO data it never sent, so its flight is a whole datagram
    /// and often longer than the cache — and a prefix of a packet is not a
    /// packet, because the Length field inside it covers bytes the peer never
    /// received (RFC 9000 §12.2).
    close_pkt_buf: [256]u8 = undefined,
    /// Bytes of `close_pkt_buf` holding that packet, 0 when none is kept.
    close_pkt_len: u16 = 0,
    needs_close_retransmit: bool = false,
    /// Packets received while closing. The close is resent only when this
    /// reaches a power of two, so a peer (or a spoofer) cannot make us
    /// answer each packet 1:1 (RFC 9000 10.2.1).
    close_trigger_count: u64 = 0,

    /// Original DCID for client Retry verification and server transport parameters.
    odcid_buf: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    odcid_len: u8 = 0,
    /// Server Retry SCID owned by the connection; the transport parameter views it.
    retry_scid_buf: [packet.CONNECTION_ID_MAX_SIZE]u8 = @splat(0),
    retry_received: bool = false,
    /// Inline storage for the token this side sends in its Initial — a Retry
    /// token it received, or a NEW_TOKEN a caller passed to `connectInto`. It
    /// is copied so the token outlives the buffer it arrived in, and the
    /// packer holds a view of it that stops being the current token once a
    /// Retry replaces it.
    retry_token_buf: [256]u8 = .{0} ** 256,
    /// Bytes of `retry_token_buf` holding a token; 0 when none is being sent.
    retry_token_len: u16 = 0,

    // Timing
    /// Nanoseconds on the caller's clock at which a packet was last received.
    /// Every received packet stamps it, and it is what the idle timeout and the
    /// keep-alive both measure silence from.
    last_packet_received_time: i64 = 0,
    /// Nanoseconds on the caller's clock at which `sendAt` last emitted a
    /// packet. Only the idle timeout before the handshake is confirmed reads
    /// it; afterwards silence is measured from the last packet received.
    last_packet_sent_time: i64 = 0,
    /// Nanoseconds on the caller's clock at which this connection was built,
    /// which is what the client's anti-deadlock PTO measures from.
    creation_time: i64 = 0,
    /// The idle timeout in force, in nanoseconds, 30 s until configuration and
    /// the peer's value say otherwise. It is a lower bound rather than the
    /// whole deadline: `nextTimeoutNs` and `onTimeout` never fire before three
    /// base PTOs, whichever is longer.
    idle_timeout_ns: i64 = 30_000_000_000,
    const NatReply = struct {
        peer: address.Address,
        local: address.Address,
        response: [8]u8,
        challenge: [8]u8,
    };

    pub const RoundState = native_nat_state.RoundState;
    pub const PathStatus = native_path.Status;

    pub const PathTransport = struct {
        handler: ack_handler.PacketHandler,
        space: packet.PacketNumSpace = .{},
        cc: congestion.Cubic = congestion.Cubic.init(),
        pacer: congestion.Pacer = congestion.Pacer.init(),
        mtu: mtu_mod.MtuDiscoverer = .{},
        ecn_state: ecn.EcnValidator = .{},
        peer_ecn_ect0: u64 = 0,
        peer_ecn_ect1: u64 = 0,
        peer_ecn_ce: u64 = 0,
        probe_pending: u2 = 0,
        peer_cids: ConnectionIdPool = .{},
        dcid: [20]u8 = .{0} ** 20,
        dcid_len: u8 = 0,
        dcid_seq: u64 = 0,
        peer_retire_prior_to: u64 = 0,
        next_local_cid_seq: u64 = 0,
        retiring_cids: std.ArrayListUnmanaged(u64) = .empty,
    };

    pub const PathSnapshot = struct {
        id: u8,
        local: address.Address,
        peer: address.Address,
        validated: bool,
        selected: bool,
        status: native_path.Status,
        status_seq: ?u64,
        state: PathValidationState,
        sent: u64,
        received: u64,
    };

    pub fn multipathNegotiated(self: *const Connection) bool {
        const peer = self.peer_params orelse return false;
        return self.local_params.initial_max_path_id != null and peer.initial_max_path_id != null;
    }

    fn ensurePathTransport(self: *Connection) !*PathTransport {
        if (self.path1_transport) |value| return value;
        const value = try self.allocator.create(PathTransport);
        value.* = .{ .handler = ack_handler.PacketHandler.init(self.allocator) };
        self.path1_transport = value;
        return value;
    }

    fn activateTransport(self: *Connection, id: u8) void {
        self.transport_path = id;
    }

    fn packetHandler(self: *const Connection) *ack_handler.PacketHandler {
        return if (self.transport_path == 1)
            &self.path1_transport.?.handler
        else
            &@constCast(self).pkt_handler;
    }

    fn pathCongestion(self: *const Connection) *congestion.Cubic {
        return if (self.transport_path == 1)
            &self.path1_transport.?.cc
        else
            &@constCast(self).cc;
    }

    fn pathPacer(self: *const Connection) *congestion.Pacer {
        return if (self.transport_path == 1)
            &self.path1_transport.?.pacer
        else
            &@constCast(self).pacer;
    }

    fn pathMTU(self: *const Connection) *mtu_mod.MtuDiscoverer {
        return if (self.transport_path == 1)
            &self.path1_transport.?.mtu
        else
            &@constCast(self).mtu_discoverer;
    }

    fn pathECN(self: *const Connection) *ecn.EcnValidator {
        return if (self.transport_path == 1)
            &self.path1_transport.?.ecn_state
        else
            &@constCast(self).ecn_validator;
    }

    fn pathProbePending(self: *const Connection) *u2 {
        return if (self.transport_path == 1)
            &self.path1_transport.?.probe_pending
        else
            &@constCast(self).pto_probe_pending;
    }

    pub fn openPath(
        self: *Connection,
        local: address.Address,
        peer: address.Address,
        now: i64,
        random: std.Random,
    ) PathError!u8 {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) {
            return error.ClosedPath;
        }
        if (!self.multipathNegotiated()) return error.MultipathNotNegotiated;
        if (!self.handshake_confirmed) return error.HandshakeNotConfirmed;
        if (self.is_server) return error.ServerSideNotAllowed;
        if (local == .unset or peer == .unset) return error.InvalidAddress;
        if (!self.native_paths.negotiated) {
            self.native_paths = try native_path.process(self.native_paths, .{ .negotiate = .{
                .local_max = self.local_params.initial_max_path_id,
                .peer_max = self.peer_params.?.initial_max_path_id,
            } });
        }
        const other = try self.ensurePathTransport();
        if (other.dcid_len == 0) return error.NoPathConnectionId;
        self.native_paths = try native_path.process(self.native_paths, .{ .open = .{ .id = 1, .is_server = false } });
        self.paths[1] = NetworkPath.init(local, peer, false);
        other.ecn_state.start();
        if (!self.disable_pmtud) other.mtu.start();
        try self.probePath(1, now, random);
        return 1;
    }

    pub fn selectPath(self: *Connection, id: u8) PathError!void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) {
            return error.ClosedPath;
        }
        if (id >= 2) return error.InvalidPathId;
        self.native_paths.entries[id].validated = self.paths[id].is_validated;
        self.native_paths = try native_path.process(self.native_paths, .{ .select = id });
        if (self.local_path_status[id] != .available) {
            self.local_path_status[id] = .available;
            self.local_path_status_seq[id] += 1;
            self.pushReliable(.{ .path_status_available = .{
                .path_id = id,
                .status_seq_no = self.local_path_status_seq[id],
            } });
        }
        self.active_path_idx = id;
    }

    pub fn probePath(self: *Connection, id: u8, now: i64, random: std.Random) PathError!void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) {
            return error.ClosedPath;
        }
        if (id >= 2) return error.InvalidPathId;
        if (id != 0 and !self.multipathNegotiated()) return error.MultipathNotNegotiated;
        const entry = self.native_paths.entries[id];
        if (!entry.opened or entry.abandoned) return error.ClosedPath;
        const challenge = self.paths[id].validator.startChallenge(now, random);
        self.path_control[id].push(.{ .path_challenge = challenge });
        self.challenge_queued[id] = true;
        self.challenge_full_size_sent[id] = false;
    }

    pub fn pathSnapshot(self: *const Connection, id: u8) ?PathSnapshot {
        if (id >= 2) return null;
        const entry = self.native_paths.entries[id];
        if (!entry.opened or entry.abandoned) return null;
        if (!self.path_initialized) return null;
        const path = &self.paths[id];
        return .{
            .id = id,
            .local = path.local_addr,
            .peer = path.peer_addr,
            .validated = path.is_validated,
            .selected = self.active_path_idx == id,
            .status = self.local_path_status[id],
            .status_seq = entry.status_seq,
            .state = path.validator.state,
            .sent = path.bytes_sent,
            .received = path.bytes_received,
        };
    }

    pub fn lastSendPeer(self: *const Connection) *const address.Address {
        return &self.last_send_peer;
    }

    pub fn lastSendLocal(self: *const Connection) *const address.Address {
        return &self.last_send_local;
    }

    pub fn lastSendPath(self: *const Connection) u8 {
        return self.send_path;
    }

    pub fn lastSendEcn(self: *const Connection) u2 {
        return self.last_send_ecn;
    }

    pub fn peerPathCidEntries(self: *const Connection, id: u8) []const ConnectionIdEntry {
        if (id == 0) return &self.peer_cid_pool.entries;
        if (id == 1) {
            if (self.path1_transport) |other| return &other.peer_cids.entries;
        }
        return &.{};
    }

    pub fn peerPathCidGeneration(self: *const Connection, id: u8) u32 {
        if (id == 0) return self.peer_cid_pool.generation;
        if (id == 1) {
            if (self.path1_transport) |other| return other.peer_cids.generation;
        }
        return 0;
    }

    /// Builds a server or client connection in `conn`. On success `conn` is
    /// fully built and ready to use; on any failure — `error.PacketError`, an
    /// allocation that could not be made, or `error.InternalError` from a TLS
    /// handshake whose transport parameters could not be encoded — everything
    /// this built is released, including a handshake that was allocated and not
    /// yet built into, and the storage is torn down, so a caller does not call
    /// `deinit` for a construction that returned an error.
    ///
    /// `conn` is the caller's own storage and has to stay at that address for
    /// the connection's whole life: `local_params` borrows the connection ids
    /// out of it, and the handshake keeps a copy of those parameters and
    /// encodes them again.
    ///
    /// Header, original-DCID and Retry-SCID bytes are copied into the
    /// connection's own inline buffers and need only last through this call;
    /// they must not alias `conn`. Each CID must be at most 20 bytes,
    /// otherwise `error.PacketError` precedes allocation. Every connection id
    /// this call keeps is therefore owned by `conn` and released by `deinit`
    /// with the rest of it, never by the caller.
    ///
    /// `config` borrows nothing: it is taken by value and holds only integers,
    /// inline arrays and inline structs, and what the connection keeps of it
    /// is copied. So the caller may release whatever it built the config from
    /// as soon as this returns. `tls_config` is the opposite — it is copied but
    /// its slices are borrowed, so the certificate chain, the private key, the
    /// ALPN strings and any resumption ticket it points at must outlive the
    /// connection.
    ///
    /// `allocator` is retained rather than borrowed-and-released: it is stored
    /// in `conn` and is what `deinit` frees into, so it must stay valid until
    /// after that one call.
    ///
    /// `now` is the instant the connection is created at and `random` the
    /// generator its own CIDs and reset key come from; neither is read from
    /// the process, so a server can be built inside a test at a chosen time.
    pub fn acceptInto(
        conn: *Connection,
        allocator: std.mem.Allocator,
        header: packet.Header,
        local: address.Address,
        remote: address.Address,
        comptime is_server: bool,
        config: ConnectionConfig,
        tls_config: ?tls13.TlsConfig,
        odcid: ?[]const u8,
        retry_scid: ?[]const u8,
        now: i64,
        random: std.Random,
    ) !void {
        try validateNativeConfig(config);
        // A 1-RTT packet carries no SCID to answer to. A long header's may be
        // empty (RFC 9000 §5.1) — Safari's is — so test the type, not the length.
        if (is_server and header.packet_type == .one_rtt) return error.PacketError;
        if (header.dcid.len > packet.CONNECTION_ID_MAX_SIZE) return error.PacketError;
        if (header.scid.len > packet.CONNECTION_ID_MAX_SIZE) return error.PacketError;
        if (odcid) |cid| {
            if (cid.len > packet.CONNECTION_ID_MAX_SIZE) return error.PacketError;
        }
        if (retry_scid) |cid| {
            if (cid.len > packet.CONNECTION_ID_MAX_SIZE) return error.PacketError;
        }

        var initial_path = NetworkPath.init(local, remote, true);
        // If Retry was used, the path is already validated
        if (odcid != null) {
            initial_path.is_validated = true;
        }
        conn.* = Connection{
            .allocator = allocator,
            .version = header.version,
            .is_server = is_server,
            .paths = .{ initial_path, undefined },
            .path_initialized = true,
            .creation_time = now,
            .last_packet_received_time = now,

            // Initialize new subsystems
            .pkt_handler = ack_handler.PacketHandler.init(allocator),
            .conn_flow_ctrl = flow_control.ConnectionFlowController.init(
                config.initial_max_data,
                6 * 1024 * 1024,
            ),
            .streams = stream_mod.StreamsMap.init(allocator, is_server),
            .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),
        };

        // Everything below this line can allocate, and a failure there leaves
        // a connection that is half built. `deinit` is written for a fully
        // built one and is safe here because the literal above initialises
        // every member it frees, so the TLS handshake, the datagram queues and
        // the stream maps are all in their empty state until something puts
        // something in them.
        errdefer conn.deinit();

        // Set connection IDs:
        // Server: dcid = client's SCID (for sending TO client), scid = our generated CID
        // Client: dcid = header.dcid, scid = header.scid
        if (is_server) {
            conn.dcid_len = @intCast(header.scid.len);
            @memcpy(conn.dcid[0..header.scid.len], header.scid);
            if (config.quic_lb) |lb_config| {
                // Use QUIC-LB encoded CID for load balancer routing
                const scid_len = quic_lb.cidLength(&lb_config);
                conn.scid_len = scid_len;
                quic_lb.generateCid(&lb_config, conn.scid[0..scid_len], random);
                conn.quic_lb_config = lb_config;
            } else {
                conn.scid_len = 8;
                generateConnectionId(conn.scid[0..8], random);
            }
            conn.got_peer_conn_id = true;
        } else {
            conn.dcid_len = @intCast(header.dcid.len);
            @memcpy(conn.dcid[0..header.dcid.len], header.dcid);
            conn.scid_len = @intCast(header.scid.len);
            @memcpy(conn.scid[0..header.scid.len], header.scid);
        }

        if (config.static_reset_key) |k| {
            conn.static_reset_key = k;
        } else {
            random.bytes(&conn.static_reset_key);
        }

        // Register initial SCID in local CID pool with deterministic token
        conn.local_cid_pool.registerInitialCid(
            conn.scid[0..conn.scid_len],
            conn.static_reset_key,
            random,
        );

        const input_odcid: ?[]const u8 = odcid orelse (if (is_server) header.dcid else null);
        var tp_odcid: ?[]const u8 = null;
        if (input_odcid) |cid| {
            conn.odcid_len = @intCast(cid.len);
            @memcpy(conn.odcid_buf[0..cid.len], cid);
            tp_odcid = conn.odcid_buf[0..cid.len];
        }
        var tp_retry_scid: ?[]const u8 = null;
        if (retry_scid) |cid| {
            @memcpy(conn.retry_scid_buf[0..cid.len], cid);
            tp_retry_scid = conn.retry_scid_buf[0..cid.len];
        }

        // Server SHOULD include stateless_reset_token for the initial SCID (RFC 9000 §18.2)
        const reset_token: ?[16]u8 = if (is_server) conn.local_cid_pool.entries[0].stateless_reset_token else null;

        // Build transport params AFTER CIDs are stored in conn (to avoid dangling slices)
        var local_params: transport_params.TransportParams = .{
            .original_destination_connection_id = tp_odcid,
            .initial_source_connection_id = conn.scid[0..conn.scid_len],
            .retry_source_connection_id = tp_retry_scid,
            .stateless_reset_token = reset_token,
            .max_idle_timeout = config.max_idle_timeout,
            .initial_max_data = config.initial_max_data,
            .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .initial_max_streams_bidi = config.initial_max_streams_bidi,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .max_datagram_frame_size = config.max_datagram_frame_size,
            .initial_max_path_id = config.initial_max_path_id orelse
                if (config.max_remote_nat_traversal_addresses != null) @as(?u32, 1) else null,
            .max_remote_nat_traversal_addresses = config.max_remote_nat_traversal_addresses,
            .address_discovery_role = config.address_discovery_role,
            .min_ack_delay = 1000, // 1ms minimum ACK delay (draft-ietf-quic-ack-frequency)
            // Server's preferred address (RFC 9000 §9.6) — only for servers, must not coexist with disable_active_migration
            .preferred_address = if (is_server and config.preferred_address != null) config.preferred_address else null,
        };

        // RFC 9368: Include version_information transport parameter when v2 is enabled
        if (config.enable_v2) {
            local_params.version_info_chosen = header.version; // v1 for client, may be updated by server
            local_params.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
            local_params.version_info_available_count = 2;
        }

        conn.local_params = local_params;
        conn.enable_v2 = config.enable_v2;
        conn.disable_pmtud = config.disable_pmtud;

        // Compute keep-alive interval: clamp to idle_timeout/2
        if (config.keep_alive_period > 0) {
            const ka_ns: i64 = @intCast(config.keep_alive_period * 1_000_000);
            conn.keep_alive_interval_ns = @min(ka_ns, @divTrunc(conn.idle_timeout_ns, 2));
        }
        conn.close_when_idle = config.close_when_idle;

        // Initialize TLS 1.3 handshake if config provided
        if (tls_config) |tc| {
            var tc_versioned = tc;
            tc_versioned.quic_version = conn.version;
            const hs = try allocator.create(tls13.Tls13Handshake);
            // `deinit` frees the handshake through `conn.tls13_hs`, which is
            // not set yet, so the allocation is released here instead: the
            // handshake was never built into, so there is nothing in it to
            // tear down.
            errdefer allocator.destroy(hs);
            if (is_server)
                try tls13.Tls13Handshake.initServerInto(hs, tc_versioned, local_params, random)
            else
                try tls13.Tls13Handshake.initClientInto(hs, tc_versioned, local_params, random);
            hs.allocator = allocator;
            conn.tls13_hs = hs;
        }

        // Store the DCID used for initial key derivation (needed for v2 re-derivation)
        conn.initial_dcid_len = @intCast(header.dcid.len);
        @memcpy(conn.initial_dcid_buf[0..header.dcid.len], header.dcid);

        // Set up initial crypto keys (always use header.dcid for key derivation)
        try conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].setupInitial(
            header.dcid,
            header.version,
            is_server,
        );

        // Initialize the packet packer
        conn.packer = packet_packer.PacketPacker.init(
            is_server,
            conn.scid[0..conn.scid_len],
            conn.dcid[0..conn.dcid_len],
            header.version,
        );

        // Register the preferred_address CID in local CID pool (RFC 9000 §5.1.1: seq=1)
        if (is_server) {
            if (config.preferred_address) |pref| {
                const pref_cid = pref.getCid();
                if (pref_cid.len > 0) {
                    conn.local_cid_pool.registerPreferredCid(pref_cid, pref.stateless_reset_token);
                }
            }
        }

        // Set token key for NEW_TOKEN generation (server)
        conn.token_key = config.token_key;
        conn.candidateAdmission = config.candidateAdmission;
        conn.supportedIPv6 = config.supportedIPv6;

        // Configure stream limits
        conn.streams.setMaxIncomingStreams(
            config.initial_max_streams_bidi,
            config.initial_max_streams_uni,
        );
        conn.streams.local_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local;
        conn.streams.local_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
        conn.streams.local_max_stream_data_uni = config.initial_max_stream_data_uni;

        // Set initial send window from connection flow control
        conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

        if (config.max_idle_timeout > 0) {
            conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
        }

        // Resize datagram queues if configured larger than default
        if (config.datagram_queue_capacity > DatagramQueue.DEFAULT_MAX_ITEMS) {
            try conn.datagram_recv_queue.resize(allocator, config.datagram_queue_capacity);
            try conn.datagram_send_queue.resize(allocator, config.datagram_queue_capacity);
        }
    }

    /// Releases everything this connection allocated: the handshake, the ACK
    /// state, the stream maps, the crypto streams and the datagram queues.
    ///
    /// `allocator` is the one the connection was built with and is not
    /// released here — it stays the caller's. The connection is unusable
    /// afterwards, and a second call is a double free, so this is the one
    /// teardown a caller reaches exactly once, on storage it owns.
    pub fn deinit(self: *Connection) void {
        if (self.tls13_hs) |hs| {
            hs.deinit();
            self.allocator.destroy(hs);
            self.tls13_hs = null;
        }
        self.ack_result.deinit(self.allocator); // its packets are pkt_handler's
        self.pkt_handler.deinit();
        if (self.path1_transport) |other| {
            other.handler.deinit();
            other.retiring_cids.deinit(self.allocator);
            self.allocator.destroy(other);
        }
        self.streams.deinit();
        self.crypto_streams.deinit();
        self.datagram_recv_queue.deinitQueue();
        self.datagram_send_queue.deinitQueue();
        self.control_retry.deinit(self.allocator);
        self.retiring_cids.deinit(self.allocator);
    }

    /// Handle a Version Negotiation packet (RFC 9000 §6.2, client only).
    /// Since we support Compatible Version Negotiation (RFC 9368), VN packets
    /// indicate the server doesn't support any of our versions — close the connection.
    fn handleVersionNegotiation(self: *Connection, header: *const packet.Header, fbs: anytype, now: i64) void {
        // RFC 9000 §6.2: A client MUST discard VN if it has already received and
        // successfully processed any packet, including an earlier VN.
        if (self.state != .first_flight) return;

        // Validate: the VN's DCID must match our SCID, and SCID must match our DCID
        if (!std.mem.eql(u8, header.dcid, self.scid[0..self.scid_len])) return;
        if (!std.mem.eql(u8, header.scid, self.dcid[0..self.dcid_len])) return;

        // Read listed versions from the remaining bytes
        const remaining = fbs.buffer.len - fbs.seek;
        if (remaining < 4 or remaining % 4 != 0) return;

        const version_data = fbs.buffer[fbs.seek..];
        const version_count = remaining / 4;

        // Check if any listed version is one we support (skip reserved versions)
        var has_supported = false;
        var i: usize = 0;
        while (i < version_count) : (i += 1) {
            const v = std.mem.readInt(u32, version_data[i * 4 ..][0..4], .big);
            if (protocol.isSupportedVersion(v)) {
                has_supported = true;
                break;
            }
        }

        if (has_supported) {
            // The server lists a version we support but sent VN anyway.
            // This shouldn't happen with compatible VN — possible downgrade attack.
            // RFC 9000 §6.2: "A client MUST discard a Version Negotiation packet
            // that lists the QUIC version selected by the client."
            std.log.warn("VN packet lists our version — possible downgrade attack, ignoring", .{});
            return;
        }

        // No compatible version — close the connection
        std.log.info("VN: server does not support any of our versions, closing", .{});
        self.closeWithTransportError(@intFromEnum(TransportError.version_negotiation_error), 0, "Version negotiation failed", now);
    }

    /// Handle a Retry packet (client only).
    /// Verifies the integrity tag, saves ODCID, re-derives Initial keys with new DCID,
    /// and resets crypto stream so the same ClientHello is re-sent.
    ///
    /// A Retry this connection cannot act on is refused whole and before
    /// anything moves: a token longer than `retry_token_buf`, or none this
    /// connection could carry forward — absent, or present and zero bytes
    /// long (RFC 9000 §17.2.5). Acting on either would leave the next Initial
    /// carrying the token it already had, while `retry_received` turned every
    /// later Retry away — so one such packet would cost the handshake its
    /// address validation for good. Nothing of the connection changes, and a
    /// Retry this connection can use is still accepted afterwards.
    pub fn handleRetryPacket(self: *Connection, header: *const packet.Header, raw_packet: []const u8) !void {
        // Only accept one Retry, only before handshake progresses
        if (self.retry_received or self.state != .first_flight) {
            std.log.warn("ignoring Retry: retry_received={}, state={}", .{ self.retry_received, @intFromEnum(self.state) });
            return;
        }

        // Verify integrity tag using the ODCID (which is the initial DCID we sent to)
        const odcid = self.odcid_buf[0..self.odcid_len];
        const valid = packet.verifyRetryIntegrity(raw_packet, odcid, self.version) catch {
            std.log.err("Retry integrity check error", .{});
            return;
        };
        if (!valid) {
            std.log.warn("Retry integrity tag verification failed", .{});
            return;
        }

        // A Retry whose token cannot be carried into the next Initial is refused
        // before anything moves, so it costs the handshake nothing but this
        // packet.
        const token = header.token orelse {
            std.log.warn("ignoring Retry: no token to carry forward (RFC 9000 17.2.5)", .{});
            return;
        };
        // A zero-length token is that same absence in the one shape the wire
        // parser never produces: `Header.token` is a public field, so a caller
        // that built the header itself can hand over a present, empty slice.
        // There is nothing to put in the next Initial's token field either
        // way, and acting on it spends `retry_received` on a Retry that
        // carried nothing.
        if (token.len == 0 or token.len > self.retry_token_buf.len) {
            std.log.warn("ignoring Retry: {d}-byte token is not one this connection can carry forward", .{token.len});
            return;
        }

        // Update DCID to the Retry packet's SCID
        self.dcid_len = @intCast(header.scid.len);
        @memcpy(self.dcid[0..header.scid.len], header.scid);
        self.packer.updateDcid(header.scid);

        // Store the Retry token for inclusion in the next Initial packet
        @memcpy(self.retry_token_buf[0..token.len], token);
        self.retry_token_len = @intCast(token.len);
        // Point the packer's initial_token to our owned buffer
        self.packer.initial_token = self.retry_token_buf[0..self.retry_token_len];

        // Re-derive Initial keys with the new DCID (Retry SCID)
        try self.pkt_num_spaces[0].setupInitial(
            self.dcid[0..self.dcid_len],
            self.version,
            false, // client
        );

        // Reset packet number so the next Initial starts from 0
        self.pkt_num_spaces[0].next_packet_number = 0;

        // Reset the crypto stream send offset to re-send the same ClientHello
        self.crypto_streams.getStream(0).resetSendOffset();

        self.retry_received = true;
        self.got_peer_conn_id = false; // will pick up server's SCID from ServerHello

        std.log.info("Retry handled: new DCID={any}, token_len={d}", .{
            self.dcid[0..self.dcid_len],
            self.retry_token_len,
        });
    }

    /// Decrypt and process a single 0-RTT packet (early data). Caller must
    /// have `early_data_open` installed. Does not advance the handshake.
    fn processZeroRttPacket(
        self: *Connection,
        header: *packet.Header,
        fbs: anytype,
        info: RecvInfo,
        now: i64,
        random: std.Random,
    ) !void {
        std.log.info("recv: processing 0-RTT packet (early data)", .{});
        // 0-RTT uses pkt_num_spaces[2] (application) for PN tracking
        var space = self.pkt_num_spaces[2];
        const saved_open = space.crypto_open;
        space.crypto_open = self.early_data_open.?;
        const payload = packet.decrypt(header, fbs, &space) catch |err| {
            std.log.err("can't decrypt 0-RTT packet. {any}", .{err});
            space.crypto_open = saved_open;
            return error.InvalidPacket;
        };
        space.crypto_open = saved_open;

        if (payload.len == 0) {
            self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "empty packet payload", now);
            return error.InvalidPacket;
        }

        self.last_packet_received_time = now;
        self.keep_alive_ping_sent = false;
        self.total_packets_received += 1;
        if (info.datagram_size > 0) {
            self.paths[self.active_path_idx].bytes_received += info.datagram_size;
        }

        // Process 0-RTT frames (STREAM, DATAGRAM etc. - no CRYPTO or HANDSHAKE_DONE)
        var remaining = payload;
        var ack_eliciting = false;
        while (remaining.len > 0) {
            if (remaining[0] == 0x00) {
                remaining = remaining[frame_mod.paddingLen(remaining)..];
                continue;
            }
            var frame_len: usize = undefined;
            const frame = Frame.parseSized(remaining, &frame_len) catch break;
            // Enforce frame-in-correct-space (RFC 9000 §12.5)
            if (!frame.isAllowedIn(.zero_rtt)) {
                self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.crypto), "frame not allowed in 0-RTT", now);
                return error.ProtocolViolation;
            }
            if (frame.isAckEliciting()) ack_eliciting = true;
            try self.processFrame(&frame, .application, now, random);
            remaining = remaining[frame_len..];
        }
        try self.packetHandler().*.onPacketReceived(.application, header.packet_number, ack_eliciting, now, info.ecn);
        if (header.packet_number + 1 > self.pkt_num_spaces[2].next_packet_number) {
            self.pkt_num_spaces[2].next_packet_number = header.packet_number + 1;
        }
        if (self.state == .first_flight) self.state = .handshake;
    }

    /// The raw bytes of the packet currently being parsed, from its start to
    /// the end of its payload (excludes any coalesced packets that follow).
    /// Valid before decrypt() advances the stream.
    fn currentPacketBytes(header: *packet.Header, fbs: anytype) ?[]const u8 {
        const pkt_len = (fbs.seek - header.packet_start) + header.remainder_len;
        if (header.packet_start + pkt_len > fbs.buffer.len) return null;
        return fbs.buffer[header.packet_start..][0..pkt_len];
    }

    /// Buffer a packet whose encryption-level keys aren't installed yet,
    /// instead of dropping it (RFC 9001 §4.1.4). No-op while replaying so a
    /// still-undecryptable packet is dropped rather than re-queued.
    fn bufferUndecryptable(self: *Connection, header: *packet.Header, fbs: anytype, info: RecvInfo, what: []const u8) void {
        if (self.replaying_undecryptable) return;
        const bytes = currentPacketBytes(header, fbs) orelse return;
        self.undecryptable.push(bytes, info);
        std.log.info("recv: buffered undecryptable {s} packet ({d} bytes; {d} queued)", .{ what, bytes.len, self.undecryptable.count });
    }

    /// Replay packets that were buffered because their keys weren't installed
    /// yet (RFC 9001 §4.1.4; mirrors quic-go's undecryptablePacketsToProcess).
    /// Called from recv() after advanceHandshake() returns, never re-entrantly
    /// from inside the handshake action loop. The `replaying_undecryptable`
    /// guard makes recv() drop (not re-queue) anything still undecryptable.
    fn replayUndecryptable(self: *Connection, now: i64, random: std.Random) void {
        const n = self.undecryptable.count;
        if (n == 0) return;
        std.log.info("replaying {d} buffered undecryptable packet(s)", .{n});
        // Don't re-credit received bytes on replay (anti-amplification:
        // keeps the server conservative — RFC 9000 §8.1).
        var rinfo = self.undecryptable.info;
        rinfo.datagram_size = 0;
        self.replaying_undecryptable = true;
        defer self.replaying_undecryptable = false;
        for (0..n) |i| {
            const off = self.undecryptable.off[i];
            const len = self.undecryptable.plen[i];
            var rfbs = io.fixedBufferStream(self.undecryptable.buf[off..][0..len]);
            var h = packet.Header.parse(&rfbs, 0) catch continue;
            self.recv(&h, &rfbs, rinfo, now, random) catch continue;
        }
        self.undecryptable.reset();
    }

    /// Replay buffered packets if a read key was just installed. Safe to call
    /// after any advanceHandshake(); the guard prevents nested replay.
    fn drainUndecryptableIfPending(self: *Connection, now: i64, random: std.Random) void {
        if (self.pending_replay_undecryptable and !self.replaying_undecryptable) {
            self.pending_replay_undecryptable = false;
            self.replayUndecryptable(now, random);
        }
    }

    /// Process a received packet.
    ///
    /// `now` is the instant this packet arrived at and `random` the generator
    /// any CID, reset key or path challenge drawn while handling it comes from.
    /// The whole function is pure over `(state, input)` once those two are
    /// given, which is what lets `lossy_link_test.zig` drive a whole handshake
    /// and transfer in virtual time with no socket and no wall clock.
    pub fn recv(
        self: *Connection,
        header: *packet.Header,
        fbs: anytype,
        info: RecvInfo,
        now: i64,
        random: std.Random,
    ) !void {
        // Guard: don't process packets in terminal states (RFC 9000 §10)
        if (self.state == .terminated) return;
        if (self.state == .draining) {
            self.last_packet_received_time = now;
            return;
        }
        if (self.state == .closing) {
            self.close_trigger_count += 1;
            if (std.math.isPowerOfTwo(self.close_trigger_count)) self.needs_close_retransmit = true;
            self.last_packet_received_time = now;
            return;
        }

        // Intercept Retry packets before normal processing (client only)
        if (header.packet_type == .retry) {
            if (!self.is_server) {
                try self.handleRetryPacket(header, fbs.buffer[header.packet_start..fbs.buffer.len]);
            }
            return;
        }

        // RFC 9000 §6.2: Handle Version Negotiation packets (client only)
        if (header.packet_type == .version_negotiation) {
            if (!self.is_server and !self.handshake_confirmed) {
                self.handleVersionNegotiation(header, fbs, now);
            }
            return;
        }

        const epoch = try packet.Epoch.fromPacketType(header.packet_type);
        std.log.debug("recv: packet_type={s}, epoch={s}", .{ @tagName(header.packet_type), @tagName(epoch) });

        // RFC 9368: Client-side Compatible Version Negotiation detection
        // If we receive an Initial/Handshake from the server with a different version
        // than what we sent, and we advertised that version, switch to it.
        if (!self.is_server and self.enable_v2 and header.version != 0 and header.version != self.version) {
            if (protocol.isSupportedVersion(header.version)) {
                std.log.info("recv: compatible version negotiation detected, switching to 0x{x:0>8}", .{header.version});
                try self.switchVersion(header.version);
            }
        }

        // 0-RTT packets use the application PN space but with early data keys
        if (epoch == packet.Epoch.zero_rtt) {
            if (self.early_data_open == null) {
                // Key not installed yet (e.g. multi-Initial ClientHello).
                // Buffer rather than drop; replayed on early-data key install.
                self.bufferUndecryptable(header, fbs, info, "0-RTT");
                return;
            }
            try self.processZeroRttPacket(header, fbs, info, now, random);
            try self.advanceHandshake(now, random);
            self.drainUndecryptableIfPending(now, random);
            return;
        }

        const enc_level = epochToEncLevel(epoch);
        const space_idx = @intFromEnum(enc_level);
        const mp = epoch == .application and self.multipathNegotiated();
        var incoming_path: u8 = 0;
        if (mp) {
            for (&self.local_cid_pool.entries) |*entry| {
                if (entry.occupied and std.mem.eql(u8, entry.getCid(), header.dcid)) {
                    incoming_path = @intCast(entry.path_id);
                    break;
                }
            }
            if (incoming_path == 1) {
                const other = try self.ensurePathTransport();
                other.space.crypto_open = self.pkt_num_spaces[2].crypto_open;
                other.space.crypto_seal = self.pkt_num_spaces[2].crypto_seal;
            }
            self.activateTransport(incoming_path);
        }
        defer self.activateTransport(0);
        const selected_path = self.active_path_idx;
        if (mp) {
            self.receiving_packet = true;
            self.active_path_idx = incoming_path;
        }
        defer if (mp) {
            self.receiving_packet = false;
            // Keep the receiving-path view through PN, byte-credit and ACK
            // bookkeeping; commit a live replacement only after the packet.
            self.active_path_idx = if (self.native_paths.entries[selected_path].abandoned)
                self.native_paths.selected
            else
                selected_path;
        };
        const space = if (mp and incoming_path == 1)
            &self.path1_transport.?.space
        else
            &self.pkt_num_spaces[space_idx];
        const has_keys = space.crypto_open != null and space.crypto_seal != null;
        std.log.debug("recv: using space {d} ({s}), has_keys={}", .{ space_idx, @tagName(enc_level), has_keys });

        if (!has_keys) {
            // Keys for this level aren't installed yet (early Handshake/1-RTT,
            // e.g. reordering). Buffer rather than drop; replayed on key
            // install (RFC 9001 §4.1.4; quic-go undecryptablePackets).
            self.bufferUndecryptable(header, fbs, info, @tagName(enc_level));
            return;
        }

        // For 1-RTT packets with key update manager, use the appropriate key generation
        var payload: []u8 = undefined;
        if (epoch == .application and self.key_update != null) {
            // Decrypt using KeyUpdateManager: first do header unprotection with the
            // (unchanging) HP key, then select the right AEAD key based on key phase
            payload = (if (mp)
                packet.decryptWithKeyUpdateForPath(header, fbs, space, &self.key_update.?, incoming_path)
            else
                packet.decryptWithKeyUpdate(header, fbs, space, &self.key_update.?)) catch |err| {
                if (err == error.KeyUpdateError) {
                    self.closeWithTransportError(0x0e, 0, "non-increasing key update PN", now);
                    return error.KeyUpdateError;
                }
                return error.UndecryptablePacket;
            };
        } else {
            payload = (if (mp)
                packet.decryptForPath(header, fbs, space, incoming_path)
            else
                packet.decrypt(header, fbs, space)) catch {
                std.log.debug("silently dropping packet enc_level={s}", .{@tagName(enc_level)});
                // A short header ends the datagram, and may be a stateless reset.
                if (header.packet_type == .one_rtt) return error.UndecryptablePacket;
                return;
            };
        }
        self.receive_path = if (mp) incoming_path else self.active_path_idx;
        self.received_cid_len = @intCast(header.dcid.len);
        @memcpy(self.received_cid[0..header.dcid.len], header.dcid);
        self.received_peer = info.from;
        self.received_local = info.to;
        if (mp and incoming_path == 1) {
            if (!self.native_paths.entries[1].opened) {
                // Noq drops packets for unknown client paths; only the server
                // accepts a new authenticated path.
                if (!self.is_server) return error.InvalidPath;
                self.native_paths = native_path.process(self.native_paths, .{ .accept = 1 }) catch |err| {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "invalid authenticated multipath path", now);
                    return err;
                };
                self.paths[1] = NetworkPath.init(info.to, info.from, false);
                try self.probePath(1, now, random);
            }
        }

        if (payload.len == 0) {
            self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "empty packet payload", now);
            return error.InvalidPacket;
        }

        // RFC 9000 §17.2, §17.3: reserved bits MUST be zero after header protection removal
        if (header.reserved_bits_set) {
            self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "reserved header bits are non-zero", now);
            return error.ProtocolViolation;
        }

        self.last_packet_received_time = now;
        self.keep_alive_ping_sent = false;

        // RFC 9000 §8.1: Receipt of a Handshake packet from the client confirms
        // address ownership (client derived keys → it processed our Initial).
        // Lift the anti-amplification limit immediately.
        if (self.is_server and epoch == .handshake and !self.paths[self.active_path_idx].is_validated) {
            self.paths[self.active_path_idx].is_validated = true;
            std.log.info("path validated via Handshake packet (amplification limit lifted)", .{});
        }

        // Handle key phase change for 1-RTT packets (RFC 9001 Section 6)
        if (epoch == .application) {
            if (self.key_update) |*ku| {
                if (header.key_update_authenticated) {
                    // Only the next AEAD key authenticating can advance the global phase.
                    const pto_ns = self.maxActivePathPto();
                    ku.onPeerKeyUpdate(now, pto_ns);
                    self.packer.key_phase = ku.key_phase;
                    std.log.info("key update: peer-initiated, new key_phase={}", .{ku.key_phase});
                }
                if (header.key_phase == ku.key_phase) {
                    // Noq confirms an update by authenticating the peer's current phase.
                    ku.first_acked_with_current = true;
                }
                ku.maybeDropPrevKeys(now);
            }
        }

        // Spin bit handling (RFC 9000 §17.4) for 1-RTT packets only
        if (epoch == .application) {
            const is_new_largest = self.largest_pn_received == null or header.packet_number > self.largest_pn_received.?;
            if (is_new_largest) {
                self.largest_pn_received = header.packet_number;
                if (self.is_server) {
                    // Server: reflect the spin bit from the client
                    self.spin_bit = header.spin_bit;
                } else {
                    // Client: invert the spin bit on each new largest PN
                    self.spin_bit = !header.spin_bit;
                }
                self.packer.spin_bit = self.spin_bit;
            }
        }

        // Update network path stats (only once per datagram, not per coalesced packet)
        self.total_packets_received += 1;
        const off_path_nat = epoch == .application and self.nat_state != null and
            incoming_path == 0 and self.path_initialized and
            (!info.from.eql(self.paths[0].peer_addr) or !info.to.eql(self.paths[0].local_addr));
        if (info.datagram_size > 0 and !off_path_nat) {
            self.paths[self.active_path_idx].bytes_received += info.datagram_size;
        }

        // Check for duplicate
        if (self.packetHandler().*.recv[@intFromEnum(enc_level)].isDuplicate(header.packet_number)) {
            return; // Duplicate, ignore
        }

        // Determine path - set peer connection ID on first packet
        if (!self.got_peer_conn_id and header.scid.len > 0) {
            std.log.info("recv: updating DCID to peer SCID={any}", .{header.scid});
            self.dcid_len = @intCast(header.scid.len);
            @memcpy(self.dcid[0..header.scid.len], header.scid);
            // Update packer with new DCID
            self.packer.updateDcid(header.scid);
            self.got_peer_conn_id = true;
        }

        // Server: re-verify DCID from AEAD-authenticated long-header packets.
        // If the Initial that created this connection was corrupted in transit,
        // acceptInto() may have stored a wrong peer SCID as our outgoing DCID.
        // The first successfully-decrypted packet has the real peer SCID.
        if (self.is_server and !self.handshake_confirmed and
            (epoch == .initial or epoch == .handshake) and header.scid.len > 0)
        {
            if (self.dcid_len != @as(u8, @intCast(header.scid.len)) or
                !std.mem.eql(u8, self.dcid[0..self.dcid_len], header.scid))
            {
                std.log.info("recv: correcting DCID to AEAD-verified SCID (len {d})", .{header.scid.len});
                self.dcid_len = @intCast(header.scid.len);
                @memcpy(self.dcid[0..header.scid.len], header.scid);
                self.packer.updateDcid(header.scid);
            }
        }

        // Process all frames from the decrypted payload
        var ack_eliciting = false;
        var has_non_probing = false;
        var remaining = payload;

        while (remaining.len > 0) {
            if (remaining[0] == 0x00) {
                remaining = remaining[frame_mod.paddingLen(remaining)..];
                continue;
            }

            var frame_len: usize = undefined;
            const frame = Frame.parseSized(remaining, &frame_len) catch |err| {
                std.log.err("Failed to parse frame: {}", .{err});
                // RFC 9000 §12.4: frame encoding errors
                if (err == error.FrameEncodingError) {
                    self.closeWithTransportError(
                        @intFromEnum(TransportError.frame_encoding_error),
                        0,
                        "unknown or malformed frame type",
                        now,
                    );
                } else {
                    self.closeWithTransportError(
                        @intFromEnum(TransportError.frame_encoding_error),
                        0,
                        "frame encoding error",
                        now,
                    );
                }
                return error.ProtocolViolation;
            };

            std.log.debug("recv: parsed frame type={s}", .{@tagName(frame)});

            // Enforce frame-in-correct-space (RFC 9000 §12.5)
            if (!frame.isAllowedIn(header.packet_type)) {
                std.log.warn("frame {s} not allowed in {s} packet, closing", .{ @tagName(frame), @tagName(header.packet_type) });
                self.closeWithTransportError(
                    @intFromEnum(TransportError.protocol_violation),
                    0,
                    "frame not allowed in this packet type",
                    now,
                );
                return error.ProtocolViolation;
            }

            if (frame.isAckEliciting()) {
                ack_eliciting = true;
            }
            if (!frame.isProbing()) {
                has_non_probing = true;
            }

            self.processFrame(&frame, epoch, now, random) catch |err| {
                if (self.state != .closing) {
                    self.closeWithTransportError(
                        @intFromEnum(TransportError.protocol_violation),
                        0,
                        "invalid authenticated frame",
                        now,
                    );
                }
                return err;
            };

            remaining = remaining[frame_len..];
        }

        // Record receipt for ACK generation
        try self.packetHandler().*.onPacketReceived(enc_level, header.packet_number, ack_eliciting, now, info.ecn);
        // Only probing traffic stays off-path. Authenticated ACK/STREAM semantics
        // and largest-PN passive migration remain ordinary QUIC operations.
        const pure_nat_probe = off_path_nat and !has_non_probing;
        if (off_path_nat and !pure_nat_probe and info.datagram_size > 0) {
            self.paths[self.active_path_idx].bytes_received += info.datagram_size;
        }

        // Update expected packet number for correct decoding of subsequent packets
        // (critical for coalesced packets where multiple packets share a datagram)
        if (header.packet_number + 1 > space.next_packet_number) {
            space.next_packet_number = header.packet_number + 1;
        }

        // Initialize path on first received packet (client-side: connectInto() doesn't know server addr)
        if (!self.path_initialized) {
            self.paths[self.active_path_idx] = NetworkPath.init(info.to, info.from, true);
            self.path_initialized = true;
        }

        // Detect connection migration (RFC 9000 Section 9)
        // Only for 1-RTT packets after handshake is confirmed, with non-probing frames
        if (!pure_nat_probe and epoch == .application and self.handshake_confirmed and
            has_non_probing and header.packet_number + 1 >= space.next_packet_number)
        {
            const active_path = &self.paths[self.active_path_idx];
            if (!info.from.eql(active_path.peer_addr)) {
                std.log.info("connection migration detected from new peer address", .{});
                if (mp) {
                    active_path.* = NetworkPath.init(info.to, info.from, false);
                    try self.probePath(incoming_path, now, random);
                } else {
                    self.handleMigration(info.from, info.to, now, random);
                }
                // Credit this packet's bytes to the new path (already counted on old path above)
                if (info.datagram_size > 0) {
                    self.paths[self.active_path_idx].bytes_received += info.datagram_size;
                }
            } else if (!info.to.eql(active_path.local_addr)) {
                // A new local address does not prove or disprove peer ownership.
                // Noq updates this independently of remote path validation.
                active_path.local_addr = info.to;
            }
        }

        // Update connection state
        if (self.state == .first_flight and epoch == .initial) {
            self.state = .handshake;
        }

        // After processing crypto frames, try advancing the handshake
        try self.advanceHandshake(now, random);

        // If advanceHandshake() just installed a read key, replay any packets
        // buffered before that key was available. Done here, after it returns,
        // to avoid re-entering the handshake action loop where keys install.
        self.drainUndecryptableIfPending(now, random);
    }

    /// Queue CRYPTO frame retransmission by resetting the crypto stream's send offset.
    /// This causes the packer to re-send all crypto data at the given level (RFC 9002 §6.2).
    fn queueCryptoRetransmission(self: *Connection, level: ack_handler.EncLevel) void {
        const crypto_idx: u8 = switch (level) {
            .initial => 0,
            .handshake => 2,
            .application => 3,
        };
        const cs = self.crypto_streams.getStream(crypto_idx);
        if (cs.write_offset > 0) {
            cs.resetSendOffset();
        }
    }

    /// A fresh NEW_TOKEN for the current peer address (RFC 9000 8.1.3).
    /// Announces one of our CIDs, with the current Retire Prior To.
    fn newConnectionIdFrame(self: *const Connection, e: *const LocalCidEntry) frame_mod.PendingControlFrame {
        const cid: @FieldType(frame_mod.PendingControlFrame, "new_connection_id") = .{
            .seq_num = e.seq_num,
            .retire_prior_to = if (e.path_id == 0) self.local_cid_pool.retire_prior_to else 0,
            .cid_buf = e.cid_buf,
            .cid_len = e.cid_len,
            .stateless_reset_token = e.stateless_reset_token,
        };
        return if (self.multipathNegotiated())
            .{ .path_new_connection_id = .{ .path_id = e.path_id, .cid = cid } }
        else
            .{ .new_connection_id = cid };
    }

    fn issuePathCid(self: *Connection, random: std.Random) !void {
        const other = try self.ensurePathTransport();
        const issued = if (self.quic_lb_config) |*lb|
            self.local_cid_pool.issueNewCidLb(lb, self.static_reset_key, random)
        else
            self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key, random);
        if (issued) |entry_const| {
            const entry = @constCast(entry_const);
            entry.path_id = 1;
            entry.seq_num = other.next_local_cid_seq;
            other.next_local_cid_seq += 1;
            self.pushReliable(self.newConnectionIdFrame(entry));
        }
    }

    fn newTokenFrame(self: *Connection, now: i64, random: std.Random) ?frame_mod.PendingControlFrame {
        // No key, no token: sealing one under an absent key would be sealing
        // it under something a reader has, which is worse than sending none.
        const token_key = self.token_key orelse return null;
        var nt_buf: [packet.TOKEN_MAX_LEN]u8 = undefined;
        const nt_len = packet.generateNewToken(
            &nt_buf,
            self.paths[self.active_path_idx].peer_addr,
            token_key,
            now,
            random,
        ) catch return null;
        var pcf: frame_mod.PendingControlFrame = .{ .new_token = .{} };
        if (nt_len == 0 or nt_len > pcf.new_token.token_buf.len) return null;
        @memcpy(pcf.new_token.token_buf[0..nt_len], nt_buf[0..nt_len]);
        pcf.new_token.token_len = @intCast(nt_len);
        return pcf;
    }

    /// Close for a RESET_STREAM the receive side refused (RFC 9000 4.5, 4.1).
    fn rejectResetStream(self: *Connection, err: anyerror, now: i64) error{ FlowControlError, ProtocolViolation } {
        if (err == error.FlowControlError) {
            self.closeWithTransportError(@intFromEnum(TransportError.flow_control_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM exceeds stream flow control", now);
            return error.FlowControlError;
        }
        self.closeWithTransportError(@intFromEnum(TransportError.final_size_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM final_size mismatch", now);
        return error.ProtocolViolation;
    }

    /// Charge a STREAM frame to flow control and buffer it, closing the
    /// connection for whatever the receive side refuses.
    fn recvStreamFrame(self: *Connection, rs: *stream_mod.ReceiveStream, offset: u64, data: []const u8, fin: bool, now: i64) !void {
        try self.chargeConnWindow(rs, offset + data.len, .stream, now);
        rs.handleStreamFrame(offset, data, fin) catch |err| switch (err) {
            error.FinalSizeError => {
                self.closeWithTransportError(@intFromEnum(TransportError.final_size_error), @intFromEnum(FrameType.stream), "STREAM final_size mismatch", now);
                return error.ProtocolViolation;
            },
            error.TooManyChunks => {
                self.closeWithTransportError(@intFromEnum(TransportError.internal_error), @intFromEnum(FrameType.stream), "too many reassembly gaps", now);
                return error.ProtocolViolation;
            },
            error.FlowControlError => {
                self.closeWithTransportError(@intFromEnum(TransportError.flow_control_error), @intFromEnum(FrameType.stream), "STREAM exceeds stream flow control limit", now);
                return error.FlowControlError;
            },
            else => return err,
        };
    }

    fn requeueAbandonedPath(self: *Connection, id: u1, now: i64, random: std.Random) void {
        const handler = if (id == 0)
            &self.pkt_handler
        else if (self.path1_transport) |other|
            &other.handler
        else
            return;
        const tracker = &handler.sent[@intFromEnum(ack_handler.EncLevel.application)];
        for (tracker.sent_packets.values()) |pkt| {
            self.queueStreamRetransmissions(pkt);
            self.requeueLostControlFrames(pkt, now, random);
            if (pkt.has_crypto_data) self.queueCryptoRetransmission(pkt.enc_level);
            if (pkt.has_handshake_done and self.handshake_done_pending) {
                self.packer.send_handshake_done = true;
            }
            if (pkt.in_flight) handler.bytes_in_flight -= pkt.size;
        }
        // A following ordinary ACK still refers to this packet-number history.
        // Only the owned sent records and their recovery deadlines are retired.
        const largest_sent = tracker.largest_sent;
        const largest_acked = tracker.largest_acked;
        tracker.clear();
        tracker.largest_sent = largest_sent;
        tracker.largest_acked = largest_acked;
        handler.pto_count = 0;
        self.path_control[id].len = 0;
        self.challenge_queued[id] = false;
        self.challenge_full_size_sent[id] = false;
        if (id == 0) {
            self.pto_probe_pending = 0;
        } else {
            self.path1_transport.?.probe_pending = 0;
        }
    }

    /// Queue retransmission for stream frames that were in a lost packet.
    fn queueStreamRetransmissions(self: *Connection, pkt: *const ack_handler.SentPacket) void {
        for (pkt.getStreamFrames()) |sf| {
            // Look up the stream and queue the retransmission
            if (stream_mod.isBidi(sf.stream_id)) {
                if (self.streams.getStream(sf.stream_id)) |s| {
                    if (s.send.reset_err == null) {
                        s.send.queueRetransmit(sf.offset, sf.length, sf.fin);
                    }
                }
            } else {
                // Unidirectional send stream
                if (self.streams.send_streams.get(sf.stream_id)) |s| {
                    if (s.reset_err == null) {
                        s.queueRetransmit(sf.offset, sf.length, sf.fin);
                    }
                }
            }
        }
    }

    /// Process a single frame.
    pub const PathError = native_path.Error || error{
        OutOfMemory,
        HandshakeNotConfirmed,
        InvalidAddress,
        NoPathConnectionId,
    };
    pub const NatTraversalError = native_nat_state.Error || error{NatTraversalNotNegotiated};

    pub fn observedAddress(self: *const Connection, id: u8) ?observed.Report {
        if (id >= 2) return null;
        return self.observed_paths[id].last_received;
    }

    pub fn observedRoles(self: *const Connection) struct { local: observed.Role, peer: observed.Role } {
        return .{
            .local = self.local_params.address_discovery_role,
            .peer = if (self.peer_params) |peer| peer.address_discovery_role else .disabled,
        };
    }

    fn processNat(
        self: *Connection,
        event: native_nat_state.Event,
    ) NatTraversalError!native_nat_state.Result {
        const state = if (self.nat_state) |*value| value else return error.NatTraversalNotNegotiated;
        const configured = native_nat_state.process(state, .{ .configure = .{ .supported_ipv6 = self.supportedIPv6 } }, state) catch |err| return err;
        _ = configured;
        return native_nat_state.process(state, event, state);
    }

    fn admitCandidate(self: *const Connection, value: address.Address) bool {
        const canonical = @import("native_nat_policy.zig").canonicalAddress(value) catch return false;
        if (!self.supportedIPv6 and canonical == .ipv6) return false;
        return if (self.candidateAdmission) |admit| admit(canonical) else true;
    }

    fn maxActivePathPto(self: *const Connection) i64 {
        var maximum: i64 = if (self.native_paths.entries[0].abandoned)
            0
        else
            self.pkt_handler.rtt_stats.pto();
        if (self.path1_transport) |other| {
            if (self.native_paths.entries[1].opened and !self.native_paths.entries[1].abandoned) {
                maximum = @max(maximum, other.handler.rtt_stats.pto());
            }
        }
        // With no surviving path, keep the base closing/idle timer meaningful.
        return if (maximum == 0) self.pkt_handler.rtt_stats.pto() else maximum;
    }

    pub fn addNatTraversalAddress(self: *Connection, value: address.Address) NatTraversalError!void {
        if (!self.admitCandidate(value)) return;
        const canonical = try @import("native_nat_policy.zig").canonicalAddress(value);
        if ((try self.processNat(.{ .add = canonical })).sequence) |sequence| {
            self.pushReliable(.{ .add_address = .{ .sequence = sequence, .address = canonical } });
        }
    }

    pub fn removeNatTraversalAddress(self: *Connection, value: address.Address) NatTraversalError!void {
        if ((try self.processNat(.{ .remove = value })).sequence) |sequence| {
            self.pushReliable(.{ .remove_address = sequence });
        }
    }

    pub fn initiateNatTraversalRound(
        self: *Connection,
        now: i64,
        random: std.Random,
    ) NatTraversalError!void {
        _ = random;
        const state = if (self.nat_state) |*s| s else return error.NatTraversalNotNegotiated;
        const result = try self.processNat(.{ .initiate = now });
        _ = result;
        self.nat_reply = null;
        self.direct_ready = null;
        for (state.localCandidates()) |candidate| {
            self.pushReliable(.{ .reach_address = .{
                .round = state.currentRound(),
                .address = candidate.address,
            } });
        }
    }

    pub fn roundState(self: *const Connection) native_nat_state.RoundState {
        return if (self.nat_state) |*state| state.roundState() else .idle;
    }

    pub fn remoteTraversalCandidates(
        self: *const Connection,
        out: []address.Address,
    ) []const address.Address {
        return if (self.nat_state) |*state| state.snapshotRemote(out) else out[0..0];
    }

    pub fn processFrame(
        self: *Connection,
        frame: *const Frame,
        epoch: packet.Epoch,
        now: i64,
        random: std.Random,
    ) !void {
        const native_frame = switch (frame.*) {
            .path_ack, .path_ack_ecn, .path_abandon, .path_status_available, .path_status_backup, .path_new_connection_id, .path_retire_connection_id, .max_path_id, .paths_blocked, .path_cids_blocked, .observed_address, .add_address, .remove_address, .reach_address => true,
            else => false,
        };
        errdefer if (native_frame) {
            self.closeWithTransportError(
                @intFromEnum(TransportError.protocol_violation),
                0,
                "native frame protocol violation",
                now,
            );
        };
        const mp = self.multipathNegotiated();
        switch (frame.*) {
            .path_ack, .path_ack_ecn, .path_abandon, .path_status_available, .path_status_backup, .path_new_connection_id, .path_retire_connection_id, .max_path_id, .paths_blocked, .path_cids_blocked => {
                if (!mp or epoch != .application) {
                    self.closeWithTransportError(
                        @intFromEnum(TransportError.protocol_violation),
                        0,
                        "multipath frame without negotiation",
                        now,
                    );
                    return error.ProtocolViolation;
                }
            },
            .add_address, .remove_address, .reach_address => {
                if (epoch != .application or self.nat_state == null) return error.ProtocolViolation;
                if (frame.* == .reach_address and !self.is_server) return error.ProtocolViolation;
                if (frame.* != .reach_address and self.is_server) return error.ProtocolViolation;
            },
            else => {},
        }
        switch (frame.*) {
            .ack, .ack_ecn => {
                const previous = self.transport_path;
                if (epoch == .application) self.activateTransport(0);
                defer self.activateTransport(previous);
                return self.processBaseFrame(frame, epoch, now, random);
            },
            .path_ack => |value| {
                if (value.path_id >= 2) return error.ProtocolViolation;
                if (self.native_paths.entries[value.path_id].abandoned) return;
                if (!self.native_paths.entries[value.path_id].opened) return error.ProtocolViolation;
                const previous = self.transport_path;
                self.activateTransport(@intCast(value.path_id));
                defer self.activateTransport(previous);
                const base: Frame = .{ .ack = value.ack };
                return self.processBaseFrame(&base, epoch, now, random);
            },
            .path_ack_ecn => |value| {
                if (value.path_id >= 2) return error.ProtocolViolation;
                if (self.native_paths.entries[value.path_id].abandoned) return;
                if (!self.native_paths.entries[value.path_id].opened) return error.ProtocolViolation;
                const previous = self.transport_path;
                self.activateTransport(@intCast(value.path_id));
                defer self.activateTransport(previous);
                const base: Frame = .{ .ack_ecn = value.ack };
                return self.processBaseFrame(&base, epoch, now, random);
            },
            .path_status_available => |value| {
                self.native_paths = try native_path.process(self.native_paths, .{ .status = .{
                    .id = value.path_id,
                    .seq = value.status_seq_no,
                    .value = .available,
                } });
            },
            .path_status_backup => |value| {
                self.native_paths = try native_path.process(self.native_paths, .{ .status = .{
                    .id = value.path_id,
                    .seq = value.status_seq_no,
                    .value = .backup,
                } });
            },
            .path_abandon => |value| {
                if (value.path_id >= 2) return;
                const was_abandoned = self.native_paths.entries[value.path_id].abandoned;
                self.native_paths = try native_path.process(
                    self.native_paths,
                    .{ .abandon = value.path_id },
                );
                if (!was_abandoned and self.native_paths.entries[value.path_id].abandoned) {
                    self.requeueAbandonedPath(@intCast(value.path_id), now, random);
                }
                if (!self.receiving_packet) self.active_path_idx = self.native_paths.selected;
            },
            .max_path_id => |value| {
                const maximum = @min(@as(u32, 1), @min(self.local_params.initial_max_path_id.?, value));
                if (maximum <= self.native_paths.peer_max_path_id) return;
                self.native_paths.peer_max_path_id = maximum;
                if (maximum >= 1) try self.issuePathCid(random);
                try self.resumeDirectPath(now, random);
            },
            .paths_blocked => |value| {
                if (value > self.local_params.initial_max_path_id.?) return error.ProtocolViolation;
            },
            .path_cids_blocked => |value| {
                if (value.path_id > self.local_params.initial_max_path_id.? or value.path_id >= 2)
                    return error.ProtocolViolation;
                if (self.native_paths.entries[value.path_id].abandoned) return;
                const next_sequence = if (value.path_id == 0) self.local_cid_pool.next_seq_num else if (self.path1_transport) |other| other.next_local_cid_seq else 0;
                if (value.next_seq > next_sequence) return error.ProtocolViolation;
                // Retry the actual outstanding CID, not an unrelated path's CID.
                var available = false;
                for (&self.local_cid_pool.entries) |*entry| {
                    if (entry.occupied and !entry.retired and entry.path_id == value.path_id and
                        entry.seq_num >= value.next_seq)
                    {
                        self.pushReliable(self.newConnectionIdFrame(entry));
                        available = true;
                    }
                }
                if (!available and value.path_id == 1 and self.native_paths.peer_max_path_id >= 1)
                    try self.issuePathCid(random);
            },
            .path_new_connection_id => |value| {
                if (value.path_id >= 2) return error.ProtocolViolation;
                if (value.path_id == 0) {
                    const base: Frame = .{ .new_connection_id = value.cid };
                    return self.processBaseFrame(&base, epoch, now, random);
                }
                const other = try self.ensurePathTransport();
                const cid = value.cid;
                if (cid.conn_id.len == 0 or cid.retire_prior_to > cid.seq_num) {
                    return error.ProtocolViolation;
                }
                if (value.path_id > self.local_params.initial_max_path_id.?) {
                    return error.ProtocolViolation;
                }
                var duplicate = false;
                for (0..2) |id| {
                    for (self.peerPathCidEntries(@intCast(id))) |entry| {
                        if (!entry.occupied) continue;
                        if (id == 1 and entry.seq_num == cid.seq_num) {
                            if (!std.mem.eql(u8, entry.getCid(), cid.conn_id) or
                                !std.mem.eql(u8, &entry.stateless_reset_token, &cid.stateless_reset_token))
                            {
                                return error.ProtocolViolation;
                            }
                            duplicate = true;
                        } else if (std.mem.eql(u8, entry.getCid(), cid.conn_id)) {
                            return error.ProtocolViolation;
                        }
                    }
                }
                const floor = @max(other.peer_retire_prior_to, cid.retire_prior_to);
                for (&other.peer_cids.entries) |*entry| {
                    if (entry.occupied and entry.seq_num < floor) {
                        try self.retirePeerCid(1, entry.seq_num, now);
                    }
                }
                other.peer_cids.retirePriorTo(floor);
                other.peer_retire_prior_to = floor;
                if (cid.seq_num < floor) {
                    try self.retirePeerCid(1, cid.seq_num, now);
                    return;
                }
                if (!duplicate) {
                    if (other.peer_cids.count() >= self.local_params.active_connection_id_limit) {
                        return error.ProtocolViolation;
                    }
                    other.peer_cids.addPeerCid(cid.seq_num, cid.conn_id, cid.stateless_reset_token);
                }
                if (other.dcid_len == 0 or other.dcid_seq < floor) {
                    const selected = other.peer_cids.consumeUnused() orelse return error.ProtocolViolation;
                    other.dcid_len = selected.cid_len;
                    other.dcid_seq = selected.seq_num;
                    @memcpy(other.dcid[0..selected.cid_len], selected.getCid());
                }
            },
            .path_retire_connection_id => |value| {
                if (value.path_id >= 2) return error.ProtocolViolation;
                if (value.path_id == 0) {
                    const base: Frame = .{ .retire_connection_id = .{ .seq_num = value.seq_num } };
                    return self.processBaseFrame(&base, epoch, now, random);
                }
                for (&self.local_cid_pool.entries) |*entry| {
                    if (entry.occupied and entry.path_id == value.path_id and
                        entry.seq_num == value.seq_num)
                    {
                        if (self.received_cid_len == entry.cid_len and std.mem.eql(
                            u8,
                            self.received_cid[0..self.received_cid_len],
                            entry.getCid(),
                        )) return error.ProtocolViolation;
                        entry.occupied = false;
                        entry.retired = true;
                        try self.issuePathCid(random);
                        return;
                    }
                }
                if (self.path1_transport) |other| {
                    if (value.seq_num < other.next_local_cid_seq) return;
                }
                return error.ProtocolViolation;
            },
            .observed_address => |report| {
                const roles = self.observedRoles();
                const id = if (self.multipathNegotiated()) self.receive_path else 0;
                const transition = try observed.receiveTransition(
                    self.observed_paths[id],
                    report,
                    .{
                        .local_role = roles.local,
                        .peer_role = roles.peer,
                        .data_space = epoch == .application,
                    },
                );
                self.observed_paths[id] = transition.state;
            },
            .add_address => |value| {
                if (!self.admitCandidate(value.address)) return;
                const result = try self.processNat(.{ .receiveAdd = .{
                    .sequence = value.sequence,
                    .address = value.address,
                } });
                _ = result;
            },
            .remove_address => |sequence| {
                const result = try self.processNat(.{ .receiveRemove = sequence });
                _ = result;
            },
            .reach_address => |value| {
                if (!self.admitCandidate(value.address)) return;
                const result = try self.processNat(.{ .receiveReach = .{
                    .round = value.round,
                    .address = value.address,
                    .now = now,
                } });
                _ = result;
            },
            else => return self.processBaseFrame(frame, epoch, now, random),
        }
    }

    fn processBaseFrame(
        self: *Connection,
        frame: *const Frame,
        epoch: packet.Epoch,
        now: i64,
        random: std.Random,
    ) !void {
        switch (frame.*) {
            .padding => {},
            .ping => {},

            .ack => |ack| {
                const enc_level = epochToEncLevel(epoch);
                if (self.packetHandler().*.acksUnsentPacket(enc_level, ack.largest_ack, ack.first_ack_range, ack.ack_ranges[0..ack.ack_range_count])) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.ack), "ACK for unsent packet", now);
                    return error.ProtocolViolation;
                }
                const peer_tp = self.peer_params orelse transport_params.TransportParams{};

                // RFC 9002 §7.8: snapshot app_limited BEFORE processing ACKs,
                // while bytes_in_flight still reflects the pre-ACK state.
                // If checked after, bytes_in_flight is already decremented,
                // making it appear app-limited even when the sender filled cwnd.
                const was_app_limited = self.packetHandler().*.bytes_in_flight <
                    self.pathCongestion().*.sendWindow();

                defer self.ack_result.release(self.allocator);
                try self.packetHandler().*.onAckReceived(
                    enc_level,
                    ack.largest_ack,
                    ack.ack_delay,
                    @intCast(peer_tp.ack_delay_exponent),
                    ack.ack_ranges[0..ack.ack_range_count],
                    ack.first_ack_range,
                    now,
                    &self.ack_result,
                );
                const result = &self.ack_result;
                if (result.acked.count() == 0) return;
                self.pathCongestion().*.app_limited = was_app_limited;

                // Notify congestion controller, track key update ACKs, and PMTUD
                var has_non_probe_loss = false;
                var earliest_lost_sent_time: ?i64 = null;
                for (result.acked.constSlice()) |pkt| {
                    // Check if this is an MTU probe ACK
                    if (self.pathMTU().*.onProbeAcked(pkt.pn, now)) {
                        // Probe succeeded — update packet size and congestion controller
                        const new_mtu = self.pathMTU().*.current_mtu;
                        self.packer.max_packet_size = new_mtu;
                        self.pathCongestion().*.setMaxDatagramSize(new_mtu);
                        self.pathPacer().*.max_datagram_size = new_mtu;
                        std.log.info("PMTUD: probe ACK'd, MTU raised to {d}", .{new_mtu});
                    }

                    self.pathCongestion().*.onPacketAcked(pkt.size, pkt.time_sent, now);
                    for (pkt.getControlFrames()) |cf| switch (cf) {
                        .retire_connection_id => |seq| self.onRetireCidAcked(0, seq),
                        .path_retire_connection_id => |value| {
                            if (value.path_id < 2)
                                self.onRetireCidAcked(@intCast(value.path_id), value.seq_num);
                        },
                        else => {},
                    };

                    // Update stream ack_offset for ACKed stream frames
                    for (pkt.getStreamFrames()) |sf| {
                        if (stream_mod.isBidi(sf.stream_id)) {
                            if (self.streams.getStream(sf.stream_id)) |s| {
                                try s.send.onAck(sf.offset, sf.length, sf.fin);
                                // The last ACK of a closed stream is the moment
                                // it stops being needed for retransmission.
                                self.streams.disposeIfSettled(s);
                            }
                        } else {
                            if (self.streams.send_streams.get(sf.stream_id)) |s| {
                                try s.onAck(sf.offset, sf.length, sf.fin);
                                self.streams.disposeUniIfSettled(s);
                            }
                        }
                    }

                    // Track whether a packet sent with current keys has been ACKed
                    if (enc_level == .application) {
                        if (self.key_update) |*ku| {
                            ku.onAckForPath(@intCast(self.transport_path), pkt.pn);
                        }
                    }
                }

                for (result.lost.constSlice()) |pkt| {
                    self.total_packets_lost += 1;
                    if (pkt.has_datagram) self.datagrams_lost_outgoing += 1;

                    // Check if this is an MTU probe loss — don't trigger CC
                    if (self.pathMTU().*.onProbeLost(pkt.pn, now)) {
                        std.log.info("PMTUD: probe lost pn={d}", .{pkt.pn});
                    } else {
                        has_non_probe_loss = true;
                        if (earliest_lost_sent_time == null or pkt.time_sent < earliest_lost_sent_time.?) {
                            earliest_lost_sent_time = pkt.time_sent;
                        }
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(pkt);
                    self.requeueLostControlFrames(pkt, now, random);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }

                    // Re-arm HANDSHAKE_DONE if the lost packet carried it
                    if (pkt.has_handshake_done and self.handshake_done_pending) {
                        self.packer.send_handshake_done = true;
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        // Only trigger persistent congestion if the lost packets
                        // are from outside the current recovery epoch. This prevents
                        // repeated resets when old packets are gradually declared lost
                        // across multiple ACK events after a blackhole.
                        if (earliest_lost_sent_time) |lost_time| {
                            if (!self.pathCongestion().*.inCongestionRecovery(lost_time)) {
                                self.pathCongestion().*.onPersistentCongestion(now);
                                std.log.info("persistent congestion detected, window reduced to minimum", .{});
                            }
                        }
                    } else if (earliest_lost_sent_time) |lost_time| {
                        self.pathCongestion().*.onCongestionEvent(lost_time, now);
                    }
                }

                self.maybeConfirmHandshake(enc_level, result.acked.count());

                // Update pacer
                self.pathPacer().*.setBandwidth(self.pathCongestion().*.sendWindow(), &self.packetHandler().*.rtt_stats);
            },

            .ack_ecn => |ack| {
                const enc_level = epochToEncLevel(epoch);
                if (self.packetHandler().*.acksUnsentPacket(enc_level, ack.largest_ack, ack.first_ack_range, ack.ack_ranges[0..ack.ack_range_count])) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.ack_ecn), "ACK for unsent packet", now);
                    return error.ProtocolViolation;
                }
                const space_idx = @intFromEnum(enc_level);
                const peer_tp = self.peer_params orelse transport_params.TransportParams{};
                const previous_largest = self.packetHandler().*.sent[space_idx].largest_acked;
                const new_largest = previous_largest == null or ack.largest_ack > previous_largest.?;

                // RFC 9002 §7.8: snapshot app_limited BEFORE processing ACKs
                const was_app_limited = self.packetHandler().*.bytes_in_flight <
                    self.pathCongestion().*.sendWindow();

                defer self.ack_result.release(self.allocator);
                try self.packetHandler().*.onAckReceived(
                    enc_level,
                    ack.largest_ack,
                    ack.ack_delay,
                    @intCast(peer_tp.ack_delay_exponent),
                    ack.ack_ranges[0..ack.ack_range_count],
                    ack.first_ack_range,
                    now,
                    &self.ack_result,
                );
                const result = &self.ack_result;
                // ACKs covering only off-path packets have no recovery evidence.
                if (result.acked.count() == 0) return;
                self.pathCongestion().*.app_limited = was_app_limited;

                // Notify congestion controller, track key update ACKs, and PMTUD
                var has_non_probe_loss = false;
                var earliest_lost_sent_time_ecn: ?i64 = null;
                for (result.acked.constSlice()) |pkt| {
                    if (self.pathMTU().*.onProbeAcked(pkt.pn, now)) {
                        const new_mtu = self.pathMTU().*.current_mtu;
                        self.packer.max_packet_size = new_mtu;
                        self.pathCongestion().*.setMaxDatagramSize(new_mtu);
                        self.pathPacer().*.max_datagram_size = new_mtu;
                        std.log.info("PMTUD: probe ACK'd, MTU raised to {d}", .{new_mtu});
                    }
                    self.pathCongestion().*.onPacketAcked(pkt.size, pkt.time_sent, now);
                    for (pkt.getControlFrames()) |cf| switch (cf) {
                        .retire_connection_id => |seq| self.onRetireCidAcked(0, seq),
                        .path_retire_connection_id => |value| {
                            if (value.path_id < 2)
                                self.onRetireCidAcked(@intCast(value.path_id), value.seq_num);
                        },
                        else => {},
                    };

                    // Stop including HANDSHAKE_DONE once a packet containing it is ACKed
                    if (pkt.has_handshake_done) {
                        self.packer.send_handshake_done = false;
                        self.handshake_done_pending = false;
                    }

                    // Update stream ack_offset for ACKed stream frames
                    for (pkt.getStreamFrames()) |sf| {
                        if (stream_mod.isBidi(sf.stream_id)) {
                            if (self.streams.getStream(sf.stream_id)) |s| {
                                try s.send.onAck(sf.offset, sf.length, sf.fin);
                                // The last ACK of a closed stream is the moment
                                // it stops being needed for retransmission.
                                self.streams.disposeIfSettled(s);
                            }
                        } else {
                            if (self.streams.send_streams.get(sf.stream_id)) |s| {
                                try s.onAck(sf.offset, sf.length, sf.fin);
                                self.streams.disposeUniIfSettled(s);
                            }
                        }
                    }

                    if (enc_level == .application) {
                        if (self.key_update) |*ku| {
                            ku.onAckForPath(@intCast(self.transport_path), pkt.pn);
                        }
                    }
                }

                for (result.lost.constSlice()) |pkt| {
                    self.total_packets_lost += 1;
                    if (pkt.has_datagram) self.datagrams_lost_outgoing += 1;

                    if (self.pathMTU().*.onProbeLost(pkt.pn, now)) {
                        std.log.info("PMTUD: probe lost pn={d}", .{pkt.pn});
                    } else {
                        has_non_probe_loss = true;
                        if (earliest_lost_sent_time_ecn == null or pkt.time_sent < earliest_lost_sent_time_ecn.?) {
                            earliest_lost_sent_time_ecn = pkt.time_sent;
                        }
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(pkt);
                    self.requeueLostControlFrames(pkt, now, random);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }

                    // Re-arm HANDSHAKE_DONE if the lost packet carried it
                    if (pkt.has_handshake_done and self.handshake_done_pending) {
                        self.packer.send_handshake_done = true;
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        if (earliest_lost_sent_time_ecn) |lost_time| {
                            if (!self.pathCongestion().*.inCongestionRecovery(lost_time)) {
                                self.pathCongestion().*.onPersistentCongestion(now);
                                std.log.info("persistent congestion detected, window reduced to minimum", .{});
                            }
                        }
                    } else if (earliest_lost_sent_time_ecn) |lost_time| {
                        self.pathCongestion().*.onCongestionEvent(lost_time, now);
                    }
                }

                // ECN validation (RFC 9000 §13.4.2.1):
                // Count how many newly-acked packets were ECN-marked
                var newly_acked_ect0: u64 = 0;
                var largest_newly_acked_pn: ?u64 = null;
                var largest_newly_acked_sent_time: i64 = 0;
                for (result.acked.constSlice()) |pkt| {
                    if (pkt.ecn_marked) newly_acked_ect0 += 1;
                    if (largest_newly_acked_pn == null or pkt.pn > largest_newly_acked_pn.?) {
                        largest_newly_acked_pn = pkt.pn;
                        largest_newly_acked_sent_time = pkt.time_sent;
                    }
                }

                // Reordered/equal ACK_ECN does not replace newer path feedback.
                if (new_largest) {
                    const previous_ect0 = if (self.transport_path == 1)
                        &self.path1_transport.?.peer_ecn_ect0
                    else
                        &self.peer_ecn_ect0[space_idx];
                    const previous_ect1 = if (self.transport_path == 1)
                        &self.path1_transport.?.peer_ecn_ect1
                    else
                        &self.peer_ecn_ect1[space_idx];
                    const previous_ce = if (self.transport_path == 1)
                        &self.path1_transport.?.peer_ecn_ce
                    else
                        &self.peer_ecn_ce[space_idx];
                    const ecn_valid = self.pathECN().*.validate(
                        ack.ecn_ect0,
                        ack.ecn_ect1,
                        ack.ecn_ce,
                        previous_ect0.*,
                        previous_ect1.*,
                        previous_ce.*,
                        newly_acked_ect0,
                    );
                    if (ecn_valid and ack.ecn_ce > previous_ce.*) {
                        self.pathCongestion().*.onCongestionEvent(largest_newly_acked_sent_time, now);
                    }
                    previous_ect0.* = ack.ecn_ect0;
                    previous_ect1.* = ack.ecn_ect1;
                    previous_ce.* = ack.ecn_ce;
                }

                self.maybeConfirmHandshake(enc_level, result.acked.count());

                // Update pacer
                self.pathPacer().*.setBandwidth(self.pathCongestion().*.sendWindow(), &self.packetHandler().*.rtt_stats);
            },

            .reset_stream => |rs| {
                // RFC 9000 §19.4: RESET_STREAM on a send-only stream is STREAM_STATE_ERROR
                if (stream_mod.isLocal(rs.stream_id, self.is_server) and !stream_mod.isBidi(rs.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM on send-only stream", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §3.2: RESET_STREAM opens a receive stream just as a
                // STREAM frame does, so the same MAX_STREAMS bound applies.
                if (!stream_mod.isLocal(rs.stream_id, self.is_server)) {
                    const limit = if (stream_mod.isBidi(rs.stream_id))
                        self.streams.max_incoming_bidi_streams
                    else
                        self.streams.max_incoming_uni_streams;
                    if (rs.stream_id / 4 >= limit) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM stream ID exceeds MAX_STREAMS limit", now);
                        return error.ProtocolViolation;
                    }
                    // An unheard-of uni stream is opened by the reset itself;
                    // without this its final size never reaches connection flow
                    // control and the window is short by that much for good.
                    if (!stream_mod.isBidi(rs.stream_id) and
                        self.streams.recv_streams.get(rs.stream_id) == null)
                    {
                        _ = self.streams.getOrCreateRecvStream(rs.stream_id) catch |err| switch (err) {
                            error.StreamAlreadyClosed => return, // already reclaimed
                            else => return,
                        };
                    }
                }
                if (self.streams.getStream(rs.stream_id)) |s| {
                    s.recv.handleResetStream(rs.error_code, rs.final_size) catch |err| return self.rejectResetStream(err, now);
                    // RFC 9000 §4.5: the final size counts once; the credit
                    // comes back when queueFlowControlUpdates harvests it.
                    try self.chargeConnWindow(&s.recv, rs.final_size, .reset_stream, now);
                    // If send side is also done, stream is fully closed
                    if (s.send.fin_sent or s.send.reset_err != null) {
                        self.streams.closeStream(rs.stream_id);
                    }
                } else if (self.streams.recv_streams.get(rs.stream_id)) |s| {
                    // Peer-initiated uni stream. The peer counted final_size
                    // against connection flow control when it sent the data, so
                    // we have to release that credit here or the connection
                    // stalls at the window even though the bytes never arrived.
                    s.handleResetStream(rs.error_code, rs.final_size) catch |err| return self.rejectResetStream(err, now);
                    try self.chargeConnWindow(s, rs.final_size, .reset_stream, now);
                    if (!s.closed_counted) {
                        s.closed_counted = true;
                        self.streams.closeStream(rs.stream_id);
                    }
                }
            },

            .stop_sending => |ss| {
                // RFC 9000 §19.5: STOP_SENDING for a receive-only stream is STREAM_STATE_ERROR
                if (!stream_mod.isLocal(ss.stream_id, self.is_server) and !stream_mod.isBidi(ss.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stop_sending), "STOP_SENDING on receive-only stream", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.5: STOP_SENDING for a locally-initiated stream not yet created
                if (stream_mod.isLocal(ss.stream_id, self.is_server) and self.streams.localNeverOpened(ss.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stop_sending), "STOP_SENDING for stream not yet created", now);
                    return error.ProtocolViolation;
                }
                const sender: ?*stream_mod.SendStream = if (self.streams.getStream(ss.stream_id)) |s|
                    &s.send
                else
                    self.streams.send_streams.get(ss.stream_id);
                if (sender) |snd| {
                    snd.reset(ss.error_code);
                    snd.peer_stop_sending = ss.error_code;
                }
            },

            .crypto => |crypto_frame| {
                const level: u8 = @intFromEnum(epoch);
                self.crypto_streams.handleCryptoFrame(level, crypto_frame.offset, crypto_frame.data) catch |err| switch (err) {
                    // RFC 9000 7.5: an oversized or heavily fragmented flight is
                    // refused rather than buffered for an unauthenticated peer.
                    error.CryptoBufferExceeded, error.TooManyChunks => {
                        self.closeWithTransportError(@intFromEnum(TransportError.crypto_buffer_exceeded), @intFromEnum(FrameType.crypto), "CRYPTO buffer exceeded", now);
                        return error.ProtocolViolation;
                    },
                    else => return err,
                };
                // Handshake advancement happens after all frames are processed
            },

            .new_token => |token| {
                // RFC 9000 §19.7: server MUST NOT send NEW_TOKEN; client receiving it is valid
                if (self.is_server) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.new_token), "server received NEW_TOKEN", now);
                    return error.ProtocolViolation;
                }
                if (token.len <= self.new_token_buf.len) {
                    @memcpy(self.new_token_buf[0..token.len], token);
                    self.new_token_len = @intCast(token.len);
                    std.log.info("stored NEW_TOKEN from server ({d} bytes)", .{token.len});
                }
            },

            .stream => |s| {
                // RFC 9000 §19.8: STREAM on send-only stream is STREAM_STATE_ERROR
                if (stream_mod.isLocal(s.stream_id, self.is_server) and !stream_mod.isBidi(s.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stream), "STREAM on send-only stream", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.8: STREAM for locally-initiated stream not yet created
                if (stream_mod.isLocal(s.stream_id, self.is_server) and self.streams.localNeverOpened(s.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stream), "STREAM for locally-initiated stream not yet created", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §4.6: stream ID exceeding peer's MAX_STREAMS limit
                {
                    const stream_seq = s.stream_id / 4;
                    const limit = if (stream_mod.isBidi(s.stream_id)) self.streams.max_incoming_bidi_streams else self.streams.max_incoming_uni_streams;
                    if (!stream_mod.isLocal(s.stream_id, self.is_server) and stream_seq >= limit) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.stream), "stream ID exceeds MAX_STREAMS limit", now);
                        return error.ProtocolViolation;
                    }
                }
                if (stream_mod.isBidi(s.stream_id)) {
                    // Bidirectional stream
                    const strm = self.streams.getOrCreateStream(s.stream_id) catch |err| switch (err) {
                        // Retransmission of data we acked before reclaiming the
                        // stream. Nothing to deliver, and no error to raise.
                        error.StreamAlreadyClosed => return,
                        else => {
                            std.log.err("Failed to get/create stream {}: {}", .{ s.stream_id, err });
                            return;
                        },
                    };
                    try self.recvStreamFrame(&strm.recv, s.offset, s.data, s.fin, now);
                    if (s.fin) self.streams.needs_gc_scan = true;

                    // With the FIN ahead of a hole, the frame filling it closes.
                    self.streams.closeIfDone(strm);
                } else {
                    // Unidirectional stream — route to recv_streams
                    const recv_strm = self.streams.getOrCreateRecvStream(s.stream_id) catch |err| switch (err) {
                        // Retransmission of data the consumer took before the
                        // stream was reclaimed. Nothing to deliver.
                        error.StreamAlreadyClosed => return,
                        else => {
                            std.log.err("Failed to get/create recv stream {}: {}", .{ s.stream_id, err });
                            return;
                        },
                    };
                    try self.recvStreamFrame(recv_strm, s.offset, s.data, s.fin, now);

                    // For incoming uni streams, FIN means the stream is done.
                    // A retransmitted FIN must not count against MAX_STREAMS twice.
                    if (s.fin and !recv_strm.closed_counted) {
                        recv_strm.closed_counted = true;
                        self.streams.closeStream(s.stream_id);
                    }
                }
            },

            .max_data => |max| {
                self.conn_flow_ctrl.updateSendWindow(max);
            },

            .max_stream_data => |msd| {
                // RFC 9000 §19.10: MAX_STREAM_DATA on receive-only stream is STREAM_STATE_ERROR
                if (!stream_mod.isLocal(msd.stream_id, self.is_server) and !stream_mod.isBidi(msd.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.max_stream_data), "MAX_STREAM_DATA on receive-only stream", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.10: MAX_STREAM_DATA for locally-initiated stream not yet created
                if (stream_mod.isLocal(msd.stream_id, self.is_server) and self.streams.localNeverOpened(msd.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.max_stream_data), "MAX_STREAM_DATA for stream not yet created", now);
                    return error.ProtocolViolation;
                }
                // Update send window on bidi streams
                if (self.streams.getStream(msd.stream_id)) |s| {
                    s.send.updateSendWindow(msd.max);
                }
                // Update send window on uni send streams
                if (self.streams.send_streams.get(msd.stream_id)) |s| {
                    s.updateSendWindow(msd.max);
                }
            },

            .max_streams_bidi => |max| {
                // RFC 9000 §19.11: MAX_STREAMS must not exceed 2^60
                if (max > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.max_streams_bidi), "MAX_STREAMS_BIDI exceeds 2^60", now);
                    return error.ProtocolViolation;
                }
                self.streams.setMaxStreams(max, self.streams.max_uni_streams);
            },

            .max_streams_uni => |max| {
                // RFC 9000 §19.11: MAX_STREAMS must not exceed 2^60
                if (max > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.max_streams_uni), "MAX_STREAMS_UNI exceeds 2^60", now);
                    return error.ProtocolViolation;
                }
                self.streams.setMaxStreams(self.streams.max_bidi_streams, max);
            },

            .data_blocked => |limit| {
                // If the peer is blocked on connection credit, immediately
                // re-advertise our current receive limit. MAX_DATA is
                // idempotent, and blocked frames are the peer's explicit
                // signal that a previous update might not have arrived.
                self.queueFlowControlUpdates();
                const current = self.conn_flow_ctrl.base.receive_window;
                if (current > limit) {
                    self.pending_frames.push(.{ .max_data = current });
                }
            },
            .stream_data_blocked => |blocked| {
                // Same logic for per-stream credit. For bidi streams, the
                // receive side carries the limit we advertise to the peer.
                self.queueFlowControlUpdates();
                if (self.streams.getRecvStream(blocked.stream_id)) |rs| {
                    const current = rs.receive_window;
                    if (rs.receive_window_size > 0 and current > blocked.limit) {
                        self.pending_frames.push(.{ .max_stream_data = .{
                            .stream_id = blocked.stream_id,
                            .max = current,
                        } });
                    }
                }
            },
            .streams_blocked_bidi => |val| {
                // RFC 9000 §19.14: STREAMS_BLOCKED must not exceed 2^60
                if (val > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.streams_blocked_bidi), "STREAMS_BLOCKED_BIDI exceeds 2^60", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §4.6: the peer wants streams it has no credit for.
                // Echoing the limit it is already sitting at unblocks nothing —
                // grant what its closed streams have earned. With nothing to
                // grant, our last MAX_STREAMS was probably lost, so resend it.
                if (self.streams.flushMaxStreams(true)) |new_max| {
                    self.pending_frames.push(.{ .max_streams_bidi = new_max });
                } else if (val < self.streams.max_incoming_bidi_streams) {
                    self.pending_frames.push(.{ .max_streams_bidi = self.streams.max_incoming_bidi_streams });
                }
            },
            .streams_blocked_uni => |val| {
                // RFC 9000 §19.14: STREAMS_BLOCKED must not exceed 2^60
                if (val > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.streams_blocked_uni), "STREAMS_BLOCKED_UNI exceeds 2^60", now);
                    return error.ProtocolViolation;
                }
                // Same as the bidi case above.
                if (self.streams.flushMaxStreams(false)) |new_max| {
                    self.pending_frames.push(.{ .max_streams_uni = new_max });
                } else if (val < self.streams.max_incoming_uni_streams) {
                    self.pending_frames.push(.{ .max_streams_uni = self.streams.max_incoming_uni_streams });
                }
            },

            .new_connection_id => |ncid| {
                for (0..2) |id| {
                    for (self.peerPathCidEntries(@intCast(id))) |entry| {
                        if (!entry.occupied) continue;
                        if (id == 0 and entry.seq_num == ncid.seq_num) {
                            if (!std.mem.eql(u8, entry.getCid(), ncid.conn_id) or
                                !std.mem.eql(u8, &entry.stateless_reset_token, &ncid.stateless_reset_token))
                                return error.ProtocolViolation;
                        } else if (std.mem.eql(u8, entry.getCid(), ncid.conn_id)) {
                            return error.ProtocolViolation;
                        }
                    }
                }
                // RFC 9000 §19.15: Retire_Prior_To must not exceed Sequence_Number
                if (ncid.retire_prior_to > ncid.seq_num) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.new_connection_id), "NEW_CONNECTION_ID: retire_prior_to > seq_num", now);
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.15: CID length of 0 is invalid (except for initial)
                if (ncid.conn_id.len == 0) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.new_connection_id), "NEW_CONNECTION_ID: 0-byte connection ID", now);
                    return error.ProtocolViolation;
                }
                if (ncid.seq_num > self.peer_max_cid_seq) {
                    self.peer_max_cid_seq = ncid.seq_num;
                }

                // RFC 9000 19.15: a CID arriving already below Retire Prior To
                // is retired straight away, never used.
                if (ncid.seq_num < self.active_cid_seq) {
                    try self.retirePeerCid(0, ncid.seq_num, now);
                    return;
                }

                // Retire only the CIDs we actually hold: the jump itself can
                // be as large as 2^62.
                if (ncid.retire_prior_to > self.active_cid_seq) {
                    if (self.active_cid_seq == 0 and !self.peer_cid_pool.contains(0)) {
                        try self.retirePeerCid(0, 0, now); // the handshake DCID, never pooled
                    }
                    for (&self.peer_cid_pool.entries) |*entry| {
                        if (entry.occupied and entry.seq_num < ncid.retire_prior_to) {
                            try self.retirePeerCid(0, entry.seq_num, now);
                        }
                    }
                    self.active_cid_seq = ncid.retire_prior_to;
                    self.peer_cid_pool.retirePriorTo(ncid.retire_prior_to);
                }

                // A retransmitted frame repeats a CID we already hold.
                if (!self.peer_cid_pool.contains(ncid.seq_num)) {
                    self.peer_cid_pool.addPeerCid(ncid.seq_num, ncid.conn_id, ncid.stateless_reset_token);
                    std.log.info("stored peer CID in pool from NEW_CONNECTION_ID seq={d}, pool_size={d}", .{ ncid.seq_num, self.peer_cid_pool.count() });
                }

                // §5.1.2: keep the DCID in use until Retire Prior To takes it.
                // Switching early moved our Handshake Finished onto a CID
                // imquic does not route long headers by, so it never arrived.
                if (self.dcid_seq < self.active_cid_seq) self.replaceRetiredDcid();
            },

            .retire_connection_id => |rcid| {
                var issued = false;
                for (&self.local_cid_pool.entries) |*entry| {
                    if (entry.path_id != 0 or entry.seq_num != rcid.seq_num) continue;
                    if (!entry.occupied and !entry.retired) continue;
                    issued = true;
                    if (entry.occupied and entry.cid_len == self.received_cid_len and
                        std.mem.eql(u8, entry.getCid(), self.received_cid[0..self.received_cid_len]))
                        return error.ProtocolViolation;
                }
                if (!issued and rcid.seq_num >= self.local_cid_pool.next_seq_num)
                    return error.ProtocolViolation;
                std.log.info("peer retired connection ID seq={d}", .{rcid.seq_num});
                self.local_cid_pool.retireBySeq(rcid.seq_num);

                // Issue a replacement CID to stay at the peer's limit
                const peer_limit = if (self.peer_params) |pp| pp.active_connection_id_limit else 2;
                if (self.local_cid_pool.activeCount() < peer_limit) {
                    const maybe_entry = if (self.quic_lb_config) |*lb_cfg|
                        self.local_cid_pool.issueNewCidLb(lb_cfg, self.static_reset_key, random)
                    else
                        self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key, random);
                    if (maybe_entry) |entry| {
                        self.pushReliable(self.newConnectionIdFrame(entry));
                        std.log.info("issued replacement NEW_CONNECTION_ID seq={d}", .{entry.seq_num});
                    }
                }
            },

            .path_challenge => |data| {
                const roles = self.observedRoles();
                self.observed_paths[self.receive_path].schedule(roles.local, roles.peer);
                if (self.nat_state != null and self.receive_path == 0 and
                    !self.received_peer.eql(self.paths[0].peer_addr))
                {
                    if (!self.admitCandidate(self.received_peer)) return;
                    _ = try self.processNat(.{ .configure = .{ .supported_ipv6 = self.supportedIPv6 } });
                    if (!self.nat_state.?.canRecordChallenge(self.received_peer)) return;
                    var challenge: [8]u8 = undefined;
                    random.bytes(&challenge);
                    self.nat_reply = .{
                        .peer = self.received_peer,
                        .local = self.received_local,
                        .response = data,
                        .challenge = challenge,
                    };
                    return;
                }
                if (self.multipathNegotiated()) {
                    self.path_control[self.receive_path].push(.{ .path_response = data });
                } else {
                    self.pending_frames.push(.{ .path_response = data });
                }
            },

            .path_response => |data| {
                const roles = self.observedRoles();
                self.observed_paths[self.receive_path].schedule(roles.local, roles.peer);
                if (self.nat_state != null) {
                    const matched = (try self.processNat(.{ .response = .{
                        .address = self.received_peer,
                        .token = data,
                    } })).matched;
                    if (matched) {
                        if (!self.is_server and self.multipathNegotiated() and
                            !self.native_paths.entries[1].opened and
                            !self.native_paths.entries[1].abandoned)
                        {
                            self.direct_ready = .{
                                .local = self.received_local,
                                .peer = try @import("native_nat_policy.zig").canonicalAddress(self.received_peer),
                            };
                        }
                        return;
                    }
                }
                const path = &self.paths[self.receive_path];
                if (self.received_peer.eql(path.peer_addr) and
                    self.received_local.eql(path.local_addr) and
                    (!self.multipathNegotiated() or self.challenge_full_size_sent[self.receive_path]) and
                    path.validator.handleResponse(data))
                {
                    path.is_validated = true;
                    self.native_paths.entries[self.receive_path].validated = true;
                    if (self.receive_path == 1 and self.nat_state != null) {
                        const result = try self.processNat(.directValidated);
                        _ = result;
                    }
                }
            },

            .connection_close => |cc| {
                std.log.warn("peer CONNECTION_CLOSE: error_code=0x{x}, frame_type=0x{x}, reason_len={d}, reason={s}", .{
                    cc.error_code,
                    cc.frame_type,
                    cc.reason.len,
                    if (cc.reason.len > 0) cc.reason else "none",
                });
                self.state = .draining;
                self.closing_start_time = now;
                self.local_err = .{
                    .is_app = false,
                    .code = cc.error_code,
                    .reason = cc.reason,
                };
            },

            .application_close => |ac| {
                self.state = .draining;
                self.closing_start_time = now;
                self.local_err = .{
                    .is_app = true,
                    .code = ac.error_code,
                    .reason = ac.reason,
                };
            },

            .handshake_done => {
                // RFC 9000 §19.20: only server sends HANDSHAKE_DONE
                if (self.is_server) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.handshake_done), "server received HANDSHAKE_DONE", now);
                    return error.ProtocolViolation;
                }
                self.handshake_confirmed = true;
                self.state = .connected;
                self.pathECN().*.start();

                // Drop Initial and Handshake packet number spaces and encryption keys
                self.packetHandler().*.dropSpace(.initial);
                self.packetHandler().*.dropSpace(.handshake);
                self.pkt_num_spaces[0].crypto_open = null;
                self.pkt_num_spaces[0].crypto_seal = null;
                self.pkt_num_spaces[1].crypto_open = null;
                self.pkt_num_spaces[1].crypto_seal = null;
            },

            .datagram => |d| {
                if (self.datagrams_enabled) {
                    if (self.datagram_recv_callback) |cb| {
                        cb(d.data, self.datagram_recv_ctx);
                    } else {
                        if (!self.datagram_recv_queue.push(d.data, now)) {
                            self.datagrams_dropped_incoming += 1;
                        }
                    }
                }
            },

            .datagram_with_length => |d| {
                if (self.datagrams_enabled) {
                    if (self.datagram_recv_callback) |cb| {
                        cb(d.data, self.datagram_recv_ctx);
                    } else {
                        if (!self.datagram_recv_queue.push(d.data, now)) {
                            self.datagrams_dropped_incoming += 1;
                        }
                    }
                }
            },

            .ack_frequency => |af| {
                // draft-ietf-quic-ack-frequency: update ACK generation parameters
                if (!self.peer_supports_ack_freq) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0xaf, "ACK_FREQUENCY not negotiated", now);
                    return error.ProtocolViolation;
                }
                const applied = self.packetHandler().*.recv[2].applyAckFrequency(
                    af.sequence_number,
                    af.ack_eliciting_threshold,
                    af.request_max_ack_delay,
                    af.reordering_threshold,
                );
                if (applied) {
                    std.log.info("ACK_FREQUENCY applied: seq={d} threshold={d} max_delay={d}µs reorder={d}", .{
                        af.sequence_number, af.ack_eliciting_threshold, af.request_max_ack_delay, af.reordering_threshold,
                    });
                }
            },

            .immediate_ack => {
                // draft-ietf-quic-ack-frequency: force immediate ACK
                self.packetHandler().*.recv[2].triggerImmediateAck();
            },
            else => unreachable,
        }
    }

    /// Advance the TLS 1.3 handshake by reading contiguous crypto data.
    fn advanceHandshake(self: *Connection, now: i64, random: std.Random) !void {
        // Allow post-handshake messages (NST) even after handshake_confirmed
        const hs = self.tls13_hs orelse return;

        // One instant for every step this call makes, in the unit TLS reads.
        // A loop that converted per iteration would step a handshake against a
        // clock that moved under it, which is a handshake no test can drive.
        const now_s = tlsSeconds(now);

        // If handshake is confirmed, only feed application-level crypto data for NST
        if (self.handshake_confirmed) {
            const cs = self.crypto_streams.getStream(3); // application level
            var got_data = false;
            while (cs.read()) |data| {
                defer self.allocator.free(data);
                hs.provideData(data);
                got_data = true;
            }
            if (got_data) {
                var nst_iters: usize = 0;
                while (nst_iters < 10) : (nst_iters += 1) {
                    const action = hs.step(now_s, random) catch |err| {
                        // RFC 9001 §4.8: post-handshake TLS errors
                        const tls_alert: u64 = @intFromEnum(switch (err) {
                            error.UnexpectedMessage => tls.Alert.Description.unexpected_message,
                            else => tls.Alert.Description.internal_error,
                        });
                        self.closeWithTransportError(TransportError.cryptoError(tls_alert), @intFromEnum(FrameType.crypto), "post-handshake TLS error", now);
                        return;
                    };
                    switch (action) {
                        .complete => {
                            if (hs.received_ticket) |ticket| {
                                self.session_ticket = ticket;
                                std.log.info("stored session ticket from server (lifetime={d}s)", .{ticket.lifetime});
                            }
                            break;
                        },
                        ._continue => continue,
                        else => break,
                    }
                }
            }
            return;
        }

        std.log.info("advanceHandshake: state={}, iterations starting", .{@intFromEnum(hs.state)});

        // Feed crypto stream data to the handshake
        inline for ([_]u8{ 0, 2, 3 }) |level| {
            const cs = self.crypto_streams.getStream(level);
            var crypto_data_count: usize = 0;
            while (cs.read()) |data| {
                defer self.allocator.free(data);
                crypto_data_count += 1;
                std.log.info("advanceHandshake: feeding crypto level={} data len={}", .{ level, data.len });
                hs.provideData(data);
            }
            if (crypto_data_count > 0) {
                std.log.info("advanceHandshake: fed {d} crypto frames from level {}", .{ crypto_data_count, level });
            }
        }

        // Drive the state machine until it needs more data or completes
        var iterations: usize = 0;
        while (iterations < 50) {
            iterations += 1;
            const action = hs.step(now_s, random) catch |err| {
                std.log.err("TLS 1.3 handshake error: {}", .{err});
                // RFC 9000 §7.4: TransportParameterError is a QUIC transport error, not TLS
                if (err == error.TransportParameterError) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "transport parameter error", now);
                    return;
                }
                // RFC 9001 §4.8: map TLS errors to CRYPTO_ERROR (0x100 + TLS alert code)
                const tls_alert: u64 = @intFromEnum(switch (err) {
                    error.BadCertificate => tls.Alert.Description.bad_certificate,
                    error.BadCertificateVerify => tls.Alert.Description.decrypt_error,
                    error.UnexpectedMessage => tls.Alert.Description.unexpected_message,
                    error.DecodeError => tls.Alert.Description.decode_error,
                    error.BadFinished => tls.Alert.Description.decrypt_error,
                    error.NoKeyShare => tls.Alert.Description.handshake_failure,
                    error.UnsupportedVersion => tls.Alert.Description.protocol_version,
                    error.NoApplicationProtocol => tls.Alert.Description.no_application_protocol,
                    error.MissingExtension => tls.Alert.Description.missing_extension,
                    error.HandshakeFailure => tls.Alert.Description.handshake_failure,
                    error.CertificateRequired => tls.Alert.Description.certificate_required,
                    error.IllegalParameter => tls.Alert.Description.illegal_parameter,
                    else => tls.Alert.Description.internal_error,
                });
                self.closeWithTransportError(TransportError.cryptoError(tls_alert), @intFromEnum(FrameType.crypto), "TLS handshake failure", now);
                return;
            };
            std.log.info("advanceHandshake: step {d} produced action={s}", .{ iterations, @tagName(action) });

            switch (action) {
                .send_data => |sd| {
                    // Write the TLS handshake data to the appropriate crypto stream
                    const cs_level: u8 = @intFromEnum(sd.level);
                    const cs = self.crypto_streams.getStream(cs_level);
                    // Log hash of data being written to crypto stream for corruption debugging
                    var data_hash: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(sd.data, &data_hash, .{});
                    std.log.info("advanceHandshake: writing {d} bytes to level {}, first4={x:0>2}{x:0>2}{x:0>2}{x:0>2}, sha256={x}", .{
                        sd.data.len,
                        cs_level,
                        sd.data[0],
                        if (sd.data.len > 1) sd.data[1] else @as(u8, 0),
                        if (sd.data.len > 2) sd.data[2] else @as(u8, 0),
                        if (sd.data.len > 3) sd.data[3] else @as(u8, 0),
                        data_hash,
                    });
                    try cs.writeData(sd.data);
                },
                .install_keys => |ik| {
                    switch (ik.level) {
                        .early_data => {
                            if (self.is_server) {
                                self.early_data_open = ik.open;
                                self.pending_replay_undecryptable = true;
                                std.log.info("installed 0-RTT decrypt keys (server)", .{});
                            } else {
                                self.early_data_seal = ik.seal;
                                // RFC 9000 §7.4.1: restore remembered transport params for 0-RTT
                                if (self.remembered_params) |rp| {
                                    self.streams.setMaxStreams(rp.initial_max_streams_bidi, rp.initial_max_streams_uni);
                                    self.streams.setPeerInitialMaxStreamData(
                                        rp.initial_max_stream_data_bidi_local,
                                        rp.initial_max_stream_data_bidi_remote,
                                        rp.initial_max_stream_data_uni,
                                    );
                                    self.conn_flow_ctrl.base.send_window = rp.initial_max_data;
                                    std.log.info("installed 0-RTT keys (client), restored remembered params: max_bidi={d}, max_uni={d}, max_data={d}", .{
                                        rp.initial_max_streams_bidi, rp.initial_max_streams_uni, rp.initial_max_data,
                                    });
                                } else {
                                    self.streams.setMaxStreams(100, 100);
                                    std.log.info("installed 0-RTT encrypt keys (client), default stream limits", .{});
                                }
                            }
                        },
                        .handshake => {
                            self.installHandshakeKeys(ik.open, ik.seal);
                            self.pending_replay_undecryptable = true;
                            // RFC 9001 §4.9.1: client stops sending Initial packets after
                            // receiving the first Handshake packet (which installs these keys).
                            // Drop the Initial seal to prevent the packer from generating
                            // Initial packets with the (now shorter) DCID.
                            if (!self.is_server) {
                                self.pkt_num_spaces[0].crypto_seal = null;
                            }
                            if (self.is_server and self.enable_v2) {
                                if (hs.config.quic_version != self.version) {
                                    try self.switchVersion(hs.config.quic_version);
                                }
                            }
                        },
                        .application => {
                            self.installAppKeys(ik.open, ik.seal);
                            self.pending_replay_undecryptable = true;
                        },
                        else => {},
                    }
                },
                .wait_for_data => break,
                .complete => {
                    // Skip if already connected (duplicate .complete from post-handshake messages)
                    if (self.state == .connected) break;

                    self.state = .connected;
                    self.pathECN().*.start();
                    self.paths[self.active_path_idx].is_validated = true;

                    // Drop Initial space and keys (both client and server)
                    self.packetHandler().*.dropSpace(.initial);
                    self.pkt_num_spaces[0].crypto_open = null;
                    self.pkt_num_spaces[0].crypto_seal = null;

                    // Clear early data keys (0-RTT period is over)
                    self.early_data_open = null;
                    self.early_data_seal = null;
                    // Handshake done: discard any still-buffered packets
                    // (RFC 9001 §4.1.4 — peers retransmit if needed).
                    self.undecryptable.reset();
                    self.pending_replay_undecryptable = false;

                    // Handle 0-RTT rejection (RFC 9001 §4.1.2):
                    // When the server rejects 0-RTT, the client must retransmit all
                    // 0-RTT data as 1-RTT. Queue retransmission of all in-flight
                    // application-space packets that carried stream data.
                    if (!self.is_server and !hs.zero_rtt_accepted) {
                        const app_tracker = &self.packetHandler().*.sent[@intFromEnum(ack_handler.EncLevel.application)];
                        var pkt_it = app_tracker.sent_packets.iterator();
                        while (pkt_it.next()) |entry| {
                            const pkt = entry.value_ptr.*;
                            if (pkt.getStreamFrames().len > 0) {
                                self.queueStreamRetransmissions(pkt);
                            }
                        }
                    }

                    if (self.is_server) {
                        // Server confirms handshake immediately and clears Handshake keys
                        self.handshake_confirmed = true;
                        self.packetHandler().*.dropSpace(.handshake);
                        self.pkt_num_spaces[1].crypto_open = null;
                        self.pkt_num_spaces[1].crypto_seal = null;

                        // Server must send HANDSHAKE_DONE to the client (RFC 9001 Section 4.1.2)
                        self.packer.send_handshake_done = true;
                        self.handshake_done_pending = true;

                        // draft-ietf-quic-ack-frequency: disabled for now.
                        // Sending ACK_FREQUENCY changes the browser's ACK behavior,
                        // which can negatively impact datagram latency in ping-pong patterns.
                        // The RFC 9000 default (ACK every 2 ack-eliciting packets) works well
                        // for interactive workloads. Re-enable for bulk transfer scenarios.
                        // if (self.peer_supports_ack_freq) { ... }
                    }
                    // Client: Keep Handshake keys until HANDSHAKE_DONE received (RFC 9001 §4.9.2)
                    // This allows the client to ACK server's Handshake retransmissions under loss

                    // Store received session ticket if any
                    if (hs.received_ticket) |ticket| {
                        self.session_ticket = ticket;
                        std.log.info("stored session ticket (lifetime={d}s)", .{ticket.lifetime});
                    }

                    // Initialize KeyUpdateManager from TLS traffic secrets (RFC 9001 Section 6)
                    if (hs.key_schedule.computed_app) {
                        const recv_secret = if (self.is_server)
                            hs.key_schedule.client_app_traffic_secret
                        else
                            hs.key_schedule.server_app_traffic_secret;
                        const send_secret = if (self.is_server)
                            hs.key_schedule.server_app_traffic_secret
                        else
                            hs.key_schedule.client_app_traffic_secret;

                        // Get HP keys from current app-level Open/Seal (they never change)
                        const app_open = self.pkt_num_spaces[2].crypto_open.?;
                        const app_seal = self.pkt_num_spaces[2].crypto_seal.?;

                        self.key_update = quic_crypto.KeyUpdateManager.initFull(
                            recv_secret,
                            send_secret,
                            app_open.hp_key,
                            app_seal.hp_key,
                            hs.negotiated_cipher_suite,
                            self.version,
                        );
                        std.log.info("KeyUpdateManager initialized for 1-RTT key rotation", .{});
                    }

                    // Store peer transport parameters and apply stream limits
                    if (hs.peer_transport_params) |peer_tp| {
                        self.peer_params = peer_tp;
                        self.observed_paths[0].schedule(
                            self.local_params.address_discovery_role,
                            peer_tp.address_discovery_role,
                        );
                        self.native_paths = try native_path.process(self.native_paths, .{ .negotiate = .{
                            .local_max = self.local_params.initial_max_path_id,
                            .peer_max = peer_tp.initial_max_path_id,
                        } });
                        if (self.local_params.max_remote_nat_traversal_addresses) |local_limit| {
                            if (peer_tp.max_remote_nat_traversal_addresses) |peer_limit| {
                                self.nat_state = native_nat_state.State.init(
                                    self.is_server,
                                    local_limit,
                                    peer_limit,
                                );
                            }
                        }

                        try self.validatePeerTransportParams(&peer_tp, now);

                        self.streams.setMaxStreams(
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                        );
                        self.streams.setPeerInitialMaxStreamData(
                            peer_tp.initial_max_stream_data_bidi_local,
                            peer_tp.initial_max_stream_data_bidi_remote,
                            peer_tp.initial_max_stream_data_uni,
                        );
                        self.conn_flow_ctrl.base.send_window = peer_tp.initial_max_data;

                        // Enable DATAGRAM support if both sides advertise max_datagram_frame_size
                        if (peer_tp.max_datagram_frame_size != null and self.local_params.max_datagram_frame_size != null) {
                            self.datagrams_enabled = true;
                            std.log.info("DATAGRAM support enabled (peer max_dgram={d}, local max_dgram={d})", .{
                                peer_tp.max_datagram_frame_size.?,
                                self.local_params.max_datagram_frame_size.?,
                            });
                        }

                        // Negotiate idle timeout: use min of local and peer when both non-zero (RFC 9000 §10.1)
                        if (peer_tp.max_idle_timeout > 0 and self.local_params.max_idle_timeout > 0) {
                            const effective_ms = @min(peer_tp.max_idle_timeout, self.local_params.max_idle_timeout);
                            self.idle_timeout_ns = @as(i64, @intCast(effective_ms)) * 1_000_000;
                        } else if (peer_tp.max_idle_timeout > 0) {
                            self.idle_timeout_ns = @as(i64, @intCast(peer_tp.max_idle_timeout)) * 1_000_000;
                        }
                        // else: keep local timeout (already set)

                        // Recompute keep-alive interval after idle timeout negotiation
                        if (self.keep_alive_interval_ns > 0) {
                            self.keep_alive_interval_ns = @min(self.keep_alive_interval_ns, @divTrunc(self.idle_timeout_ns, 2));
                        }

                        // Apply peer's max_ack_delay to RTT stats (RFC 9002 §5.3)
                        self.packetHandler().*.rtt_stats.max_ack_delay = @as(i64, @intCast(peer_tp.max_ack_delay)) * 1_000_000;

                        // Store peer's stateless reset token for initial CID (RFC 9000 §10.3.1)
                        // Server sends this in transport params; client stores it for detection
                        if (peer_tp.stateless_reset_token) |token| {
                            self.peer_cid_pool.addPeerCid(0, self.dcid[0..self.dcid_len], token);
                            std.log.info("stored peer stateless reset token from transport params", .{});
                        }

                        std.log.info("applied peer transport params: max_bidi={d}, max_uni={d}, max_data={d}", .{
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                            peer_tp.initial_max_data,
                        });

                        // draft-ietf-quic-ack-frequency: detect peer support
                        if (peer_tp.min_ack_delay != null) {
                            self.peer_supports_ack_freq = true;
                        }

                        // Client: migrate to server's preferred address (RFC 9000 §9.6)
                        if (!self.is_server) {
                            if (peer_tp.preferred_address) |pref| {
                                if (!peer_tp.disable_active_migration) {
                                    // Store preferred CID + reset token in peer CID pool
                                    self.peer_cid_pool.addPeerCid(1, pref.getCid(), pref.stateless_reset_token);

                                    // Pick preferred address of the OTHER family to ensure a real path change.
                                    // Detects IPv4-mapped IPv6 (::ffff:x.x.x.x) as effectively IPv4.
                                    const current_is_v4 =
                                        self.paths[self.active_path_idx].peer_addr.isEffectivelyIpv4();
                                    const pref_addr = if (current_is_v4)
                                        (if (pref.hasIpv6()) pref.ipv6Address() else pref.ipv4Address())
                                    else
                                        (if (pref.hasIpv4()) pref.ipv4Address() else pref.ipv6Address());

                                    // Set up candidate path
                                    const candidate_idx: u8 = 1 - self.active_path_idx;
                                    self.paths[candidate_idx] = NetworkPath.init(
                                        self.paths[self.active_path_idx].local_addr,
                                        pref_addr,
                                        false,
                                    );

                                    // Switch active path
                                    self.active_path_idx = candidate_idx;

                                    // Update packer DCID to preferred CID
                                    if (self.peer_cid_pool.consumeUnused()) |entry| {
                                        self.useDcid(entry);
                                        std.log.info("preferred_address: using CID seq={d}", .{entry.seq_num});
                                    }

                                    // Start PATH_CHALLENGE
                                    const challenge = self.paths[candidate_idx].validator.startChallenge(now, random);
                                    self.pending_frames.push(.{ .path_challenge = challenge });

                                    // Reset CC/RTT/MTU/ECN for new IP
                                    self.pathCongestion().* = congestion.Cubic.init();
                                    self.pathPacer().* = congestion.Pacer.init();
                                    self.packetHandler().*.rtt_stats = rtt.RttStats{};
                                    self.pathMTU().*.reset();
                                    self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
                                    self.pathECN().*.reset();

                                    const migrating_to_v4 = !current_is_v4 and pref.hasIpv4();
                                    std.log.info("preferred_address: migrating from {s} to {s} port {d}", .{
                                        if (current_is_v4) "IPv4" else "IPv6",
                                        if (migrating_to_v4) "IPv4" else "IPv6",
                                        if (migrating_to_v4) pref.ipv4_port else pref.ipv6_port,
                                    });
                                }
                            }
                        }
                    }

                    // Issue NEW_CONNECTION_ID frames up to peer's active_connection_id_limit (RFC 9000 §5.1)
                    {
                        const peer_limit = if (self.peer_params) |pp| pp.active_connection_id_limit else 2;
                        while (self.local_cid_pool.activeCount() < @min(peer_limit, 4)) {
                            const maybe_entry = if (self.quic_lb_config) |*lb_cfg|
                                self.local_cid_pool.issueNewCidLb(lb_cfg, self.static_reset_key, random)
                            else
                                self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key, random);
                            if (maybe_entry) |entry| {
                                self.pushReliable(self.newConnectionIdFrame(entry));
                                std.log.info("issued NEW_CONNECTION_ID seq={d}, cid_len={d}", .{ entry.seq_num, entry.cid_len });
                            } else break; // pool full
                        }
                    }
                    if (self.multipathNegotiated() and
                        self.native_paths.peer_max_path_id >= 1)
                    {
                        try self.issuePathCid(random);
                    }

                    // Server: issue NEW_TOKEN for client address validation (RFC 9000 §8.1.3)
                    if (self.is_server) {
                        if (self.newTokenFrame(now, random)) |pcf| {
                            self.pushReliable(pcf);
                            std.log.info("issued NEW_TOKEN ({d} bytes)", .{pcf.new_token.token_len});
                        }
                    }

                    // Start PMTUD now that the handshake is complete
                    if (!self.disable_pmtud) self.pathMTU().*.start();

                    break;
                },
                ._continue => continue,
            }
        }
    }

    /// Adopts `new_version` as the version this connection speaks from here on
    /// (Compatible Version Negotiation, RFC 9368).
    ///
    /// `version` and the packer's header version move to `new_version`, and the
    /// TLS config's `quic_version` moves with them, so every Handshake and
    /// 1-RTT key derived afterwards carries the new version's HKDF labels.
    /// Nothing else moves with them.
    ///
    /// The first-flight version is what 0-RTT stays fixed to.
    /// `early_data_open` and `early_data_seal` are not touched here and were
    /// labelled for the version the first flight was built with, so they keep
    /// that version's labels, and the packer's `original_version` is what a
    /// 0-RTT packet still carries in its long header. That is RFC 9369 §4.1:
    /// a 0-RTT packet sent after the negotiation under the new version would be
    /// one the server has no 0-RTT keys for. A 0-RTT packet in flight, or
    /// replayed later out of `undecryptable`, is therefore still a
    /// first-flight-version packet, and `version` must not be read as
    /// describing 0-RTT.
    ///
    /// Only the Initial keys are re-derived, and asymmetrically, from
    /// `initial_dcid_buf` — the id the first flight used, not the current
    /// `dcid`, because that is the id the derivation is defined over. A server
    /// keeps its old open key and switches only its seal, so a client still
    /// retransmitting under the old version stays readable; a client switches
    /// only its open key and keeps its old seal. Either way the direction that
    /// may still receive under the old version keeps the key for it.
    ///
    /// `error.InvalidVersion` is the only tag, and it is raised after `version`
    /// has already been set: on that path `version` reads `new_version` while
    /// the Initial keys and the packer are untouched, so a caller that retries
    /// must pass the version it wanted rather than the one it reads back.
    pub fn switchVersion(self: *Connection, new_version: u32) !void {
        const old_version = self.version;
        self.version = new_version;

        // Re-derive Initial keys with the new version's salt
        const dcid = self.initial_dcid_buf[0..self.initial_dcid_len];
        const space = &self.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)];
        if (self.is_server) {
            // Server: only switch seal keys to v2 (keep v1 open for client retransmissions)
            const saved_open = space.crypto_open;
            const keys = try quic_crypto.deriveInitialKeyMaterial(dcid, new_version, true);
            space.crypto_open = saved_open; // restore v1 open
            space.crypto_seal = keys[1]; // v2 seal
        } else {
            // Client: only switch open keys to v2 (keep v1 seal, though we won't send more Initials)
            const saved_seal = space.crypto_seal;
            const keys = try quic_crypto.deriveInitialKeyMaterial(dcid, new_version, false);
            space.crypto_open = keys[0]; // v2 open
            space.crypto_seal = saved_seal; // restore v1 seal
        }

        // Update packet packer version
        self.packer.version = new_version;

        // Update TLS config version so handshake/app key derivation uses v2 HKDF labels
        if (self.tls13_hs) |hs| {
            hs.config.quic_version = new_version;
        }

        std.log.info("switchVersion: 0x{x:0>8} -> 0x{x:0>8}", .{ old_version, new_version });
    }

    /// Installs the Handshake-space keys TLS produced, replacing whichever
    /// were there. Called when TLS produces Handshake-level secrets.
    ///
    /// It replaces the keys and nothing else: the Initial keys stay until
    /// `dropHandshakeKeys`, because a peer may still retransmit an Initial,
    /// and the packet number spaces keep their counters. Both values are taken
    /// by value and stored inline, so nothing is borrowed and there is nothing
    /// to release.
    pub fn installHandshakeKeys(self: *Connection, open: quic_crypto.Open, seal: quic_crypto.Seal) void {
        // Packet number space index 1 = Handshake
        self.pkt_num_spaces[1].crypto_open = open;
        self.pkt_num_spaces[1].crypto_seal = seal;
        std.log.info("installHandshakeKeys: keys installed for space 1", .{});
    }

    /// Install 1-RTT (Application) encryption keys.
    /// Queue every stream's unacknowledged bytes as retransmit ranges for a PTO
    /// probe. Returns whether anything was queued.
    ///
    /// RFC 9002 §6.2.1 gives the Application space no PTO timer until the
    /// handshake is confirmed: 0-RTT data cannot have been acknowledged yet, and
    /// resending it at 1-RTT spends the round trip 0-RTT exists to save.
    ///
    /// The range stops at `send_offset`, not `write_offset`. What the
    /// application has written can run past the peer's MAX_STREAM_DATA, and this
    /// is the one send path with no window check of its own. `send_offset` is
    /// not rewound either: already-sent bytes must not be recounted against
    /// connection flow control when MAX_DATA credit is zero.
    fn queueStreamPtoRetransmissions(self: *Connection) bool {
        if (!self.handshake_confirmed) return false;
        var queued = false;
        var it = self.streams.streams.valueIterator();
        while (it.next()) |s_ptr| queued = queuePtoRetransmit(&s_ptr.*.send) or queued;
        var uni_it = self.streams.send_streams.valueIterator();
        while (uni_it.next()) |ss_ptr| queued = queuePtoRetransmit(ss_ptr.*) or queued;
        return queued;
    }

    fn queuePtoRetransmit(ss: *stream_mod.SendStream) bool {
        if (!ss.hasUnackedData()) return false;
        const start = ss.ack_offset;
        const end = ss.send_offset;
        if (end > start) {
            ss.queueRetransmit(start, end - start, ss.fin_sent);
        } else if (ss.fin_sent) {
            ss.queueRetransmit(end, 0, true);
        }
        return true;
    }

    /// Installs the 1-RTT keys TLS produced, replacing whichever were there,
    /// in the Application packet number space. Called when the handshake
    /// produces application-level secrets.
    ///
    /// Both values are taken by value and stored inline, so nothing is
    /// borrowed and there is nothing to release. This installs the keys; it
    /// does not start sending under them, which is `sendAt`'s decision.
    pub fn installAppKeys(self: *Connection, open: quic_crypto.Open, seal: quic_crypto.Seal) void {
        // Packet number space index 2 = Application (1-RTT)
        self.pkt_num_spaces[2].crypto_open = open;
        self.pkt_num_spaces[2].crypto_seal = seal;
        std.log.info("installAppKeys: keys installed for space 2", .{});
    }

    /// STREAM_DATA_BLOCKED and RESET_STREAM for one stream we send on, bidi or
    /// uni alike.
    fn queueSendSideFrames(self: *Connection, ss: *stream_mod.SendStream) void {
        if (ss.shouldSendBlocked()) |limit| {
            self.pending_frames.push(.{ .stream_data_blocked = .{
                .stream_id = ss.stream_id,
                .limit = limit,
            } });
        }
        if (ss.reset_err != null and !ss.reset_stream_sent) {
            // What went out, not what was written: buffered bytes were never
            // sent and may lie past the peer's window (RFC 9000 §4.5).
            // Marked sent only once queued; a full queue is retried next pass.
            ss.reset_stream_sent = self.pending_frames.tryPush(.{ .reset_stream = .{
                .stream_id = ss.stream_id,
                .error_code = ss.reset_err.?,
                .final_size = ss.send_offset,
            } });
        }
    }

    /// Check if connection-level flow control needs a MAX_DATA or MAX_STREAMS update.
    fn queueFlowControlUpdates(self: *Connection) void {
        // Frames that found the queue full last time go first.
        var moved: usize = 0;
        for (self.control_retry.items) |f| {
            if (!self.pending_frames.tryPush(f)) break;
            moved += 1;
        }
        if (moved > 0) {
            const rest = self.control_retry.items[moved..];
            @memmove(self.control_retry.items[0..rest.len], rest);
            self.control_retry.shrinkRetainingCapacity(rest.len);
        }

        // Garbage-collect fully-closed bidi streams so consumed count advances
        // and MAX_STREAMS updates can fire.
        self.streams.collectClosedStreams();

        // MAX_DATA grows only with what the consumer took or a reset abandoned.
        // With every byte charged already credited, no stream has any to give.
        const conn_fc = &self.conn_flow_ctrl.base;
        var credit: u64 = 0;
        if (conn_fc.bytes_read != conn_fc.highest_received) {
            credit = self.streams.takeConnCredit();
            self.conn_flow_ctrl.addBytesRead(credit);
        }

        // Credit generators commit the new limit as they return it, so each
        // one runs only when its frame is sure to fit.
        if (self.pending_frames.hasRoomFor(1)) {
            if (self.conn_flow_ctrl.getWindowUpdate(&self.packetHandler().*.rtt_stats)) |new_max| {
                self.pending_frames.push(.{ .max_data = new_max });
            }
        }

        // Check if MAX_STREAMS updates are needed (sliding window)
        if (self.pending_frames.hasRoomFor(2)) {
            const ms_update = self.streams.getMaxStreamsUpdates();
            if (ms_update.bidi) |new_max| {
                self.pending_frames.push(.{ .max_streams_bidi = new_max });
            }
            if (ms_update.uni) |new_max| {
                self.pending_frames.push(.{ .max_streams_uni = new_max });
            }
        }

        // MAX_STREAM_DATA: update peer's send window as we consume stream data.
        // A stream's update only comes due when its consumer reads, which is
        // what `credit` just measured, so with none there is nothing to find:
        // skipping the walk saves one of this function's per-datagram scans of
        // every stream. When `takeConnCredit` was not called at all, every
        // received byte was credited already and no stream can read more.
        if (credit > 0 or self.window_scan_pending) scan: {
            self.window_scan_pending = false;
            var stream_it = self.streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                if (!self.queueWindowUpdate(&s_ptr.*.recv)) {
                    self.window_scan_pending = true;
                    break :scan;
                }
            }
            // Peer-initiated uni streams carry H3 control, QPACK, WT and MoQ
            // data; without this they stall once the initial window is spent.
            var recv_it = self.streams.recv_streams.valueIterator();
            while (recv_it.next()) |rs_ptr| {
                if (!self.queueWindowUpdate(rs_ptr.*)) {
                    self.window_scan_pending = true;
                    break :scan;
                }
            }
        }

        // DATA_BLOCKED: signal peer when connection-level flow control blocks sending (RFC 9000 §4.1)
        if (self.conn_flow_ctrl.base.shouldSendBlocked()) |limit| {
            self.pending_frames.push(.{ .data_blocked = limit });
        }

        {
            // One walk of the bidi streams for both directions' frames.
            var stream_it = self.streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                self.queueSendSideFrames(&s_ptr.*.send);
                self.queueStopSending(&s_ptr.*.recv);
            }
            var uni_it = self.streams.send_streams.valueIterator();
            while (uni_it.next()) |ss_ptr| {
                self.queueSendSideFrames(ss_ptr.*);
                // A queued RESET_STREAM is the last thing a reset stream sends.
                self.streams.disposeUniIfSettled(ss_ptr.*);
            }
        }

        // STOP_SENDING for the peer's uni streams (bidi ones went above).
        {
            var recv_it = self.streams.recv_streams.valueIterator();
            while (recv_it.next()) |rs_ptr| self.queueStopSending(rs_ptr.*);
        }
    }

    /// MAX_STREAM_DATA for window the consumer freed. False once the queue is
    /// full: getWindowUpdate commits the limit it returns, so it runs only
    /// when the frame is sure to fit.
    fn queueWindowUpdate(self: *Connection, rs: *stream_mod.ReceiveStream) bool {
        if (!self.pending_frames.hasRoomFor(1)) return false;
        if (rs.getWindowUpdate()) |new_max| {
            self.pending_frames.push(.{ .max_stream_data = .{ .stream_id = rs.stream_id, .max = new_max } });
        }
        return true;
    }

    fn queueStopSending(self: *Connection, rs: *stream_mod.ReceiveStream) void {
        if (rs.stop_sending_err == null or rs.stop_sending_sent) return;
        rs.stop_sending_sent = self.pending_frames.tryPush(.{ .stop_sending = .{
            .stream_id = rs.stream_id,
            .error_code = rs.stop_sending_err.?,
        } });
    }

    /// RFC 9000 4.1: the connection window bounds the sum over streams of each
    /// stream's highest offset (or final size), so only growth past what the
    /// stream already charged counts — a retransmission charges nothing.
    fn chargeConnWindow(self: *Connection, rs: *stream_mod.ReceiveStream, end: u64, frame_type: FrameType, now: i64) error{FlowControlError}!void {
        if (end <= rs.conn_counted) return;
        // Data after a reset is dropped, and its final size already counted.
        if (frame_type == .stream and rs.reset_err != null) return;
        const fc = &self.conn_flow_ctrl.base;
        fc.addBytesReceived(fc.highest_received + (end - rs.conn_counted)) catch {
            self.closeWithTransportError(@intFromEnum(TransportError.flow_control_error), @intFromEnum(frame_type), "data exceeds connection flow control limit", now);
            return error.FlowControlError;
        };
        rs.conn_counted = end;
    }

    /// Queue a frame the peer must eventually see, holding it back if the
    /// queue is full rather than dropping it.
    fn pushReliable(self: *Connection, frame: frame_mod.PendingControlFrame) void {
        if (self.pending_frames.tryPush(frame)) return;
        self.control_retry.append(self.allocator, frame) catch
            std.log.warn("control frame {s} dropped: out of memory", .{@tagName(frame)});
    }

    /// Queue RETIRE_CONNECTION_ID for a peer CID, tracking it until acked.
    /// RFC 9000 5.1.2 lets us bound retirements in flight: past twice our
    /// active_connection_id_limit the peer is closed with
    /// CONNECTION_ID_LIMIT_ERROR, as quic-go and quinn do.
    fn retirePeerCid(self: *Connection, path_id: u1, seq: u64, now: i64) error{ProtocolViolation}!void {
        const pending = if (path_id == 0) &self.retiring_cids else &self.path1_transport.?.retiring_cids;
        if (std.mem.indexOfScalar(u64, pending.items, seq) != null) return;
        if (pending.items.len >= 2 * self.local_params.active_connection_id_limit) {
            self.closeWithTransportError(@intFromEnum(TransportError.connection_id_limit_error), @intFromEnum(FrameType.new_connection_id), "too many connection IDs pending retirement", now);
            return error.ProtocolViolation;
        }
        pending.append(self.allocator, seq) catch {
            self.closeWithTransportError(@intFromEnum(TransportError.internal_error), @intFromEnum(FrameType.new_connection_id), "out of memory", now);
            return error.ProtocolViolation;
        };
        self.pushReliable(if (self.multipathNegotiated())
            .{ .path_retire_connection_id = .{ .path_id = path_id, .seq_num = seq } }
        else
            .{ .retire_connection_id = seq });
    }

    fn onRetireCidAcked(self: *Connection, path_id: u1, seq: u64) void {
        const pending = if (path_id == 0) &self.retiring_cids else &self.path1_transport.?.retiring_cids;
        if (std.mem.indexOfScalar(u64, pending.items, seq)) |i| {
            _ = pending.swapRemove(i);
        }
    }

    /// RFC 9000 13.3: what a lost packet's control frames become. Credit is
    /// resent at its current value, not the one lost; anything the stream
    /// no longer needs is not resent at all.
    fn requeueLostControlFrames(self: *Connection, pkt: *const ack_handler.SentPacket, now: i64, random: std.Random) void {
        for (pkt.getControlFrames()) |cf| {
            const frame: frame_mod.PendingControlFrame = switch (cf) {
                .max_data => .{ .max_data = self.conn_flow_ctrl.base.receive_window },
                .max_stream_data => |id| blk: {
                    const rs = self.streams.getRecvStream(id) orelse continue;
                    // The final size is known: no more credit is needed.
                    if (rs.receive_window_size == 0 or rs.sorter.fin_offset != null) continue;
                    break :blk .{ .max_stream_data = .{ .stream_id = id, .max = rs.receive_window } };
                },
                .max_streams_bidi => .{ .max_streams_bidi = self.streams.max_incoming_bidi_streams },
                .max_streams_uni => .{ .max_streams_uni = self.streams.max_incoming_uni_streams },
                .data_blocked => |limit| blk: {
                    const fc = &self.conn_flow_ctrl.base;
                    if (fc.send_window != limit or !fc.isBlocked()) continue;
                    break :blk .{ .data_blocked = limit };
                },
                .stream_data_blocked => |b| blk: {
                    const ss = self.streams.getSendStream(b.stream_id) orelse continue;
                    if (ss.send_window != b.limit or ss.reset_err != null) continue;
                    break :blk .{ .stream_data_blocked = .{ .stream_id = b.stream_id, .limit = b.limit } };
                },
                .streams_blocked_bidi => |l| if (self.streams.max_bidi_streams == l) .{ .streams_blocked_bidi = l } else continue,
                .streams_blocked_uni => |l| if (self.streams.max_uni_streams == l) .{ .streams_blocked_uni = l } else continue,
                // Rebuilt from the record: a reset uni stream is already gone.
                .reset_stream => |r| .{ .reset_stream = .{ .stream_id = r.stream_id, .error_code = r.error_code, .final_size = r.final_size } },
                .stop_sending => |ss| blk: {
                    const rs = self.streams.getRecvStream(ss.stream_id) orelse continue;
                    // Data Recvd or Reset Recvd: the request is moot.
                    if (rs.reset_err != null or rs.sorter.fin_offset != null) continue;
                    break :blk .{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = ss.error_code } };
                },
                .new_connection_id => |seq| blk: {
                    for (&self.local_cid_pool.entries) |*e| {
                        if (e.occupied and !e.retired and e.seq_num == seq) break :blk self.newConnectionIdFrame(e);
                    }
                    continue;
                },
                .retire_connection_id => |seq| if (std.mem.indexOfScalar(u64, self.retiring_cids.items, seq) != null)
                    if (self.multipathNegotiated())
                        .{ .path_retire_connection_id = .{ .path_id = 0, .seq_num = seq } }
                    else
                        .{ .retire_connection_id = seq }
                else
                    continue,
                .new_token => self.newTokenFrame(now, random) orelse continue,
                .observed_address => |id| {
                    if (id >= 2 or self.native_paths.entries[id].abandoned) continue;
                    const roles = self.observedRoles();
                    self.observed_paths[id].lost(roles.local, roles.peer);
                    continue;
                },
                .add_address => |value| blk: {
                    const state = if (self.nat_state) |*s| s else continue;
                    for (state.localCandidates()) |candidate| {
                        if (candidate.sequence == value.sequence and
                            candidate.address.eql(value.address))
                        {
                            break :blk .{ .add_address = value };
                        }
                    }
                    continue;
                },
                .reach_address => |value| blk: {
                    const state = if (self.nat_state) |*s| s else continue;
                    if (value.round != state.currentRound()) continue;
                    for (state.localCandidates()) |candidate| {
                        if (candidate.address.eql(value.address)) {
                            break :blk .{ .reach_address = value };
                        }
                    }
                    continue;
                },
                .remove_address => |sequence| .{ .remove_address = sequence },
                .path_new_connection_id => |value| blk: {
                    for (&self.local_cid_pool.entries) |*entry| {
                        if (entry.occupied and !entry.retired and
                            entry.path_id == value.path_id and entry.seq_num == value.seq_num)
                        {
                            break :blk self.newConnectionIdFrame(entry);
                        }
                    }
                    continue;
                },
                .path_retire_connection_id => |value| blk: {
                    if (value.path_id >= 2) continue;
                    const pending = if (value.path_id == 0) &self.retiring_cids else if (self.path1_transport) |other| &other.retiring_cids else continue;
                    if (std.mem.indexOfScalar(u64, pending.items, value.seq_num) == null) continue;
                    break :blk .{ .path_retire_connection_id = value };
                },
                .path_status => |id| blk: {
                    if (id >= 2 or self.native_paths.entries[id].abandoned) continue;
                    break :blk if (self.local_path_status[id] == .available)
                        .{ .path_status_available = .{
                            .path_id = id,
                            .status_seq_no = self.local_path_status_seq[id],
                        } }
                    else
                        .{ .path_status_backup = .{
                            .path_id = id,
                            .status_seq_no = self.local_path_status_seq[id],
                        } };
                },
                .path_abandon => |value| if (value.path_id < 2 and
                    self.native_paths.entries[value.path_id].abandoned)
                    .{ .path_abandon = value }
                else
                    continue,
                .max_path_id => .{ .max_path_id = self.local_params.initial_max_path_id.? },
                .paths_blocked => |value| .{ .paths_blocked = value },
                .path_cids_blocked => |value| .{ .path_cids_blocked = value },
            };
            self.pushReliable(frame);
        }
    }

    /// Build and send outgoing packets.
    /// The 1-RTT seal, once there is one to use. A server holds it back until
    /// the handshake is confirmed: a 1-RTT PING before then draws a 1-RTT ACK
    /// instead of the Handshake Finished it still needs retransmitted.
    fn appSeal(self: *Connection) ?*const quic_crypto.Seal {
        if (self.is_server and !self.handshake_confirmed) return null;
        if (self.key_update) |*ku| return &ku.current_seal;
        return self.levelSeal(2);
    }

    fn levelSeal(self: *Connection, space_idx: usize) ?*const quic_crypto.Seal {
        if (self.transport_path == 1 and space_idx != 2) return null;
        return if (self.pkt_num_spaces[space_idx].crypto_seal) |*s| s else null;
    }

    /// Close a connection whose datagram could not be assembled. The frames the
    /// pass had already taken are gone with it — `packSinglePacket` documents
    /// both of its errors that way — so the connection cannot be left open
    /// holding a flight it swallowed, and nothing can be replayed for it:
    /// RFC 9000 §10.2 closes it with an internal error. A connection already
    /// closing, draining or terminated keeps the close it has, so the peer is
    /// told about the first one and not this.
    fn failAssembly(self: *Connection, now: i64) void {
        self.closeWithTransportError(
            @intFromEnum(TransportError.internal_error),
            0,
            "the datagram could not be assembled",
            now,
        );
    }

    /// Build and write the next datagram at `now`, a monotonic instant the
    /// caller read. Packets of one burst share it rather than each paying for
    /// a clock read — and the connection never reads one itself, so a test can
    /// drive an entire transfer in virtual time.
    /// `random` draws the packet numbers this send skips; it is the same
    /// generator the connection draws its own CIDs and reset keys from, handed
    /// in by the caller for the same reason.
    ///
    /// Zero means nothing was sent, which is not the same as having sent an
    /// empty datagram: a flight the caller can still send stays whole. Two
    /// errors mean the opposite — the pass had already taken frames and
    /// encrypted them before it failed — so each of them closes the connection
    /// with an internal error before it is returned, and nothing is replayed.
    fn sendNatProbe(self: *Connection, out: []u8, now: i64, random: std.Random) !usize {
        const state = if (self.nat_state) |*value| value else return 0;
        const reply = self.nat_reply;
        const offered = (try self.processNat(.{ .nextProbe = now })).probe;
        const target = if (reply) |value| value.peer else offered orelse return 0;
        const peer = @import("native_nat_policy.zig").canonicalAddress(target) catch return 0;
        if (!self.admitCandidate(peer)) return 0;
        if (reply == null and !(try self.processNat(.{ .preflightProbe = peer })).ready) return 0;
        if (!state.canRecordChallenge(peer)) return 0;
        const local = if (reply) |value| value.local else self.paths[0].local_addr;
        var token: [8]u8 = undefined;
        if (reply) |value| token = value.challenge else random.bytes(&token);
        const seal = self.appSeal() orelse return 0;
        self.activateTransport(0);
        self.packer.application_path_id = if (self.multipathNegotiated()) 0 else null;
        self.packer.updateDcid(self.dcid[0..self.dcid_len]);
        const written = try self.packer.packOffPath(out, &self.pkt_handler, seal, .{
            .challenge = token,
            .response = if (reply) |value| value.response else null,
        }, random);
        if (written != 0) {
            if (reply != null) {
                const result = try self.processNat(.{ .recordChallenge = .{
                    .address = peer,
                    .token = token,
                } });
                _ = result;
                self.nat_reply = null;
            } else {
                const result = try self.processNat(.{ .recordProbe = .{
                    .address = peer,
                    .token = token,
                } });
                _ = result;
            }
            self.last_send_peer = peer;
            self.last_send_local = local;
            self.last_send_ecn = 0;
            self.send_path = 0;
            self.last_send_off_path = true;
        }
        return written;
    }

    fn prepareObservedSend(self: *Connection, path_index: u8) !void {
        if (!self.handshake_confirmed) return;
        const id = if (self.multipathNegotiated()) path_index else 0;
        if (self.observed_queued[id] != null) return;
        if (self.observed_next_sequence > observed.sequence_max) return;
        // The route can be virtual while discovery describes a physical socket.
        // Apply the caller's physical admission before queueing or claiming a sequence.
        const peer = @import("native_nat_policy.zig").canonicalAddress(
            self.paths[path_index].peer_addr,
        ) catch return;
        if (!self.admitCandidate(peer)) return;
        const roles = self.observedRoles();
        if (try self.observed_paths[id].prepare(
            roles.local,
            roles.peer,
            peer,
            self.observed_next_sequence,
        )) |report| {
            if (self.path_control[path_index].tryPush(.{ .observed_address = report })) {
                self.observed_queued[id] = report.sequence;
            }
        }
    }

    fn commitObservedSend(self: *Connection) void {
        const id = if (self.multipathNegotiated()) self.send_path else 0;
        const sequence = self.observed_queued[id] orelse return;
        for (self.path_control[self.send_path].items[0..self.path_control[self.send_path].len]) |frame| {
            if (frame == .observed_address and frame.observed_address.sequence == sequence) return;
        }
        self.observed_paths[id].sent();
        self.observed_queued[id] = null;
        self.observed_next_sequence += 1;
    }

    pub fn sendAt(self: *Connection, out_buf: []u8, now: i64, random: std.Random) !usize {
        self.last_send_off_path = false;
        const before = [2]u64{
            self.pkt_handler.next_pn[2],
            if (self.path1_transport) |other| other.handler.next_pn[2] else 0,
        };
        const written = try self.sendPacketAt(out_buf, now, random);
        if (written != 0) {
            const id: u1 = if (self.multipathNegotiated()) @intCast(self.send_path) else 0;
            const handler = if (id == 1) &self.path1_transport.?.handler else &self.pkt_handler;
            if (handler.next_pn[2] > before[id]) {
                if (self.key_update) |*keys| {
                    if (self.last_send_off_path)
                        keys.onOffPathPacketSentForPath(id, handler.next_pn[2] - 1)
                    else
                        keys.onPacketSentForPath(id, handler.next_pn[2] - 1);
                }
            }
            self.commitObservedSend();
            if (self.challenge_queued[self.send_path]) {
                var still_queued = false;
                for (self.path_control[self.send_path].items[0..self.path_control[self.send_path].len]) |frame| {
                    if (frame == .path_challenge) still_queued = true;
                }
                if (!still_queued) {
                    if (written >= 1200 and !self.last_send_off_path)
                        self.challenge_full_size_sent[self.send_path] = true;
                    self.challenge_queued[self.send_path] = false;
                    if (self.challenge_retry_queued[self.send_path]) {
                        self.paths[self.send_path].validator.retry(now);
                        self.challenge_retry_queued[self.send_path] = false;
                    } else {
                        self.paths[self.send_path].validator.challenge_sent_time = now;
                    }
                }
            }
        }
        return written;
    }

    fn resumeDirectPath(self: *Connection, now: i64, random: std.Random) PathError!void {
        const ready = self.direct_ready orelse return;
        if (!self.handshake_confirmed or self.state != .connected or
            !self.multipathNegotiated() or self.native_paths.peer_max_path_id < 1 or
            self.native_paths.entries[1].opened or self.native_paths.entries[1].abandoned or
            self.path1_transport == null or self.path1_transport.?.dcid_len == 0)
            return;
        if (!self.admitCandidate(ready.peer)) {
            self.direct_ready = null;
            return;
        }
        const id = try self.openPath(ready.local, ready.peer, now, random);
        self.pushReliable(.{ .path_status_backup = .{
            .path_id = id,
            .status_seq_no = self.local_path_status_seq[id],
        } });
        self.direct_ready = null;
    }

    fn sendPacketAt(self: *Connection, out_buf: []u8, now: i64, random: std.Random) !usize {
        // Draining/terminated: do not send anything
        if (self.state == .draining or self.state == .terminated) return 0;
        if (self.handshake_confirmed and self.state == .connected) {
            const probe = try self.sendNatProbe(out_buf, now, random);
            if (probe != 0) return probe;
            try self.resumeDirectPath(now, random);
        }
        const mp = self.multipathNegotiated();
        self.send_path = self.active_path_idx;
        if (mp) {
            for (0..2) |id| {
                const handler = if (id == 0) &self.pkt_handler else if (self.path1_transport) |other| &other.handler else continue;
                const ack_ready = handler.recv[2].ack_queued or
                    (handler.recv[2].ack_alarm != null and handler.recv[2].ack_alarm.? <= now);
                const pending_probe = if (id == 0) self.pto_probe_pending else self.path1_transport.?.probe_pending;
                if ((self.path_control[id].len != 0 or ack_ready or pending_probe != 0) and
                    !self.native_paths.entries[id].abandoned)
                {
                    self.send_path = @intCast(id);
                    break;
                }
            }
        }
        try self.prepareObservedSend(self.send_path);
        self.last_send_peer = self.paths[self.send_path].peer_addr;
        self.last_send_local = self.paths[self.send_path].local_addr;
        self.last_send_ecn = self.getEcnMark();
        const selected = self.active_path_idx;
        self.active_path_idx = self.send_path;
        defer self.active_path_idx = selected;
        self.activateTransport(if (mp) self.send_path else 0);
        defer self.activateTransport(0);
        self.packer.application_path_id = if (mp) self.send_path else null;
        if (mp) self.packer.max_packet_size = self.pathMTU().*.current_mtu;
        self.packer.ecn_mark = self.pathECN().*.shouldMark();
        self.last_send_ecn = self.getEcnMark();
        const control = self.path_control[self.send_path].len != 0 or
            (mp and self.send_path != selected);
        if (mp and self.send_path == 1) {
            const other = self.path1_transport.?;
            self.packer.updateDcid(other.dcid[0..other.dcid_len]);
        }
        defer self.packer.updateDcid(self.dcid[0..self.dcid_len]);
        if (control) {
            self.packer.application_padding_min = 0;
            for (self.path_control[self.send_path].items[0..self.path_control[self.send_path].len]) |frame| {
                if (frame == .path_challenge) self.packer.application_padding_min = 1200;
            }
            defer self.packer.application_padding_min = 0;
            var empty_streams = stream_mod.StreamsMap.init(self.allocator, self.is_server);
            defer empty_streams.deinit();
            var budget = out_buf;
            const path = &self.paths[self.send_path];
            if (self.is_server and !path.is_validated) {
                const available = (3 * path.bytes_received) -| path.bytes_sent;
                budget = out_buf[0..@intCast(@min(available, out_buf.len))];
            }
            const written = self.packer.packCoalesced(
                budget,
                self.packetHandler(),
                &self.crypto_streams,
                &empty_streams,
                &self.path_control[self.send_path],
                null,
                null,
                null,
                self.appSeal(),
                now,
                null,
                false,
                random,
            ) catch |err| {
                self.failAssembly(now);
                return err;
            };
            path.bytes_sent += written;
            if (written != 0) self.last_packet_sent_time = now;
            self.pathProbePending().* -|= 1;
            return written;
        }
        if (mp and self.native_paths.entries[self.send_path].abandoned) return 0;

        // Closing: retransmit saved close packet on each incoming packet (RFC 9000 §10.2.1)
        if (self.state == .closing) {
            if (self.close_pkt_len > 0) {
                // Already built the close packet
                if (self.needs_close_retransmit) {
                    // A buffer that cannot hold the packet is not a refusal of
                    // it: nothing is copied, the trigger stands, and the next
                    // pass with room still has this packet to send.
                    if (out_buf.len < self.close_pkt_len) return 0;
                    self.needs_close_retransmit = false;
                    const len = self.close_pkt_len;
                    @memcpy(out_buf[0..len], self.close_pkt_buf[0..len]);
                    return len;
                }
                // Not triggered by incoming packet — just waiting for timeout
                return 0;
            }

            // No packet is kept, so build the flight: the first one, or the
            // next one after a flight too long for the cache to hold.
            const app_seal: ?*const quic_crypto.Seal = if (self.key_update) |*ku|
                &ku.current_seal
            else
                self.levelSeal(2);
            const handshake_seal = self.levelSeal(1);
            const initial_seal = self.levelSeal(0);

            // Try 1-RTT, then Handshake, then Initial
            const seal = app_seal orelse handshake_seal orelse initial_seal;
            if (seal != null) {
                // During closing, send at ALL available encryption levels
                // so the peer can decrypt at whatever level they've reached.
                // Include Initial/Handshake crypto data so the peer can
                // derive keys before seeing the CONNECTION_CLOSE.
                const bytes_written = self.packer.packCoalesced(
                    out_buf,
                    &self.packetHandler().*,
                    &self.crypto_streams,
                    &self.streams,
                    &self.pending_frames,
                    initial_seal,
                    null,
                    handshake_seal,
                    app_seal,
                    now,
                    null,
                    false, // not ack_only — sending CONNECTION_CLOSE
                    random,
                ) catch |err| {
                    self.failAssembly(now);
                    return err;
                };
                if (bytes_written > 0 and bytes_written <= self.close_pkt_buf.len) {
                    // Only a whole flight is kept. A closing connection owes
                    // the CRYPTO data it never sent, so the datagram is
                    // regularly longer than this cache, and a truncated copy is
                    // not a retransmission: the peer reads the Length field and
                    // finds bytes that never arrived. Too long is not a
                    // refusal of the close either — `close_pkt_len` stays 0 and
                    // the next send builds the flight again.
                    const save_len: u16 = @intCast(bytes_written);
                    @memcpy(self.close_pkt_buf[0..save_len], out_buf[0..save_len]);
                    self.close_pkt_len = save_len;
                }
                return bytes_written;
            }
            return 0;
        }

        // Check congestion window — only send ACKs + control frames when congestion-limited
        // Exception: PTO probes MUST bypass congestion control (RFC 9002 §6.2.4)
        // DATAGRAM frames are subject to CC per RFC 9221 §5: "DATAGRAM frames SHOULD be
        // subject to congestion control" — they piggyback on CC-allowed packets only.
        if (self.packetHandler().*.bytes_in_flight >= self.pathCongestion().*.sendWindow() and self.pathProbePending().* == 0) {
            // ACK-only packets bypass pacing (RFC 9002 §7.7)
            return try self.sendAckOnly(out_buf, now, random);
        }

        // PMTUD: a probe is its own datagram, and goes above the pacer. Below it
        // the only way here is a pass that has nothing to send and is not paced,
        // which a connection carrying requests back to back never gets: routez
        // sent no probe at all over 128 connections and stayed at 1200 bytes.
        // At most one probe per 5×RTT (200 ms floor), so the data it delays is
        // one datagram that rarely exists.
        self.pathMTU().*.checkRaiseTimer(now);
        // shouldProbe first: it is almost always false.
        if (self.pathMTU().*.shouldProbe(now, self.packetHandler().*.rtt_stats.smoothedRttOrDefault())) {
            if (self.appSeal()) |seal| {
                const probe_size: usize = self.pathMTU().*.nextProbeSize();
                if (out_buf.len >= probe_size) {
                    const result = self.packer.packMtuProbe(
                        out_buf,
                        probe_size,
                        &self.packetHandler().*,
                        seal,
                        now,
                        random,
                    ) catch |err| {
                        self.failAssembly(now);
                        return err;
                    };
                    if (result.bytes_written > 0) {
                        self.pathMTU().*.onProbeSent(result.pn, @intCast(result.bytes_written), now);
                        self.paths[self.active_path_idx].bytes_sent += result.bytes_written;
                        self.total_packets_sent += 1;
                        return result.bytes_written;
                    }
                }
            }
        }

        // Check if pacer allows sending
        // Exception: PTO probes bypass pacing (RFC 9002 §6.2.4)
        // Note: ACK-only path above bypasses pacer per RFC 9002 §7.7
        if (self.pathProbePending().* == 0) {
            const pacer_delay = self.pathPacer().*.timeUntilSend(now);
            if (pacer_delay > 0) {
                return 0;
            }
        }

        // Queue flow control updates before packing
        self.queueFlowControlUpdates();

        // Check if we should proactively initiate a key update (RFC 9001 Section 6)
        if (self.key_update) |*ku| {
            ku.maybeDropPrevKeys(now);
            if (ku.shouldInitiateUpdate() and ku.canUpdate()) {
                const pto_ns = self.maxActivePathPto();
                ku.rollKeys(now, pto_ns);
                self.packer.key_phase = ku.key_phase;
                std.log.info("key update: self-initiated at {d} packets, new key_phase={}", .{
                    quic_crypto.CONFIDENTIALITY_LIMIT,
                    ku.key_phase,
                });
            }
        }

        // Anti-amplification: servers must not send more than 3x bytes received
        // before address validation (RFC 9000 Section 8.1).
        // Instead of a binary canSend(1200) check, calculate remaining budget
        // and limit the output buffer size. This allows sending smaller packets
        // when the full MTU isn't available, using every byte of the 3x budget.
        var send_buf = out_buf;
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.is_validated) {
                const budget = 3 * active_path.bytes_received;
                if (active_path.bytes_sent >= budget) return 0;
                const remaining = budget - active_path.bytes_sent;
                if (remaining < out_buf.len) {
                    send_buf = out_buf[0..@intCast(remaining)];
                }
            }
        }

        // Build coalesced packet with available encryption levels
        // Packet number space indices: 0=Initial, 1=Handshake, 2=Application
        const initial_seal = self.levelSeal(0);
        const handshake_seal = self.levelSeal(1);
        const app_seal = self.appSeal();

        // 0-RTT seal (client only, before handshake completes)
        const early_seal: ?*const quic_crypto.Seal = if (self.handshake_confirmed) null else if (self.early_data_seal) |*s| s else null;

        const dq: ?*DatagramQueue = if (self.datagrams_enabled and !self.datagram_send_queue.isEmpty())
            &self.datagram_send_queue
        else
            null;

        self.packer.conn_flow_ctrl = &self.conn_flow_ctrl;
        self.packer.ecn_mark = self.pathECN().*.shouldMark();

        const bytes_written = self.packer.packCoalesced(
            send_buf,
            &self.packetHandler().*,
            &self.crypto_streams,
            &self.streams,
            &self.pending_frames,
            initial_seal,
            early_seal,
            handshake_seal,
            app_seal,
            now,
            dq,
            false, // ack_only
            random,
        ) catch |err| {
            self.failAssembly(now);
            return err;
        };

        // Always consume PTO probe slots, even if nothing was packed.
        // Without this, an empty second probe leaves pto_probe_pending=1 forever,
        // blocking all subsequent PTO fires from re-queuing crypto data.
        if (bytes_written == 0 and self.pathProbePending().* > 0) {
            self.pathProbePending().* -|= 1;
        }

        if (bytes_written > 0) {
            self.pathProbePending().* -|= 1;
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            self.total_packets_sent += 1;
            self.pathPacer().*.onPacketSent(bytes_written, now);
            self.last_packet_sent_time = now;

            // If more PTO probes are pending, re-queue stream data + crypto data
            // so the next probe ALSO carries the retransmission (not just a PING).
            // Under burst-3 loss, both probes carrying data doubles the delivery chance.
            if (self.pathProbePending().* > 0) {
                // Re-queue crypto retransmissions
                if (self.pkt_num_spaces[0].crypto_seal != null) {
                    self.queueCryptoRetransmission(.initial);
                }
                if (self.pkt_num_spaces[1].crypto_seal != null) {
                    self.queueCryptoRetransmission(.handshake);
                }
                _ = self.queueStreamPtoRetransmissions();
            }

            // Client: auto-clear Handshake keys once Finished has been sent AND acknowledged
            // RFC 9001 §4.9.2: "A client MUST NOT discard keys for the Handshake packet
            // number space until ... its HANDSHAKE packets have been acknowledged."
            if (!self.is_server and self.handshake_confirmed and self.pkt_num_spaces[1].crypto_seal != null) {
                if (!self.crypto_streams.getStream(1).hasData()) {
                    const hs_tracker = &self.packetHandler().*.sent[@intFromEnum(ack_handler.EncLevel.handshake)];
                    if (hs_tracker.ack_eliciting_in_flight == 0) {
                        self.dropHandshakeKeys();
                    }
                }
            }

            // Track ECN marking for sent packets
            if (self.pathECN().*.shouldMark() and app_seal != null) {
                self.pathECN().*.onPacketSent();
            }
        }

        return bytes_written;
    }

    /// Send ACK-only packets (when congestion limited).
    /// ACKs are NOT congestion-controlled per RFC 9000 §13.2.
    fn sendAckOnly(self: *Connection, out_buf: []u8, now: i64, random: std.Random) !usize {
        // Piggyback flow control updates (MAX_DATA, MAX_STREAMS)
        self.queueFlowControlUpdates();

        // Anti-amplification: limit output to remaining budget
        var send_buf = out_buf;
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.is_validated) {
                const budget = 3 * active_path.bytes_received;
                if (active_path.bytes_sent >= budget) return 0;
                const remaining = budget - active_path.bytes_sent;
                if (remaining < out_buf.len) {
                    send_buf = out_buf[0..@intCast(remaining)];
                }
            }
        }

        // Gather seals at all encryption levels
        const initial_seal = self.levelSeal(0);
        const handshake_seal = self.levelSeal(1);
        const app_seal = self.appSeal();

        const bytes_written = self.packer.packCoalesced(
            send_buf,
            &self.packetHandler().*,
            &self.crypto_streams,
            &self.streams,
            &self.pending_frames,
            initial_seal,
            null, // no 0-RTT for ACK-only
            handshake_seal,
            app_seal,
            now,
            null, // no datagrams
            true, // ack_only
            random,
        ) catch |err| {
            self.failAssembly(now);
            return err;
        };

        if (bytes_written > 0) {
            self.pathProbePending().* -|= 1;
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            self.total_packets_sent += 1;
            // Don't update pacer — ACKs are not paced
        }

        return bytes_written;
    }

    /// Handle connection migration (RFC 9000 Section 9).
    /// Called when a 1-RTT packet with non-probing frames arrives from a different address.
    fn handleMigration(
        self: *Connection,
        new_peer_addr: address.Address,
        local_addr: address.Address,
        now: i64,
        random: std.Random,
    ) void {
        // Check if peer disabled active migration
        if (self.peer_params) |pp| {
            if (pp.disable_active_migration) {
                std.log.info("migration: peer disabled active migration, ignoring", .{});
                return;
            }
        }

        // Set up candidate path at the alternate index
        const candidate_idx: u8 = 1 - self.active_path_idx;
        self.paths[candidate_idx] = NetworkPath.init(local_addr, new_peer_addr, false);

        // Try to consume a fresh CID for the new path
        if (self.peer_cid_pool.consumeUnused()) |entry| {
            self.useDcid(entry);
            std.log.info("migration: switched to new peer CID seq={d}", .{entry.seq_num});
        }

        // Switch active path
        self.active_path_idx = candidate_idx;

        // Start path validation via PATH_CHALLENGE
        const challenge = self.paths[candidate_idx].validator.startChallenge(now, random);
        self.pending_frames.push(.{ .path_challenge = challenge });

        // Reset CC/RTT/MTU/ECN if IP address changed (not just port — NAT rebinding preserves CC)
        const old_path = &self.paths[1 - candidate_idx];
        const same_ip = new_peer_addr.sameIp(old_path.peer_addr);
        if (!same_ip) {
            self.pathCongestion().* = congestion.Cubic.init();
            self.pathPacer().* = congestion.Pacer.init();
            self.packetHandler().*.rtt_stats = rtt.RttStats{};
            self.pathMTU().*.reset();
            self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
            self.pathECN().*.reset();
            std.log.info("migration: IP changed, reset CC, RTT, MTU and ECN", .{});
        } else {
            // NAT rebinding (port-only change): path is already validated since same IP,
            // and carry over MTU from old path
            self.paths[candidate_idx].is_validated = true;
            // Mark current time as congestion recovery start so that loss detection
            // for pre-migration packets (sent to old port) won't reduce CWND —
            // these are path losses, not congestion losses.
            self.pathCongestion().*.enterRecoveryForMigration(now);
            std.log.info("migration: port-only change (NAT rebinding), preserving CC", .{});
        }
    }

    /// Check for timeouts and maintenance tasks at `now`, the caller's
    /// monotonic instant. Every deadline below is measured against it, so a
    /// virtual clock advances this by exactly the amount the simulation says
    /// elapsed and not by however long the host took to get here.
    pub fn onTimeout(self: *Connection, now: i64, random: std.Random) !void {
        self.activateTransport(0);
        if (self.key_update) |*keys| keys.maybeDropPrevKeys(now);
        if (self.nat_state != null) {
            _ = try self.processNat(.{ .nextProbe = now });
        }
        try self.onPathTimeout(now, random);
        if (self.multipathNegotiated() and self.native_paths.entries[1].opened and
            !self.native_paths.entries[1].abandoned)
        {
            self.activateTransport(1);
            defer self.activateTransport(0);
            try self.onPathTimeout(now, random);
        }
    }

    fn onPathTimeout(self: *Connection, now: i64, random: std.Random) !void {
        if (self.state == .terminated) return;

        // Closing/draining: wait 3×PTO then terminate (RFC 9000 §10.2)
        if (self.state == .closing or self.state == .draining) {
            if (self.closing_start_time > 0) {
                const pto_ns = self.maxActivePathPto();
                const drain_timeout = 3 * pto_ns;
                if (now - self.closing_start_time > drain_timeout) {
                    self.state = .terminated;
                    std.log.info("connection terminated after draining period", .{});
                }
            }
            return;
        }

        // Check idle timeout (RFC 9000 §10.1, §10.1.2)
        // The effective idle timeout MUST be at least 3× the *base* PTO (without backoff)
        // to avoid terminating the connection before probes have a chance to be answered.
        //
        // When data is in flight, extend idle to cover the current PTO backoff schedule,
        // but cap at 5 retries to prevent indefinite extension (e.g. server broadcasting
        // to a dead peer would otherwise grow effective_idle to 180s+).
        if (self.transport_path == 0) {
            const base_pto = self.maxActivePathPto();
            var effective_idle = @max(self.idle_timeout_ns, 3 * base_pto);
            const app_idx = @intFromEnum(ack_handler.EncLevel.application);
            if (self.handshake_confirmed and self.packetHandler().*.sent[app_idx].ack_eliciting_in_flight > 0) {
                const capped_pto_count = @min(self.packetHandler().*.pto_count, 5);
                const shift: u6 = @intCast(capped_pto_count);
                const backed_off_pto = base_pto << shift;
                effective_idle = @max(effective_idle, 3 * backed_off_pto);
            }
            // RFC 9000 §10.1.2: Before handshake confirmed, also defer idle timeout
            // when sending ack-eliciting packets (to avoid premature timeout during
            // handshake retransmission). After handshake confirmed, only received
            // packets reset the idle timer.
            const last_activity = if (!self.handshake_confirmed)
                @max(self.last_packet_received_time, self.last_packet_sent_time)
            else
                self.last_packet_received_time;
            if (now - last_activity > effective_idle) {
                self.state = .terminated;
                return;
            }
        }
        // Auto-close: when close_when_idle is set and all stream data has been
        // sent (FIN queued, no pending retransmissions), close the connection.
        // Don't wait for control frame ACKs (HANDSHAKE_DONE, NEW_CONNECTION_ID)
        // which can take multiple RTTs under loss.
        // Auto-close: when close_when_idle is set, close the connection once all
        // stream data has been queued for sending (FIN queued, no pending retransmissions).
        // This triggers close BEFORE the data is necessarily ACKed — the CONNECTION_CLOSE
        // is coalesced with or sent after the data, so the peer receives both. Under loss,
        // if the data packet is lost, the CONNECTION_CLOSE packet still reaches the peer,
        // which then closes its side. The server's draining period handles retransmission
        // of the close frame.
        if (self.transport_path == 0 and self.close_when_idle and
            self.handshake_confirmed and self.state == .connected)
        {
            if (self.streams.streams.count() > 0) {
                var all_streams_done = true;
                var stream_it = self.streams.streams.valueIterator();
                while (stream_it.next()) |s_ptr| {
                    if (s_ptr.*.send.hasData() or !s_ptr.*.send.fin_queued) {
                        all_streams_done = false;
                        break;
                    }
                }
                if (all_streams_done) {
                    self.close(0, "", now);
                    return;
                }
            }
        }

        // Loss detection timer: check loss_time BEFORE PTO (RFC 9002 §6.2.1).
        // Loss timers don't increment pto_count — they run loss detection directly.
        if (self.packetHandler().*.getExpiredLossTime(now)) |loss_level| {
            var loss_result: ack_handler.AckResult = .{};
            defer loss_result.deinit(self.allocator);
            try self.packetHandler().*.detectLossesForSpace(loss_level, now, &loss_result);
            var has_non_probe_loss_lt = false;
            var earliest_lost_sent_time_lt: ?i64 = null;
            for (loss_result.lost.constSlice()) |pkt| {
                self.total_packets_lost += 1;
                if (pkt.has_datagram) self.datagrams_lost_outgoing += 1;

                if (self.pathMTU().*.onProbeLost(pkt.pn, now)) {} else {
                    has_non_probe_loss_lt = true;
                    if (earliest_lost_sent_time_lt == null or pkt.time_sent < earliest_lost_sent_time_lt.?) {
                        earliest_lost_sent_time_lt = pkt.time_sent;
                    }
                }
                self.queueStreamRetransmissions(pkt);
                self.requeueLostControlFrames(pkt, now, random);
                if (pkt.has_crypto_data) {
                    self.queueCryptoRetransmission(pkt.enc_level);
                }
                if (pkt.has_handshake_done and self.handshake_done_pending) {
                    self.packer.send_handshake_done = true;
                }
            }
            if (has_non_probe_loss_lt) {
                if (loss_result.persistent_congestion) {
                    if (earliest_lost_sent_time_lt) |lost_time| {
                        if (!self.pathCongestion().*.inCongestionRecovery(lost_time)) {
                            self.pathCongestion().*.onPersistentCongestion(now);
                            std.log.info("persistent congestion detected (loss timer), window reduced to minimum", .{});
                        }
                    }
                } else if (earliest_lost_sent_time_lt) |lost_time| {
                    self.pathCongestion().*.onCongestionEvent(lost_time, now);
                }
            }
            self.pathPacer().*.setBandwidth(self.pathCongestion().*.sendWindow(), &self.packetHandler().*.rtt_stats);
        }

        // Check PTO — fire when any space has an expired deadline.
        // Loss detection and PTO can both fire in the same onTimeout() call.
        if (self.packetHandler().*.getPtoTimeout()) |pto_time| {
            if (now >= pto_time) {
                self.packetHandler().*.pto_count += 1;
                // Increment per-space PTO count for the space that triggered
                if (self.packetHandler().*.getPtoSpace()) |pto_space| {
                    self.packetHandler().*.sent[@intFromEnum(pto_space)].pto_count += 1;
                }

                // Force-arm ACKs so probes include acknowledgements.
                // When a PTO fires, our previous packets (which carried ACK frames) likely
                // never reached the peer. getAckFrame() clears ack_queued on first call,
                // so without re-arming, PTO probes go out without ACKs. This is critical
                // for amplification-limited handshakes: the server needs ACKs to know the
                // client received its data, and the client needs ACKs in its probes to
                // give the server enough anti-amplification credit.
                //
                // Force-arm ALL spaces (not just the PTO space), because:
                // - Initial PTO should include Handshake ACKs (coalesced packets)
                // - The server needs Handshake ACKs to lift the amplification limit
                for (&self.packetHandler().*.recv) |*recv_tracker| {
                    if (recv_tracker.largest_received != null) {
                        recv_tracker.ack_queued = true;
                    }
                }

                // Queue retransmission for ALL spaces with outstanding data.
                // quic-go fires PTO for each space separately, sending 2 probes per
                // space. This maximizes the chance of at least one packet getting
                // through burst loss (burst_to_client=3 drops 3 consecutive packets).
                var has_data = false;

                // Handshake spaces: re-queue crypto data
                {
                    const has_hs_keys = self.pkt_num_spaces[1].crypto_seal != null;
                    if (!has_hs_keys and self.pkt_num_spaces[0].crypto_seal != null) {
                        self.queueCryptoRetransmission(.initial);
                    }
                    if (self.pkt_num_spaces[1].crypto_seal != null) {
                        self.queueCryptoRetransmission(.handshake);
                    }
                    if (self.crypto_streams.getStream(0).hasData() or
                        self.crypto_streams.getStream(2).hasData())
                    {
                        has_data = true;
                    }
                }

                // Application space — always process, not just when it's the earliest.
                // quic-go fires PTO for each space independently; we process all
                // spaces in a single onTimeout() to maximize packet diversity.
                {
                    {
                        // Client: also retransmit Handshake Finished when Application
                        // PTO fires but the handshake is not yet confirmed.
                        if (!self.is_server and !self.handshake_confirmed) {
                            self.queueCryptoRetransmission(.handshake);
                            if (self.crypto_streams.getStream(2).hasData()) {
                                has_data = true;
                            }
                        }
                        // Check application-level crypto stream (e.g. NewSessionTicket)
                        if (self.crypto_streams.getStream(3).hasData()) {
                            has_data = true;
                        }
                        // HANDSHAKE_DONE: re-arm for retransmission on PTO
                        if (self.handshake_done_pending) {
                            self.packer.send_handshake_done = true;
                            has_data = true;
                        }
                        // Check if any stream has data to send
                        {
                            var stream_it = self.streams.streams.valueIterator();
                            while (stream_it.next()) |s_ptr| {
                                if (s_ptr.*.send.hasData()) {
                                    has_data = true;
                                    break;
                                }
                            }
                        }
                        if (self.queueStreamPtoRetransmissions()) has_data = true;
                    }
                }

                // RFC 9002 §6.2.4: "An endpoint MUST send at least one
                // ack-eliciting packet in the packet number space..."
                // Always push a PING so the second probe (pto_probe_pending=2)
                // has content even after the first probe consumed crypto data.
                // For has_data=false, only push if there's stream data in flight
                // (to allow idle timeout when all data is delivered).
                if (has_data) {
                    // PING for second probe (first probe has crypto/stream data)
                    if (self.multipathNegotiated()) {
                        self.path_control[self.transport_path].push(.{ .ping = {} });
                    } else {
                        self.pending_frames.push(.{ .ping = {} });
                    }
                    self.idle_pto_count = 0;
                } else {
                    var has_stream_in_flight = false;
                    const app_tracker2 = &self.packetHandler().*.sent[@intFromEnum(ack_handler.EncLevel.application)];
                    var pkt_it2 = app_tracker2.sent_packets.iterator();
                    while (pkt_it2.next()) |entry| {
                        if (entry.value_ptr.*.in_flight and entry.value_ptr.*.getStreamFrames().len > 0) {
                            has_stream_in_flight = true;
                            break;
                        }
                    }
                    // A PTO in a handshake space must produce an ack-eliciting
                    // probe even with nothing to resend (RFC 9002 §6.2.4).
                    // Sending nothing leaves last_ack_eliciting_sent_time — what
                    // the deadline is measured from — where it was, so the
                    // deadline stays expired and the PTO re-fires on every tick
                    // without ever probing: 22365 fires in 10 s of
                    // handshakecorruption. Letting the app space stay quiet is
                    // deliberate, so that a delivered connection can idle out.
                    const in_handshake_space = if (self.packetHandler().*.getPtoSpace()) |sp|
                        sp != .application
                    else
                        false;
                    if (in_handshake_space or has_stream_in_flight) {
                        if (self.multipathNegotiated()) {
                            self.path_control[self.transport_path].push(.{ .ping = {} });
                        } else {
                            self.pending_frames.push(.{ .ping = {} });
                        }
                    }
                    self.idle_pto_count += 1;
                }
                // RFC 9002 §6.2.4: "An endpoint MUST send at least one ack-eliciting
                // packet in the packet number space..." — quic-go sends 2 probes per
                // PTO fire for burst loss resilience. With burst_to_client=3, a single
                // probe can be wiped; 2 probes double the chance of getting through.
                self.pathProbePending().* = 2;
                if (self.packetHandler().*.getPtoSpace()) |space| {
                    std.log.info("PTO fired: count={d}, space={s}, has_data={}", .{ self.packetHandler().*.pto_count, @tagName(space), has_data });
                }
            }
        }

        // RFC 9002 §6.2.2.1: Client anti-deadlock timer.
        // When the client has no ack-eliciting packets in flight and the handshake
        // is not confirmed, the server might be blocked by the anti-amplification
        // limit. The client MUST arm a PTO timer to send packets that unblock the
        // server (e.g. a PING in a Handshake or padded Initial packet).
        if (!self.is_server and !self.handshake_confirmed) {
            // Compute PTO based on time since handshake start (creation_time)
            var pto_duration = self.packetHandler().*.rtt_stats.ptoNoAckDelay();
            const shift: u6 = @intCast(@min(self.packetHandler().*.pto_count, 30));
            pto_duration = pto_duration << shift;
            pto_duration = @min(pto_duration, 60_000_000_000); // cap at 60s

            const deadline = self.creation_time + pto_duration;
            if (now >= deadline) {
                self.packetHandler().*.pto_count += 1;

                // Force-arm ACKs so anti-deadlock probes include them.
                // Without ACKs, the server can't confirm we received its data
                // and stays amplification-limited.
                for (&self.packetHandler().*.recv) |*recv_tracker| {
                    if (recv_tracker.largest_received != null) {
                        recv_tracker.ack_queued = true;
                    }
                }

                // Send a Handshake packet if we have Handshake keys, else padded Initial.
                // This gives the server more anti-amplification credit.
                if (self.pkt_num_spaces[1].crypto_seal != null) {
                    // Re-queue Initial crypto data too if still outstanding
                    self.queueCryptoRetransmission(.initial);
                    self.queueCryptoRetransmission(.handshake);
                } else {
                    self.queueCryptoRetransmission(.initial);
                }
                self.pending_frames.push(.{ .ping = {} });
                self.pathProbePending().* = 2;
                std.log.info("client anti-deadlock PTO fired (pto_count={d})", .{self.packetHandler().*.pto_count});
            }
        }

        // Keep-alive PING: send a PING after keep_alive_interval_ns of silence
        // to prevent the connection from hitting the idle timeout (RFC 9000 §10.1.2).
        if (self.transport_path == 0 and self.keep_alive_interval_ns > 0 and
            self.handshake_confirmed and !self.keep_alive_ping_sent)
        {
            const pto_ns = self.packetHandler().*.rtt_stats.pto();
            const interval = @max(self.keep_alive_interval_ns, pto_ns + @divTrunc(pto_ns, 2)); // floor at 1.5×PTO
            const silence = now - self.last_packet_received_time;
            if (silence >= interval) {
                self.pending_frames.push(.{ .ping = {} });
                self.keep_alive_ping_sent = true;
            }
        }

        // Check path validation timeouts
        {
            const pto_ns = self.packetHandler().*.rtt_stats.pto();
            for (&self.paths, 0..) |*path, id| {
                if (self.multipathNegotiated() and id != self.transport_path) continue;
                if (self.multipathNegotiated() and
                    (!self.native_paths.entries[id].opened or self.native_paths.entries[id].abandoned))
                    continue;
                if (!self.challenge_queued[id] and path.validator.needsRetry(now, pto_ns)) {
                    self.challenge_queued[id] = true;
                    self.challenge_retry_queued[id] = true;
                    if (self.multipathNegotiated()) {
                        self.path_control[id].push(.{ .path_challenge = path.validator.challenge_data });
                    } else {
                        self.pending_frames.push(.{ .path_challenge = path.validator.challenge_data });
                    }
                }
                if (!self.challenge_queued[id]) path.validator.checkTimeout(now, pto_ns);
                if (id == 1 and path.validator.state == .failed and self.nat_state != null) {
                    _ = try self.processNat(.cancel);
                    self.direct_ready = null;
                    self.nat_reply = null;
                }
            }
        }
    }

    /// Closes the connection with an application error, moving it to `closing`
    /// and queueing a CONNECTION_CLOSE for the next send (RFC 9000 §10.2).
    ///
    /// A connection already `closing`, `draining` or `terminated` is left
    /// alone, so the first close wins and a later one is not an error.
    /// `error_code` is in the application error space and `frame_type` is not
    /// sent; `now` stamps the start of the draining period.
    ///
    /// `reason` is not copied: `local_err` borrows the caller's slice for as
    /// long as the connection lives, so it must stay valid and unchanged for
    /// that long, or the caller copies it. The frame itself carries no reason.
    pub fn close(self: *Connection, error_code: u64, reason: []const u8, now: i64) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = now;
        self.local_err = .{
            .is_app = true,
            .code = error_code,
            .reason = reason,
        };
        self.pending_frames.push(.{ .connection_close = .{
            .error_code = error_code,
            .frame_type = 0,
            .is_app = true,
        } });
    }

    /// Validate peer transport parameters (RFC 9000 §7.3, §7.4, §18.2).
    fn validatePeerTransportParams(self: *Connection, peer_tp: *const transport_params.TransportParams, now: i64) !void {
        // Validate initial_source_connection_id is present (RFC 9000 §7.3)
        if (peer_tp.initial_source_connection_id == null) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "missing initial_source_connection_id", now);
            return error.TransportParameterError;
        }

        // Validate numeric ranges (RFC 9000 §7.4, §18.2)
        if (peer_tp.max_udp_payload_size < 1200) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "max_udp_payload_size below 1200", now);
            return error.TransportParameterError;
        }
        if (peer_tp.ack_delay_exponent > 20) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "ack_delay_exponent exceeds 20", now);
            return error.TransportParameterError;
        }
        if (peer_tp.max_ack_delay >= 16384) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "max_ack_delay exceeds 2^14", now);
            return error.TransportParameterError;
        }
        if (peer_tp.active_connection_id_limit < 2) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "active_connection_id_limit below 2", now);
            return error.TransportParameterError;
        }

        // RFC 9368 §3 and §4 put both checks below on client-sent Version
        // Information alone: a server may omit its chosen version while
        // withdrawing support for it.
        if (self.is_server) {
            if (peer_tp.version_info_chosen) |chosen| {
                // Membership, not the bounded prefix: the Chosen Version has
                // to be found anywhere in the list the peer sent, including
                // past the eight `hasAvailableVersion` reads — a client that
                // greases ahead of the version it chose has named it.
                if (!peer_tp.chosenInAvailableVersions()) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "chosen version absent from available versions", now);
                    return error.TransportParameterError;
                }
                // RFC 9368 §4: "the server MUST validate that the client's
                // Chosen Version matches the version in use for the
                // connection. If the two differ, the server MUST close the
                // connection with a version negotiation error." The version in
                // use is the one the long header of the packets carrying
                // these parameters carried — the client's first flight, which
                // §1.2 defines as the Chosen Version. It is
                // `original_version` and not `version`: a compatible
                // negotiation moves the connection on, and `version` already
                // reads as the negotiated version by the time these
                // parameters arrive, while the client's first flight has not
                // moved.
                //
                // The tag is this function's own, in inferred error sets all
                // the way up: `advanceHandshake` and `recv` infer theirs, and
                // both mappers (`handleDatagram`, `ConnectionManager.route`)
                // test for one tag rather than switch over the set, so nothing
                // has to learn a new error. The close is what the peer is
                // told; the tag only stops the handshake, as every other
                // refusal in this function does.
                if (chosen != self.packer.original_version) {
                    self.closeWithTransportError(@intFromEnum(TransportError.version_negotiation_error), @intFromEnum(FrameType.crypto), "chosen version is not the version this connection is on", now);
                    return error.VersionNegotiationError;
                }
            }
        }

        // Client-side: validate ODCID and retry_scid transport params (RFC 9000 §7.3)
        if (!self.is_server) {
            // original_destination_connection_id must match the DCID we initially sent
            if (peer_tp.original_destination_connection_id) |peer_odcid| {
                if (!std.mem.eql(u8, peer_odcid, self.odcid_buf[0..self.odcid_len])) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "ODCID mismatch", now);
                    return error.TransportParameterError;
                }
            } else {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "server must send ODCID", now);
                return error.TransportParameterError;
            }

            // If Retry was used, retry_source_connection_id must be present
            // If not, it must be absent
            if (self.retry_received) {
                if (peer_tp.retry_source_connection_id == null) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "retry_scid missing after Retry", now);
                    return error.TransportParameterError;
                }
            } else {
                if (peer_tp.retry_source_connection_id != null) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "retry_scid present without Retry", now);
                    return error.TransportParameterError;
                }
            }
        }

        // Server-side: reject server-only params from client (RFC 9000 §18.2)
        if (self.is_server) {
            if (peer_tp.original_destination_connection_id != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent original_destination_connection_id", now);
                return error.TransportParameterError;
            }
            if (peer_tp.preferred_address != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent preferred_address", now);
                return error.TransportParameterError;
            }
            if (peer_tp.retry_source_connection_id != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent retry_source_connection_id", now);
                return error.TransportParameterError;
            }
            if (peer_tp.stateless_reset_token != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent stateless_reset_token", now);
                return error.TransportParameterError;
            }
        }

        // RFC 9000 §7.4.1: if 0-RTT was used, validate that server's new
        // transport params are not less than the remembered values.
        if (self.remembered_params != null and self.early_data_seal != null) {
            const rp = self.remembered_params.?;
            if (peer_tp.initial_max_data < rp.initial_max_data or
                peer_tp.initial_max_stream_data_bidi_local < rp.initial_max_stream_data_bidi_local or
                peer_tp.initial_max_stream_data_bidi_remote < rp.initial_max_stream_data_bidi_remote or
                peer_tp.initial_max_stream_data_uni < rp.initial_max_stream_data_uni or
                peer_tp.initial_max_streams_bidi < rp.initial_max_streams_bidi or
                peer_tp.initial_max_streams_uni < rp.initial_max_streams_uni or
                peer_tp.active_connection_id_limit < rp.active_connection_id_limit)
            {
                self.closeWithTransportError(
                    @intFromEnum(TransportError.transport_parameter_error),
                    0,
                    "0-RTT transport params reduced",
                    now,
                );
                return error.TransportParameterError;
            }
            // Clear remembered params after successful validation
            self.remembered_params = null;
        }
    }

    /// Closes the connection with a transport error and the frame type that
    /// provoked it, moving it to `closing` and queueing a CONNECTION_CLOSE for
    /// the next send (RFC 9000 §10.2). A connection already `closing`,
    /// `draining` or `terminated` is left alone, as with `close`.
    ///
    /// `reason` is not copied: `local_err` borrows the caller's slice for as
    /// long as the connection lives. The frame itself carries no reason, only
    /// the code and the frame type.
    pub fn closeWithTransportError(
        self: *Connection,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now: i64,
    ) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = now;
        self.local_err = .{
            .is_app = false,
            .code = error_code,
            .reason = reason,
        };
        self.pending_frames.push(.{ .connection_close = .{
            .error_code = error_code,
            .frame_type = frame_type,
            .is_app = false,
        } });
    }

    /// Open a new bidirectional stream.
    pub fn openStream(self: *Connection) !*stream_mod.Stream {
        return self.streams.openBidiStream();
    }

    /// Open a new unidirectional stream.
    pub fn openUniStream(self: *Connection) !*stream_mod.SendStream {
        return self.streams.openUniStream();
    }

    /// Send a QUIC DATAGRAM frame (RFC 9221).
    /// Returns error.DatagramsNotEnabled, error.DatagramTooLarge (permanent — reduce payload),
    /// or error.DatagramQueueFull (transient — retry after sending).
    pub fn sendDatagram(self: *Connection, data: []const u8, now: i64) !void {
        if (!self.datagrams_enabled) return error.DatagramsNotEnabled;
        if (data.len > DatagramQueue.MAX_DATAGRAM_SIZE) return error.DatagramTooLarge;
        if (self.datagram_send_queue.isFull()) return error.DatagramQueueFull;
        _ = self.datagram_send_queue.push(data, now);
    }

    /// Bytes the application can still write, across every stream, before the
    /// peer's MAX_DATA is spent. Bytes written but not yet sent count as spent:
    /// they spend it on the way out. Advisory — a write past it is not refused,
    /// it waits in the send buffer for credit.
    pub fn sendCapacity(self: *const Connection) u64 {
        return self.conn_flow_ctrl.base.send_window -| self.streams.committedSendBytes();
    }

    /// `sendCapacity` narrowed by the stream's own MAX_STREAM_DATA. Null for a
    /// stream we cannot send on; zero once it is reset or its FIN is queued.
    pub fn streamSendCapacity(self: *const Connection, stream_id: u64) ?u64 {
        const ss = self.streams.getSendStream(stream_id) orelse return null;
        return @min(ss.sendCredit(), self.sendCapacity());
    }

    /// Bytes written to the stream but not yet sent, whatever holds them back.
    /// Null for a stream we cannot send on.
    pub fn streamBufferedBytes(self: *const Connection, stream_id: u64) ?u64 {
        const ss = self.streams.getSendStream(stream_id) orelse return null;
        if (ss.reset_err != null) return 0;
        return ss.write_offset -| ss.send_offset;
    }

    /// Whether the datagram send queue is full, which is a reason to send
    /// before queueing another datagram rather than an error.
    ///
    pub fn isDatagramSendQueueFull(self: *const Connection) bool {
        return self.datagram_send_queue.isFull();
    }

    /// Returns the number of datagrams currently in the send queue.
    pub fn datagramSendQueueLen(self: *const Connection) usize {
        return self.datagram_send_queue.queueLen();
    }

    /// Returns the maximum payload size for a DATAGRAM frame, accounting for
    /// short header overhead, AEAD tag, and frame encoding. Returns null if
    /// datagrams are not enabled.
    pub fn maxDatagramPayloadSize(self: *const Connection) ?usize {
        if (!self.datagrams_enabled) return null;
        const peer_max = if (self.peer_params) |pp| pp.max_datagram_frame_size orelse return null else return null;
        // Short header: 1 (flags) + dcid_len + 4 (max pkt num) + 16 (AEAD tag)
        const header_overhead = 1 + @as(usize, self.dcid_len) + 4 + 16;
        const max_pkt = self.packer.max_packet_size;
        if (header_overhead >= max_pkt) return null;
        const payload_budget = max_pkt - header_overhead;
        // DATAGRAM_WITH_LENGTH frame: 1 (type) + varint(len) + payload
        // Use 2-byte varint for length (covers up to 16383)
        const frame_overhead: usize = 1 + 2;
        if (frame_overhead >= payload_budget) return null;
        const from_pkt = payload_budget - frame_overhead;
        // Peer's max_datagram_frame_size includes type + length + payload
        const from_peer = if (peer_max > frame_overhead) peer_max - frame_overhead else return null;
        const max_payload = @min(from_pkt, from_peer);
        return @min(max_payload, DatagramQueue.MAX_DATAGRAM_SIZE);
    }

    /// Receive a QUIC DATAGRAM frame (RFC 9221).
    /// Returns the number of bytes written to buf, or null if no datagram available.
    /// The ALPN this connection settled on, or "" before the handshake
    /// has got that far. A server that advertises several — two MoQ drafts,
    /// say — needs this to know which one it is speaking.
    pub fn negotiatedAlpn(self: *const Connection) []const u8 {
        const hs = self.tls13_hs orelse return "";
        return hs.negotiatedAlpn();
    }

    /// Server: the client's verified certificate (DER leaf); see
    /// `Tls13Handshake.peerCertificate`.
    pub fn peerCertificate(self: *const Connection) ?[]const u8 {
        const hs = self.tls13_hs orelse return null;
        return hs.peerCertificate();
    }

    /// Server: the client-auth policy the handshake ran under, from the
    /// certificate entry SNI selected; null when none asked for a certificate.
    pub fn clientAuth(self: *const Connection) ?*const tls13.ClientAuth {
        const hs = self.tls13_hs orelse return null;
        return hs.client_auth;
    }

    /// The next datagram at `now`, skipping anything older than the configured
    /// max age. `now` is the caller's instant, so the clock that stamped the
    /// entry on arrival is the one that ages it on the way out.
    pub fn recvDatagram(self: *Connection, buf: []u8, now: i64) ?usize {
        return self.datagram_recv_queue.popSkipExpired(buf, now);
    }

    /// Zero-copy datagram receive: returns a slice into the internal ring buffer.
    /// Caller MUST call consumeDatagram() after processing the data.
    pub fn peekDatagram(self: *Connection, now: i64) ?[]const u8 {
        return self.datagram_recv_queue.peekDataSkipExpired(now);
    }

    /// Advance past the datagram returned by peekDatagram().
    pub fn consumeDatagram(self: *Connection) void {
        self.datagram_recv_queue.consume();
    }

    /// Set max age for incoming datagrams (milliseconds). null = no limit.
    pub fn setIncomingDatagramMaxAge(self: *Connection, max_age_ms: ?u64) void {
        self.datagram_recv_queue.max_age_ns = if (max_age_ms) |ms| @as(i64, @intCast(ms)) * 1_000_000 else null;
    }

    /// Set max age for outgoing datagrams (milliseconds). null = no limit.
    pub fn setOutgoingDatagramMaxAge(self: *Connection, max_age_ms: ?u64) void {
        self.datagram_send_queue.max_age_ns = if (max_age_ms) |ms| @as(i64, @intCast(ms)) * 1_000_000 else null;
    }

    /// Set high water mark for incoming datagram queue (count).
    pub fn setIncomingDatagramHighWaterMark(self: *Connection, count: usize) void {
        self.datagram_recv_queue.high_water_mark = count;
    }

    /// Set high water mark for outgoing datagram queue (count).
    pub fn setOutgoingDatagramHighWaterMark(self: *Connection, count: usize) void {
        self.datagram_send_queue.high_water_mark = count;
    }

    /// Whether the connection has reached `terminated`, which is final: no
    /// further call moves it and nothing more is sent or accepted.
    ///
    /// Not the same as closing — a `closing` connection is still sending its
    /// CONNECTION_CLOSE. Read `state` for the position itself.
    pub fn isClosed(self: *const Connection) bool {
        return self.state == .terminated;
    }

    /// Whether the peer's close was acknowledged and this side is running out
    /// its three-PTO draining period. It sends nothing and accepts nothing in
    /// this state, and `nextTimeoutNs` answers the deadline that ends it.
    pub fn isDraining(self: *const Connection) bool {
        return self.state == .draining;
    }

    /// Whether the handshake is confirmed and application data may flow, which
    /// is stricter than `state != .first_flight`: a connection in `handshake`
    /// is past the Initial but has not yet confirmed.
    pub fn isEstablished(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Compute the next timeout deadline (nanosecond timestamp) without side effects.
    /// Returns null if the connection is terminated and needs no timer.
    /// `now` is the caller's instant: the pacer's next-send deadline is
    /// measured from it, so this reads no clock of its own.
    pub fn nextTimeoutNs(self: *const Connection, now: i64) ?i64 {
        if (self.state == .terminated) return null;

        var earliest: ?i64 = null;
        if (self.key_update) |*keys| {
            if (keys.prev_open_expires) |deadline| earliest = deadline;
        }
        if (self.nat_state) |*state| {
            if (state.deadline()) |deadline|
                earliest = if (earliest) |old| @min(old, deadline) else deadline;
        }
        if (self.path1_transport) |other| {
            if (self.native_paths.entries[1].opened and !self.native_paths.entries[1].abandoned) {
                for ([_]?i64{
                    other.handler.sent[2].loss_time,
                    other.handler.spacePtoDeadline(other.handler.sent[2], 2),
                    other.handler.recv[2].ack_alarm,
                }) |deadline| {
                    if (deadline) |at| earliest = if (earliest) |old| @min(old, at) else at;
                }
                if (other.pacer.bandwidth_shifted > 0) {
                    const at = now + other.pacer.delayAt(now);
                    earliest = if (earliest) |old| @min(old, at) else at;
                }
            }
        }
        for (self.paths, 0..) |path, id| {
            if (path.validator.state != .pending) continue;
            if (self.challenge_queued[id]) continue;
            if (self.multipathNegotiated() and
                (!self.native_paths.entries[id].opened or self.native_paths.entries[id].abandoned))
                continue;
            const handler = if (id == 1 and self.multipathNegotiated())
                &self.path1_transport.?.handler
            else
                &self.pkt_handler;
            const at = path.validator.challenge_sent_time + handler.rtt_stats.pto() + 1;
            earliest = if (earliest) |old| @min(old, at) else at;
        }

        // Closing/draining: 3×PTO from closing_start_time
        if (self.state == .closing or self.state == .draining) {
            if (self.closing_start_time > 0) {
                const pto_ns = self.maxActivePathPto();
                const deadline = self.closing_start_time + 3 * pto_ns;
                return deadline;
            }
            return null;
        }

        // Idle timeout — use base PTO (no backoff), matching quic-go/quiche
        {
            const base_pto = self.maxActivePathPto();
            const effective_idle = @max(self.idle_timeout_ns, 3 * base_pto);
            const last_activity = if (!self.handshake_confirmed)
                @max(self.last_packet_received_time, self.last_packet_sent_time)
            else
                self.last_packet_received_time;
            const idle_deadline = last_activity + effective_idle;
            if (earliest == null or idle_deadline < earliest.?) {
                earliest = idle_deadline;
            }
        }

        // Keep-alive deadline
        if (self.keep_alive_interval_ns > 0 and self.handshake_confirmed and !self.keep_alive_ping_sent) {
            const pto_ns = self.maxActivePathPto();
            const interval = @max(self.keep_alive_interval_ns, pto_ns + @divTrunc(pto_ns, 2));
            const ka_deadline = self.last_packet_received_time + interval;
            if (earliest == null or ka_deadline < earliest.?) {
                earliest = ka_deadline;
            }
        }

        // Loss detection timer — must fire immediately, no clamping
        for (self.packetHandler().*.sent) |tracker| {
            if (tracker.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
            }
        }

        // PTO timer — delegates to spacePtoDeadline which correctly handles
        // handshake spaces per RFC 9002 §6.2.2.1.
        // Clamp past deadlines to avoid spinning on stale handshake spaces
        // (client waiting for HANDSHAKE_DONE after TLS completion).
        {
            var pto_earliest: ?i64 = null;
            for (self.packetHandler().*.sent, 0..) |tracker, idx| {
                if (tracker.loss_time != null) continue; // handled above
                const deadline = self.packetHandler().*.spacePtoDeadline(tracker, idx) orelse continue;
                if (pto_earliest == null or deadline < pto_earliest.?) {
                    pto_earliest = deadline;
                }
            }
            if (pto_earliest) |pto_deadline| {
                if (earliest == null or pto_deadline < earliest.?) {
                    earliest = pto_deadline;
                }
            }
        }

        // No pending data check needed — spacePtoDeadline handles this via
        // last_ack_eliciting_sent_time for handshake spaces. For application space,
        // the loss detection timer + send loop handles retransmissions.

        // ACK alarm: if we have pending ACKs to send (delayed ACK timer),
        // include the alarm deadline so the event loop wakes up in time (RFC 9000 §13.2.1).
        for (self.packetHandler().*.recv) |tracker| {
            if (tracker.ack_alarm) |alarm| {
                if (earliest == null or alarm < earliest.?) {
                    earliest = alarm;
                }
            }
        }

        // Pacer: if the pacer has bandwidth set (active transfer), include its
        // next-send time so the event loop wakes up promptly to send more data.
        if (self.pathPacer().*.bandwidth_shifted > 0 and self.state == .connected) {
            const delay = self.pathPacer().*.delayAt(now);
            if (delay > 0) {
                const pacer_deadline = now + delay;
                if (earliest == null or pacer_deadline < earliest.?) {
                    earliest = pacer_deadline;
                }
            }
        }

        return earliest;
    }

    /// Drop Initial and Handshake encryption keys (RFC 9001 §4.9).
    /// Called automatically for server in advanceHandshake, and for client
    /// after the Handshake Finished has been sent. Applications should not
    /// need to call this directly.
    /// RFC 9001 §4.1.2: At the client, the handshake is considered confirmed
    /// when it receives an acknowledgment for a 1-RTT packet.
    fn maybeConfirmHandshake(self: *Connection, enc_level: ack_handler.EncLevel, acked_count: usize) void {
        if (!self.is_server and !self.handshake_confirmed and enc_level == .application and acked_count > 0) {
            self.handshake_confirmed = true;
            // RFC 9001 §4.9.2: Do NOT drop Handshake keys here — they must be kept
            // until the client's Handshake packets (Finished) have been acknowledged.
            // In 0-RTT scenarios, the server may send 1-RTT ACKs (for 0-RTT data)
            // before receiving the client's Handshake Finished. Dropping keys here
            // would prevent the client from retransmitting the Finished if lost.
            // The auto-clear in emitPackets() handles key discard safely.
            std.log.info("handshake confirmed via 1-RTT ACK", .{});
        }
    }

    /// Drops the Initial and Handshake keys and the sent-packet state for both
    /// spaces (RFC 9001 §4.9), so nothing at those levels can be decrypted or
    /// sent afterwards and no PTO fires for them.
    ///
    /// Only safe once the peer's Handshake packets have been acknowledged: a
    /// peer still retransmitting a Finished needs the Handshake seal to
    /// resend it, and a handshake packet that arrives after this is dropped
    /// rather than answered. The handshake itself does this at the right
    /// moment, so a caller driving this state machine does not need to; the
    /// call is idempotent in effect, since dropping absent keys changes
    /// nothing.
    pub fn dropHandshakeKeys(self: *Connection) void {
        self.pkt_num_spaces[0].crypto_open = null;
        self.pkt_num_spaces[0].crypto_seal = null;
        self.pkt_num_spaces[1].crypto_open = null;
        self.pkt_num_spaces[1].crypto_seal = null;
        // Drop Initial and Handshake packet number spaces so PTO won't fire for them
        self.packetHandler().*.dropSpace(.initial);
        self.packetHandler().*.dropSpace(.handshake);
    }

    /// Initiate a key update (RFC 9001 §6).
    /// The next 1-RTT packet will use the new key phase.
    /// Returns true if the key update was initiated, false if not possible
    /// (e.g., no key update manager, or update already in progress).
    pub fn initiateKeyUpdate(self: *Connection, now: i64) bool {
        if (self.key_update) |*ku| {
            ku.maybeDropPrevKeys(now);
            if (ku.canUpdate()) {
                const pto_ns = self.maxActivePathPto();
                ku.rollKeys(now, pto_ns);
                self.packer.key_phase = ku.key_phase;
                return true;
            }
        }
        return false;
    }

    /// Manually queue a keep-alive PING frame.
    /// No-op if the connection is not yet fully established.
    pub fn sendKeepAlive(self: *Connection) void {
        if (self.state != .connected or !self.handshake_confirmed) return;
        self.pending_frames.push(.{ .ping = {} });
    }

    /// Connection-level statistics (matches browser WebTransport.getStats()).
    ///
    /// A snapshot taken by `getStats` and owned by the caller: it borrows
    /// nothing and stays readable after `deinit`. Counters are cumulative from
    /// construction and are not reset by a key change or a migration.
    pub const Stats = struct {
        /// Bytes of QUIC packet data written to the socket, summed over every
        /// path.
        bytes_sent: u64,
        /// Bytes of QUIC packet data received, summed over every path and
        /// counted once per datagram rather than per coalesced packet.
        bytes_received: u64,
        /// Packets `sendAt` emitted, every epoch.
        packets_sent: u64,
        /// Packets accepted, every epoch.
        packets_received: u64,
        /// Packets loss detection declared lost, every epoch.
        packets_lost: u64,
        /// Streams this side opened, bidirectional and unidirectional added
        /// together, derived from the stream-id counters rather than counted.
        num_outgoing_streams_created: u64,
        /// Streams the peer opened that this side has seen, open and consumed
        /// added together.
        num_incoming_streams_created: u64,
        /// Smoothed round-trip time in nanoseconds, exactly as the estimator
        /// holds it: 0 until the first sample, not the RFC initial RTT.
        smoothed_rtt_ns: i64,
        /// Mean deviation around `smoothed_rtt_ns`, in nanoseconds; 0 until
        /// the first sample.
        rtt_variation_ns: i64,
        /// Smallest round-trip time seen, in nanoseconds; 0 until the first
        /// sample.
        min_rtt_ns: i64,
        /// Received DATAGRAM frames dropped on arrival.
        datagrams_dropped_incoming: u64,
        /// Packets carrying a datagram that were declared lost.
        datagrams_lost_outgoing: u64,
    };

    /// A snapshot of `Stats` taken now. Allocates nothing, borrows nothing and
    /// changes no connection state, so it is safe from any of the ingress,
    /// egress or timer paths. The stream counts are derived from the stream-id
    /// counters rather than counted as streams are opened, so a stream that
    /// was opened and fully reclaimed still counts.
    pub fn getStats(self: *const Connection) Stats {
        // Aggregate bytes across all paths
        var bytes_sent: u64 = 0;
        var bytes_received: u64 = 0;
        for (&self.paths) |*p| {
            bytes_sent += p.bytes_sent;
            bytes_received += p.bytes_received;
        }

        // Stream counts: derive from StreamsMap
        const is_server = self.is_server;
        const bidi_base: u64 = if (is_server) 1 else 0;
        const uni_base: u64 = if (is_server) 3 else 2;
        const outgoing_bidi = (self.streams.next_bidi_stream_id - bidi_base) / 4;
        const outgoing_uni = (self.streams.next_uni_stream_id - uni_base) / 4;
        // Incoming = peer-initiated streams we've seen (open + consumed)
        const incoming_bidi = self.streams.open_bidi_streams + self.streams.consumed_bidi_streams;
        const incoming_uni = self.streams.open_uni_streams + self.streams.consumed_uni_streams;

        return .{
            .bytes_sent = bytes_sent,
            .bytes_received = bytes_received,
            .packets_sent = self.total_packets_sent,
            .packets_received = self.total_packets_received,
            .packets_lost = self.total_packets_lost,
            .num_outgoing_streams_created = outgoing_bidi + outgoing_uni,
            .num_incoming_streams_created = incoming_bidi + incoming_uni,
            .smoothed_rtt_ns = self.packetHandler().*.rtt_stats.smoothed_rtt,
            .rtt_variation_ns = self.packetHandler().*.rtt_stats.rtt_var,
            .min_rtt_ns = self.packetHandler().*.rtt_stats.min_rtt,
            .datagrams_dropped_incoming = self.datagrams_dropped_incoming,
            .datagrams_lost_outgoing = self.datagrams_lost_outgoing,
        };
    }

    /// Return the ECN codepoint to mark on outgoing packets.
    /// Returns ECT(0) if ECN validation allows it, else Not-ECT.
    pub fn getEcnMark(self: *const Connection) u2 {
        return if (self.pathECN().*.shouldMark()) ECN_ECT0 else ECN_NOT_ECT;
    }

    /// Moves off a DCID the peer retired, onto the lowest CID it still allows.
    fn replaceRetiredDcid(self: *Connection) void {
        var best: ?*ConnectionIdEntry = null;
        for (&self.peer_cid_pool.entries) |*e| {
            if (!e.occupied or e.seq_num < self.active_cid_seq) continue;
            if (best == null or e.seq_num < best.?.seq_num) best = e;
        }
        const entry = best orelse return; // replacement not here yet
        entry.in_use = true;
        self.useDcid(entry);
        std.log.info("updated DCID to seq={d}, the previous one was retired", .{entry.seq_num});
    }

    fn useDcid(self: *Connection, entry: *const ConnectionIdEntry) void {
        const cid = entry.getCid();
        self.packer.updateDcid(cid);
        self.dcid_len = @intCast(cid.len);
        @memcpy(self.dcid[0..cid.len], cid);
        self.dcid_seq = entry.seq_num;
    }

    /// Initiate a client-side connection migration (RFC 9000 §9).
    ///
    /// Consumes a fresh destination CID from the peer pool and queues a
    /// PATH_CHALLENGE on it. The caller is responsible for actually sending
    /// from a new local address; nothing here opens one.
    ///
    /// False when the peer issued no unused CID, which is a fact about the
    /// peer's `active_connection_id_limit` rather than a failure: the caller
    /// can ask again once the peer has issued one.
    ///
    pub fn initiateClientMigration(self: *Connection) bool {
        const entry = self.peer_cid_pool.consumeUnused() orelse return false;
        self.useDcid(entry);
        std.log.info("client migration: switched to new DCID seq={d}", .{entry.seq_num});
        return true;
    }

    /// Return the peer address on the active path.
    /// This may change after connection migration or preferred address selection.
    pub fn peerAddress(self: *const Connection) *const address.Address {
        return &self.paths[self.active_path_idx].peer_addr;
    }

    /// Return the local address on the active path.
    pub fn localAddress(self: *const Connection) *const address.Address {
        return &self.paths[self.active_path_idx].local_addr;
    }

    /// The NEW_TOKEN the peer sent, for reuse on a later connection, or `null`
    /// when none arrived.
    ///
    /// Borrowed from the connection's inline storage, so it stays valid until
    /// `deinit` and must be copied before then to outlive the connection.
    /// Passing it to a later `connectInto` is what makes the next connection's
    /// address validation cheap, and only a token sealed under the key the
    /// receiving side validates with is accepted — see
    /// `ConnectionConfig.token_key`.
    pub fn getNewToken(self: *const Connection) ?[]const u8 {
        if (self.new_token_len == 0) return null;
        return self.new_token_buf[0..self.new_token_len];
    }

    /// Enter draining if `datagram` ends in a reset token the peer issued for
    /// a connection ID it has not retired (RFC 9000 §10.3.1). Call only for a
    /// datagram whose first packet could not be decrypted. Sends nothing;
    /// the connection terminates after the draining period, with
    /// `received_stateless_reset` set. Returns whether it was a reset.
    pub fn handleStatelessReset(self: *Connection, datagram: []const u8, now: i64) bool {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return false;
        if (!self.matchesStatelessReset(datagram)) return false;
        std.log.info("stateless reset received, draining", .{});
        self.state = .draining;
        self.closing_start_time = now;
        self.received_stateless_reset = true;
        self.local_err = .{ .is_app = false, .code = 0, .reason = "stateless reset" };
        return true;
    }

    /// Whether `data` ends in a stateless reset token the peer issued for a
    /// connection id it has not retired (RFC 9000 §10.3).
    ///
    /// Every occupied entry of `peer_cid_pool` is tested against the last 16
    /// bytes of `data`, so a datagram too short to hold one is never a reset.
    /// This compares only: it does not change `state` and does not drain, which
    /// is what `handleStatelessReset` does once this says yes. `data` is the
    /// whole datagram, not one packet of it.
    pub fn matchesStatelessReset(self: *const Connection, data: []const u8) bool {
        var tokens: [2 * ConnectionIdPool.MAX_POOL_SIZE][stateless_reset.TOKEN_LEN]u8 = undefined;
        var count: usize = 0;
        for (0..2) |id| {
            for (self.peerPathCidEntries(@intCast(id))) |entry| {
                if (entry.occupied) {
                    tokens[count] = entry.stateless_reset_token;
                    count += 1;
                }
            }
        }
        if (count == 0) return false;
        return stateless_reset.isStatelessReset(data, tokens[0..count]);
    }

    fn setInitialDCID(self: *Connection, cid: []const u8) void {
        self.dcid_len = @intCast(cid.len);
        @memcpy(self.dcid[0..cid.len], cid);
        // Update packer
        self.packer.dcid = self.dcid[0..self.dcid_len];
    }

    fn epochToEncLevel(epoch: packet.Epoch) ack_handler.EncLevel {
        return switch (epoch) {
            .initial => .initial,
            .zero_rtt, .handshake => .handshake,
            .application => .application,
        };
    }

    /// Process a raw UDP datagram containing one or more coalesced QUIC packets.
    /// Handles header parsing, coalesced packet boundaries (RFC 9000 §12.2),
    /// and dispatches each packet through `recv`.
    ///
    /// The walk ends at the first byte without the fixed bit, at a Version
    /// Negotiation packet, and at the first packet `recv` refuses — a refusal
    /// on the first packet of the datagram also runs the stateless-reset check,
    /// so a reset that could not be decrypted still drains the connection.
    /// `info` is this datagram's addresses and ECN codepoint; its
    /// `datagram_size` is counted against the amplification ledger once, on
    /// the first packet, whatever the caller put there.
    ///
    /// Nothing is returned: the outcome is `state`, `local_err` and whatever
    /// the frames carried. `bytes` is decrypted in place — header protection is
    /// removed through it — so it no longer holds the wire bytes and a caller
    /// that still wants those must copy first. Nothing borrowed from it is kept
    /// beyond the next packet: `local_err.reason` is the one value that
    /// borrows this buffer, and only until then.
    pub fn handleDatagram(
        self: *Connection,
        bytes: []u8,
        info: RecvInfo,
        now: i64,
        random: std.Random,
    ) void {
        var fbs = io.fixedBufferStream(bytes);
        var first_packet = true;
        while (fbs.seek < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            // If not set, remaining bytes are padding — stop parsing.
            if (bytes[fbs.seek] & 0x40 == 0) break;

            const pkt_start = fbs.seek;
            var header = packet.Header.parse(&fbs, self.scid_len) catch break;
            // A Version Negotiation packet is a whole datagram, not a packet
            // inside one, and it is the one type whose header has no Length
            // field for this loop to step by. Hand it to recv — which is where
            // a client acts on one — and stop, rather than reading a length
            // this packet never had.
            if (header.packet_type == .version_negotiation) {
                // A client acts on one here; a server has nothing to do with
                // it. Whatever `recv` answers, the walk ends here, because the
                // packet is the whole datagram and there is no length to step
                // by. A refusal is reported rather than dropped: it says the
                // packet was not one this end could read.
                self.recv(&header, &fbs, info, now, random) catch |err| {
                    std.log.debug("version negotiation packet refused: {t}", .{err});
                };
                break;
            }
            const full_size = fbs.seek - pkt_start + header.remainder_len;

            // Only count datagram_size for the first packet to avoid
            // double-counting in amplification limit calculations.
            var pkt_info = info;
            if (!first_packet) pkt_info.datagram_size = 0;
            first_packet = false;
            self.recv(&header, &fbs, pkt_info, now, random) catch |err| {
                if (err == error.UndecryptablePacket and pkt_start == 0) {
                    _ = self.handleStatelessReset(bytes, now);
                }
                break;
            };

            const next_pos = pkt_start + full_size;
            if (fbs.seek < next_pos) fbs.seek = next_pos;
        }
    }
};

/// Fills `buf` with random bytes, for a connection id of the size the caller
/// wants.
///
/// `buf.len` is the id length, 0 to `packet.CONNECTION_ID_MAX_SIZE`, and the
/// whole slice is overwritten. `random` is the caller's generator and this call
/// advances it, so two ids from one engine differ and a seeded engine gives
/// the same ids twice — which is what lets a test pin them. Nothing is
/// allocated and nothing is retained.
pub fn generateConnectionId(buf: []u8, random: std.Random) void {
    random.bytes(buf);
}

/// The connection's clock in the unit the TLS handshake reads it in. `now` is
/// nanoseconds; `Tls13Handshake.step` wants seconds. One conversion, in one
/// place — a factor of a billion would stretch every session ticket lifetime
/// by a billion and expire none of them.
///
/// The base is the connection's own clock, not the epoch: this core reads no
/// clock of its own, and `now` is the only instant in scope. What TLS does
/// with the value is a difference against another value stamped from the same
/// clock — ticket age against the ticket's creation time — so the arithmetic
/// holds whatever the base is. It does not hold an epoch second: the instant
/// `serverSendTicket` encrypts into a ticket is this one's, and `tls13.zig`
/// documents that parameter as wall-clock.
fn tlsSeconds(now_ns: i64) i64 {
    return @divTrunc(now_ns, std.time.ns_per_s);
}

/// The QUIC version a client's first flight is built with.
///
/// `protocol.SUPPORTED_VERSIONS[0]`, unless the client holds a session ticket
/// from a later version it can speak and `enable_v2` lets it start there: a
/// ticket belongs to one QUIC version and RFC 9369 §5 has a client use it only
/// on a connection of that version, so a version-2 ticket is what makes a
/// client start on version 2. Without version 2 the ticket is left behind
/// rather than offered.
fn firstFlightVersion(config: ConnectionConfig, tls_config: ?tls13.TlsConfig) u32 {
    const default = protocol.SUPPORTED_VERSIONS[0];
    if (!config.enable_v2) return default;
    const configuration = tls_config orelse return default;
    const ticket = tls13.Resumption.clientTicket(configuration.resumption) orelse return default;
    if (ticket.quic_version == default) return default;
    if (!protocol.isSupportedVersion(ticket.quic_version)) return default;
    return ticket.quic_version;
}

/// Creates a client connection in `conn`, storage the caller owns and must
/// keep at that address for the connection's whole life — see `local_params`.
/// On success it is ready to produce an Initial packet; on failure everything
/// it built is released and the storage is torn down, so a caller does not
/// call `deinit` for a construction that returned an error.
///
/// If `tls_config` is provided, a real TLS 1.3 ClientHello is generated.
/// Otherwise, transport parameters are queued as a placeholder.
///
/// `tls_config` is copied in, so the chain, the key, the ALPN strings and the
/// resumption ticket it points at must outlive the connection. `server_name`
/// is copied into that copy and `initial_token` into `conn.retry_token_buf`,
/// so neither has to outlive this call — an `initial_token` longer than that
/// buffer is truncated to what fits rather than refused.
///
/// `config` borrows nothing: it is taken by value and holds only integers,
/// inline arrays and inline structs, and what the connection keeps of it is
/// copied, so the caller may release whatever it built the config from as soon
/// as this returns. Three of its fields have no effect on a client —
/// `preferred_address` and `quic_lb` are server-side, and `static_reset_key`
/// is ignored because a client issues no stateless resets, so a key is drawn
/// from `random` instead.
///
/// `allocator` is stored rather than borrowed-and-released: it is what `deinit`
/// frees into, so it must stay valid until after that one call.
///
/// Building in place is what the transport parameters force, not a preference:
/// `local_params.initial_source_connection_id` borrows the connection's own
/// `scid` buffer, and the handshake keeps a copy of those parameters and
/// encodes them again, so a connection built anywhere but its final address
/// would carry a source connection id read from a dead slot. Build it in
/// storage the caller owns and keeps at that address for the connection's
/// whole life.
pub fn connectInto(
    conn: *Connection,
    allocator: std.mem.Allocator,
    server_name: []const u8,
    config: ConnectionConfig,
    tls_config: ?tls13.TlsConfig,
    initial_token: ?[]const u8,
    now: i64,
    random: std.Random,
) !void {
    try validateNativeConfig(config);
    var scid: [8]u8 = undefined;
    var dcid: [8]u8 = undefined;
    generateConnectionId(&scid, random);
    generateConnectionId(&dcid, random);

    var local_params: transport_params.TransportParams = .{
        .max_idle_timeout = config.max_idle_timeout,
        .initial_max_data = config.initial_max_data,
        .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config.initial_max_streams_bidi,
        .initial_max_streams_uni = config.initial_max_streams_uni,
        .max_datagram_frame_size = config.max_datagram_frame_size,
        .initial_max_path_id = config.initial_max_path_id orelse
            if (config.max_remote_nat_traversal_addresses != null) @as(?u32, 1) else null,
        .max_remote_nat_traversal_addresses = config.max_remote_nat_traversal_addresses,
        .address_discovery_role = config.address_discovery_role,
        .min_ack_delay = 1000, // 1ms minimum ACK delay (draft-ietf-quic-ack-frequency)
        .initial_source_connection_id = &scid,
    };

    // The version this connection's first flight is built with. RFC 9369 §5 has
    // a client neither offer a ticket from another version's connection nor
    // resume one, so a ticket this client holds and can speak is what decides
    // it: a version-2 ticket is usable only on a connection that starts on
    // version 2, and a version-1 ticket only on one that starts on version 1.
    // A client that cannot speak a ticket's version leaves the ticket behind
    // and starts where it always did.
    const first_flight_version = firstFlightVersion(config, tls_config);
    if (config.enable_v2) {
        local_params.version_info_chosen = first_flight_version;
        local_params.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
        local_params.version_info_available_count = 2;
    }

    conn.* = Connection{
        .allocator = allocator,
        .version = first_flight_version,
        .is_server = false,
        .state = .first_flight,
        .creation_time = now,
        .last_packet_received_time = now,

        .pkt_handler = ack_handler.PacketHandler.init(allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(
            config.initial_max_data,
            6 * 1024 * 1024,
        ),
        .streams = stream_mod.StreamsMap.init(allocator, false),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),

        .local_params = local_params,
        .native_paths = .{},
    };

    // Every step below can allocate, and a failure there leaves a connection
    // the caller cannot `deinit` — this has not returned yet, so there is no
    // value yet. The guard is the one `acceptInto` explains: the literal
    // above initialises every member `deinit` frees, so a half-built
    // connection is safe to tear down.
    errdefer conn.deinit();
    conn.candidateAdmission = config.candidateAdmission;
    conn.supportedIPv6 = config.supportedIPv6;

    // Set connection IDs
    conn.scid_len = 8;
    @memcpy(conn.scid[0..8], &scid);
    conn.dcid_len = 8;
    @memcpy(conn.dcid[0..8], &dcid);

    // The transport parameters borrow this connection's own connection ids, so
    // they are bound here, after the ids are stored — not to the locals they
    // were drawn from. A parameter still pointing at this frame would be
    // encoded from a dead slot in the very first Initial.
    conn.local_params.initial_source_connection_id = conn.scid[0..conn.scid_len];

    // Save the initial DCID as the Original Destination CID (needed for Retry handling)
    conn.odcid_len = 8;
    @memcpy(conn.odcid_buf[0..8], &dcid);

    // Store DCID for v2 re-derivation and enable_v2 flag
    conn.initial_dcid_len = 8;
    @memcpy(conn.initial_dcid_buf[0..8], &dcid);
    conn.enable_v2 = config.enable_v2;
    conn.disable_pmtud = config.disable_pmtud;

    // Compute keep-alive interval: clamp to idle_timeout/2
    if (config.keep_alive_period > 0) {
        const ka_ns: i64 = @intCast(config.keep_alive_period * 1_000_000);
        conn.keep_alive_interval_ns = @min(ka_ns, @divTrunc(conn.idle_timeout_ns, 2));
    }
    conn.close_when_idle = config.close_when_idle;

    // Generate static reset key and register initial SCID with deterministic token
    random.bytes(&conn.static_reset_key);
    conn.local_cid_pool.registerInitialCid(
        conn.scid[0..conn.scid_len],
        conn.static_reset_key,
        random,
    );

    std.log.info("connection.connect: dcid={any}, scid={any}", .{ dcid, scid });

    // Derive Initial encryption keys from the DCID we chose
    try conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].setupInitial(
        &dcid,
        conn.version,
        false, // client-side
    );

    // Initialize packet packer
    conn.packer = packet_packer.PacketPacker.init(
        false,
        conn.scid[0..conn.scid_len],
        conn.dcid[0..conn.dcid_len],
        conn.version,
    );

    // If a token from NEW_TOKEN was provided, include it in the Initial packet
    if (initial_token) |token| {
        const len = @min(token.len, conn.retry_token_buf.len);
        @memcpy(conn.retry_token_buf[0..len], token[0..len]);
        conn.retry_token_len = @intCast(len);
        conn.packer.initial_token = conn.retry_token_buf[0..len];
        std.log.info("using NEW_TOKEN from previous connection ({d} bytes)", .{len});
    }

    // Configure stream limits
    conn.streams.setMaxIncomingStreams(
        config.initial_max_streams_bidi,
        config.initial_max_streams_uni,
    );
    conn.streams.local_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local;
    conn.streams.local_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
    conn.streams.local_max_stream_data_uni = config.initial_max_stream_data_uni;

    conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

    if (config.max_idle_timeout > 0) {
        conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
    }

    // Initialize TLS 1.3 handshake and generate ClientHello
    if (tls_config) |tc| {
        var tc_with_sni = tc;
        tc_with_sni.server_name = server_name;
        tc_with_sni.quic_version = conn.version;

        // RFC 9000 §7.4.1: remember transport params from session ticket for 0-RTT
        if (tc.session_ticket) |ticket| {
            conn.remembered_params = ticket.*;
        }

        const hs = try allocator.create(tls13.Tls13Handshake);
        // Until initialization succeeds, the connection does not own this allocation.
        // `conn.local_params`, not the `local_params` this frame drew the
        // ids from: the handshake keeps this copy and encodes it again later,
        // so a parameter still pointing at this frame would be encoded from a
        // dead slot after this has returned.
        tls13.Tls13Handshake.initClientInto(hs, tc_with_sni, conn.local_params, random) catch |err| {
            allocator.destroy(hs);
            return err;
        };
        conn.tls13_hs = hs;

        // Step the handshake to generate the ClientHello
        try conn.advanceHandshake(now, random);
    } else {
        // Legacy: queue transport parameters as placeholder crypto data
        var tp_buf: [transport_params.encode_len_max]u8 = undefined;
        var tp_fbs = io.fixedBufferStream(&tp_buf);
        try conn.local_params.encode(&tp_fbs, random);
        const tp_data = tp_fbs.buffered();
        const cs = conn.crypto_streams.getStream(0); // Initial level
        try cs.writeData(tp_data);
    }

    // Resize datagram queues if configured larger than default
    if (config.datagram_queue_capacity > DatagramQueue.DEFAULT_MAX_ITEMS) {
        try conn.datagram_recv_queue.resize(allocator, config.datagram_queue_capacity);
        try conn.datagram_send_queue.resize(allocator, config.datagram_queue_capacity);
    }

    return;
}

// --- Test inputs ---

/// The instant every test pretends it is. A fixed value rather than a clock
/// read: `test_now` is what makes `last_packet_received_time` and the
/// datagram queue's age arithmetic reproducible.
const test_now: i64 = 1_000 * std.time.ns_per_s;

/// A generator a test owns, seeded so the same run draws the same connection
/// IDs, reset keys and path challenges twice.
///
/// A `std.Random` borrows the engine that backs it, so the engine is the
/// local and `random()` is the borrow — the shape `addr_map.zig` uses for its
/// `ScriptedBits`. Nothing here reaches for the process CSPRNG.
const TestRandom = struct {
    prng: std.Random.DefaultPrng = .init(0x6a697474),

    fn random(self: *@This()) std.Random {
        return self.prng.random();
    }
};

test "connect: create client connection" {
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{}, null, null, test_now, rng.random());
    defer conn.deinit();

    try std.testing.expect(!conn.is_server);
    try std.testing.expectEqual(conn.state, .first_flight);
    try std.testing.expectEqual(conn.version, protocol.SUPPORTED_VERSIONS[0]);
    try std.testing.expectEqual(@as(u8, 8), conn.scid_len);
    try std.testing.expectEqual(@as(u8, 8), conn.dcid_len);

    // Should have crypto data queued (transport parameters)
    const cs = conn.crypto_streams.getStream(0);
    try std.testing.expect(cs.hasData());

    // Should have Initial encryption keys
    const seal = conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].crypto_seal;
    try std.testing.expect(seal != null);
}

/// The TLS configuration a client-only test needs: a client presents no
/// certificate and verifies none here, so the chain and the key are empty and
/// only the ClientHello this writes is exercised.
const client_test_tls: tls13.TlsConfig = .{
    .cert_chain_der = &.{},
    .private_key_bytes = &.{},
    .alpn = &.{},
};

test "connect: a client advertises its own source cid after the constructor frame is gone" {
    const allocator = std.testing.allocator;
    var rng = TestRandom{};

    // Two constructions out of one generator. The second reuses the frame the
    // first one ran in and overwrites what it left there, so a transport
    // parameter still pointing into that frame now reads the second
    // connection's source cid. The test can tell those two apart without
    // knowing what either one is, which is what makes the difference certain
    // rather than merely likely.
    const first = try allocator.create(Connection);
    defer allocator.destroy(first);
    try connectInto(first, allocator, "example.com", .{}, client_test_tls, null, test_now, rng.random());
    defer first.deinit();

    const second = try allocator.create(Connection);
    defer allocator.destroy(second);
    try connectInto(second, allocator, "example.com", .{}, client_test_tls, null, test_now, rng.random());
    defer second.deinit();

    try std.testing.expect(!std.mem.eql(u8, first.scid[0..first.scid_len], second.scid[0..second.scid_len]));

    // The handshake keeps its own copy of these parameters and encodes them
    // again later, so what that copy points at has to outlive the frame that
    // drew them.
    const hs = first.tls13_hs.?;
    const retained = hs.local_transport_params.initial_source_connection_id orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, first.scid[0..first.scid_len], retained);

    // The extension the ClientHello carries agrees with that copy, and did so
    // even when the copy did not: it is encoded inside the frame while the
    // frame is still standing. The retained copy is what needed proving.
    const encoded = try transport_params.TransportParams.decode(hs.tp_encoded[0..hs.tp_encoded_len]);
    const on_the_wire = encoded.initial_source_connection_id orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, first.scid[0..first.scid_len], on_the_wire);
}

test "connect: the first flight's version follows a ticket this connection can start on" {
    // RFC 9369 §5: "Clients MUST NOT use a session ticket or token from a
    // QUIC version 1 connection to initiate a QUIC version 2 connection, and
    // vice versa." A client holding a version-2 ticket therefore either starts
    // this connection on version 2 or leaves the ticket behind, and which of
    // the two it does is what `enable_v2` decides. All three answers are
    // readable before a byte goes out: the version the first flight is built
    // with, the version it advertises, and whether 0-RTT keys were installed.
    var ticket: tls13.SessionTicket = .{ .psk = .{0x5a} ** 32, .quic_version = protocol.QUIC_V2 };
    @memset(&ticket.ticket, 0x7b);
    ticket.ticket_len = 32;
    const client_tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
        .resumption = .{ .client = &ticket },
        .session_ticket = &ticket,
    };

    // Without version 2 this connection starts on version 1, where a version-2
    // ticket is not this connection's: no Version Information is published at
    // all, and the ticket is not offered.
    var rng = TestRandom{};
    const on_v1 = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(on_v1);
    try connectInto(
        on_v1,
        std.testing.allocator,
        "example.com",
        .{},
        client_tls_config,
        null,
        test_now,
        rng.random(),
    );
    defer on_v1.deinit();
    try std.testing.expectEqual(protocol.QUIC_V1, on_v1.version);
    try std.testing.expectEqual(@as(?u32, null), on_v1.local_params.version_info_chosen);
    try std.testing.expect(on_v1.early_data_seal == null);

    // With it, the same ticket belongs to the version this connection starts
    // on, so the first flight is version 2 and its 0-RTT keys are installed.
    const on_v2 = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(on_v2);
    try connectInto(
        on_v2,
        std.testing.allocator,
        "example.com",
        .{ .enable_v2 = true },
        client_tls_config,
        null,
        test_now,
        rng.random(),
    );
    defer on_v2.deinit();
    try std.testing.expectEqual(protocol.QUIC_V2, on_v2.version);
    try std.testing.expectEqual(@as(?u32, protocol.QUIC_V2), on_v2.local_params.version_info_chosen);
    try std.testing.expect(on_v2.early_data_seal != null);
}

/// Builds a client and releases nothing when that build fails, because the
/// release is the constructor's: a `deinit` is only reachable once the
/// constructor has returned, so an allocation failure part-way through has to
/// leave the allocator as it found it. That is the contract under test, not
/// an oversight in this helper.
fn connectIntoWithoutRelease(allocator: std.mem.Allocator, tls_config: ?tls13.TlsConfig) !void {
    const conn = try allocator.create(Connection);
    defer allocator.destroy(conn);
    var rng = TestRandom{};
    try connectInto(conn, allocator, "example.com", .{
        .datagram_queue_capacity = DatagramQueue.DEFAULT_MAX_ITEMS + 4,
    }, tls_config, null, test_now, rng.random());
    conn.deinit();
}

test "connect: an interrupted construction leaves nothing allocated" {
    // Once through each branch of the handshake decision: one allocates the
    // handshake and steps it into a ClientHello, the other queues the
    // transport parameters straight into a crypto stream. The datagram queues
    // are grown on both, so their three allocations are on every run.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, connectIntoWithoutRelease, .{client_test_tls});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, connectIntoWithoutRelease, .{null});
}

test "validatePeerTransportParams: a chosen version outside the peer's own list is refused" {
    // RFC 9368 §3: "If a server receives Version Information where the Chosen
    // Version is not included in Available Versions, it MUST treat it as a
    // parsing failure." A peer naming a version it never listed cannot be
    // taken at its word when this end picks one out of that list.
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    const peer_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    var peer_tp = transport_params.TransportParams{
        .initial_source_connection_id = &peer_scid,
        .version_info_chosen = protocol.QUIC_V1,
        .version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 },
        .version_info_available_count = 1,
    };

    try std.testing.expectError(
        error.TransportParameterError,
        conn.validatePeerTransportParams(&peer_tp, test_now),
    );

    peer_tp.version_info_available[0] = protocol.QUIC_V1;
    try conn.validatePeerTransportParams(&peer_tp, test_now);

    // A peer that sends no Version Information has contradicted nothing.
    peer_tp.version_info_chosen = null;
    peer_tp.version_info_available_count = 0;
    try conn.validatePeerTransportParams(&peer_tp, test_now);
}

test "validatePeerTransportParams: a chosen version this connection never sent is refused" {
    // RFC 9368 §4: "the server MUST validate that the client's Chosen Version
    // matches the version in use for the connection. If the two differ, the
    // server MUST close the connection with a version negotiation error." The
    // version in use for the connection is the one the long header of the
    // packets carrying these parameters carried — the client's first flight,
    // which §1.2 defines as the Chosen Version and which the packer keeps in
    // `original_version` for the whole life of the connection.
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    const peer_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    var peer_tp = transport_params.TransportParams{
        .initial_source_connection_id = &peer_scid,
        // Named in the peer's own list, so the parsing-failure check above
        // takes it: a version the client listed and is nevertheless not the one
        // its first flight went out under is a downgrade, not a typo.
        .version_info_chosen = protocol.QUIC_V2,
        .version_info_available = .{ protocol.QUIC_V2, 0, 0, 0, 0, 0, 0, 0 },
        .version_info_available_count = 1,
    };
    try std.testing.expectEqual(protocol.QUIC_V1, conn.packer.original_version);

    try std.testing.expectError(
        error.VersionNegotiationError,
        conn.validatePeerTransportParams(&peer_tp, test_now),
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(TransportError.version_negotiation_error)),
        conn.local_err.?.code,
    );
    try std.testing.expect(!conn.local_err.?.is_app);

    // The compatible negotiation the same check must let through: a first
    // flight sent as v1 that came back negotiated as v2, so `version` has
    // moved to the negotiated version and the client's Chosen Version has not.
    var negotiated = testConnection(std.testing.allocator);
    defer negotiated.deinit();
    negotiated.version = protocol.QUIC_V2;
    negotiated.packer.version = protocol.QUIC_V2;
    peer_tp.version_info_chosen = protocol.QUIC_V1;
    peer_tp.version_info_available[0] = protocol.QUIC_V1;
    try negotiated.validatePeerTransportParams(&peer_tp, test_now);
    try std.testing.expectEqual(State.first_flight, negotiated.state);
}

test "validatePeerTransportParams: a client may choose the ninth version it lists" {
    // RFC 9368 §3 bounds the Available Versions list by nothing but the
    // parameter's own length, and reserves `0x?a?a?a?a` entries for greasing,
    // so a client may grease its way to a Chosen Version that this
    // connection's eight-entry copy of the list drops. The copy is the seam:
    // decode keeps the first eight and `hasAvailableVersion` answers out of
    // those, so a chosen version behind eight of them reads as absent and a
    // legal client is refused for having greased first.
    //
    // Wire-encoded rather than built as a `TransportParams`, because
    // `version_info_available_count` above eight reads past the array it
    // counts — the same eight seen from the other side.
    var wire: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&wire);
    const writer = &fbs;
    const greased = [_]u32{
        0x0a0a0a0a, 0x1a1a1a1a, 0x2a2a2a2a, 0x3a3a3a3a,
        0x4a4a4a4a, 0x5a5a5a5a, 0x6a6a6a6a, 0x7a7a7a7a,
    };
    try packet.writeVarInt(writer, @intFromEnum(transport_params.ParamId.version_information));
    try packet.writeVarInt(writer, 4 + (greased.len + 1) * 4);
    try writer.writeInt(u32, protocol.QUIC_V1, .big);
    for (greased) |version| try writer.writeInt(u32, version, .big);
    try writer.writeInt(u32, protocol.QUIC_V1, .big);

    var peer_tp = try transport_params.TransportParams.decode(fbs.buffered());
    const peer_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    peer_tp.initial_source_connection_id = &peer_scid;

    // Whatever is kept of the list is kept from its head and in order: an
    // answer that holds more than eight may hold more, not different ones.
    for (greased, 0..) |version, i| {
        if (i >= peer_tp.version_info_available_count) break;
        try std.testing.expectEqual(version, peer_tp.version_info_available[i]);
    }

    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    try conn.validatePeerTransportParams(&peer_tp, test_now);
    try std.testing.expectEqual(State.first_flight, conn.state);
}

test "validatePeerTransportParams: a client's server may name a version it does not offer" {
    // RFC 9368 §3 puts the check on the server alone: "If a server receives
    // Version Information where the Chosen Version is not included in Available
    // Versions, it MUST treat it as a parsing failure." A server's own Chosen
    // Version "is not necessarily included in this list, because the server
    // operator could be in the process of removing support for this version",
    // and the Available Versions field MAY be empty — so a client that applies
    // the same rule to what a server sends refuses a server that published a
    // perfectly valid list.
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    // The same fixture read as a client: a client owes the original
    // destination connection id check, set up beside the version information
    // so nothing else refuses these parameters first.
    conn.is_server = false;
    const odcid = conn.scid[0..conn.scid_len];
    conn.odcid_len = @intCast(odcid.len);
    @memcpy(conn.odcid_buf[0..odcid.len], odcid);

    const peer_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    var peer_tp = transport_params.TransportParams{
        .initial_source_connection_id = &peer_scid,
        .original_destination_connection_id = odcid,
        // A server still speaking v1 while it says v2 is all it has
        // deployed: the ordinary shape of an operator withdrawing a version.
        .version_info_chosen = protocol.QUIC_V1,
        .version_info_available = .{ protocol.QUIC_V2, 0, 0, 0, 0, 0, 0, 0 },
        .version_info_available_count = 1,
    };
    try conn.validatePeerTransportParams(&peer_tp, test_now);

    // The same server having withdrawn from Version Information altogether:
    // an empty Available Versions list is what RFC 9368 §3 allows.
    peer_tp.version_info_available_count = 0;
    try conn.validatePeerTransportParams(&peer_tp, test_now);

    // A chosen version the server also offers is the ordinary case.
    peer_tp.version_info_chosen = protocol.QUIC_V2;
    peer_tp.version_info_available_count = 1;
    try conn.validatePeerTransportParams(&peer_tp, test_now);
}

test "validatePeerTransportParams: a peer active_connection_id_limit below two is refused" {
    // RFC 9000 §18.2 makes 2 both the default and the floor, and the field
    // documents a smaller peer value as one for this check to catch. A peer
    // offering 0 or 1 is saying it will retire nothing, so every
    // RETIRE_CONNECTION_ID this end sends would name a connection id the
    // peer is still using.
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    const peer_scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var peer_tp = transport_params.TransportParams{
        .initial_source_connection_id = &peer_scid,
    };

    for ([_]u64{ 0, 1 }) |limit| {
        peer_tp.active_connection_id_limit = limit;
        try std.testing.expectError(
            error.TransportParameterError,
            conn.validatePeerTransportParams(&peer_tp, test_now),
        );
    }

    // Two is accepted: it is what a peer means by never sending the
    // parameter, and it is the value the field already defaults to.
    peer_tp.active_connection_id_limit = 2;
    try conn.validatePeerTransportParams(&peer_tp, test_now);
}

/// Builds a server and releases nothing when that build fails, because the
/// release is the constructor's — the same contract `connectIntoWithoutRelease`
/// states for a client, over the same allocation-failure sweep.
fn acceptIntoWithoutRelease(allocator: std.mem.Allocator, tls_config: ?tls13.TlsConfig) !void {
    const conn = try allocator.create(Connection);
    defer allocator.destroy(conn);
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const header: packet.Header = .{
        .packet_type = .initial,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .dcid = &dcid,
        .scid = &scid,
        .token = &.{},
        .packet_number = 0,
        .packet_number_len = 1,
        .remainder_len = 0,
    };
    var rng = TestRandom{};
    try Connection.acceptInto(
        conn,
        allocator,
        header,
        address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443),
        address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345),
        true,
        .{ .datagram_queue_capacity = DatagramQueue.DEFAULT_MAX_ITEMS + 4 },
        tls_config,
        null,
        null,
        test_now,
        rng.random(),
    );
    conn.deinit();
}

test "accept: an interrupted construction leaves nothing allocated" {
    // The handshake is one of the allocations this constructor makes, so the
    // sweep is what says the connection releases it whichever allocation it
    // dies on — refused before the pointer is stored included.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, acceptIntoWithoutRelease, .{client_test_tls});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, acceptIntoWithoutRelease, .{null});
}

test "Connection: init and basic state" {
    const dcid_val = "dest1234" ++ ([_]u8{0} ** 12);
    const scid_val = "src12345" ++ ([_]u8{0} ** 12);

    var conn = Connection{
        .allocator = std.testing.allocator,
        .is_server = true,
        .dcid = dcid_val.*,
        .dcid_len = 8,
        .scid = scid_val.*,
        .scid_len = 8,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .pkt_handler = ack_handler.PacketHandler.init(std.testing.allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(1048576, 6 * 1024 * 1024),
        .streams = stream_mod.StreamsMap.init(std.testing.allocator, true),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(std.testing.allocator),
        .packer = packet_packer.PacketPacker.init(
            true,
            dcid_val[0..8],
            scid_val[0..8],
            protocol.SUPPORTED_VERSIONS[0],
        ),
    };
    defer conn.deinit();

    try std.testing.expectEqual(conn.dcid[0..8].*, dcid_val[0..8].*);
    try std.testing.expectEqual(conn.state, .first_flight);
    try std.testing.expect(!conn.isClosed());
    try std.testing.expect(!conn.isDraining());
}

// ConnectionIdPool tests
test "ConnectionIdPool: add and consume" {
    var pool = ConnectionIdPool{};
    const cid1 = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const token1 = [_]u8{0xAA} ** 16;
    pool.addPeerCid(1, &cid1, token1);

    try std.testing.expectEqual(@as(usize, 1), pool.count());

    const entry = pool.consumeUnused();
    try std.testing.expect(entry != null);
    try std.testing.expectEqualSlices(u8, &cid1, entry.?.getCid());
    try std.testing.expect(entry.?.in_use);

    // No more unused entries
    try std.testing.expect(pool.consumeUnused() == null);
}

test "ConnectionIdPool: retire prior to" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    pool.addPeerCid(0, &[_]u8{ 0x01, 0x02 }, token);
    pool.addPeerCid(1, &[_]u8{ 0x03, 0x04 }, token);
    pool.addPeerCid(2, &[_]u8{ 0x05, 0x06 }, token);

    try std.testing.expectEqual(@as(usize, 3), pool.count());
    pool.retirePriorTo(2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    const entry = pool.consumeUnused();
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u64, 2), entry.?.seq_num);
}

test "ConnectionIdPool: remove by seq" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    pool.addPeerCid(5, &[_]u8{ 0x01, 0x02, 0x03 }, token);
    pool.addPeerCid(6, &[_]u8{ 0x04, 0x05, 0x06 }, token);

    try std.testing.expectEqual(@as(usize, 2), pool.count());
    pool.removeBySeq(5);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}

test "ConnectionIdPool: pool full" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    var i: u64 = 0;
    while (i < ConnectionIdPool.MAX_POOL_SIZE + 2) : (i += 1) {
        pool.addPeerCid(i, &[_]u8{@intCast(i)}, token);
    }
    // Should cap at MAX_POOL_SIZE
    try std.testing.expectEqual(ConnectionIdPool.MAX_POOL_SIZE, pool.count());
}

// PathValidator tests
test "PathValidator: challenge and response" {
    var rng = TestRandom{};
    var validator = PathValidator{};
    const challenge = validator.startChallenge(test_now, rng.random());

    try std.testing.expectEqual(PathValidationState.pending, validator.state);
    try std.testing.expect(validator.handleResponse(challenge));
    try std.testing.expectEqual(PathValidationState.validated, validator.state);
}

test "PathValidator: wrong response" {
    var rng = TestRandom{};
    var validator = PathValidator{};
    _ = validator.startChallenge(test_now, rng.random());

    const wrong_data = [_]u8{0xFF} ** 8;
    try std.testing.expect(!validator.handleResponse(wrong_data));
    try std.testing.expectEqual(PathValidationState.pending, validator.state);
}

test "PathValidator: needs retry" {
    var rng = TestRandom{};
    var validator = PathValidator{};
    _ = validator.startChallenge(test_now, rng.random());
    // Simulate time passing by setting challenge_sent_time far in the past
    validator.challenge_sent_time = 0;

    const now: i64 = 1_000_000_000; // 1s
    const pto: i64 = 100_000_000; // 100ms
    try std.testing.expect(validator.needsRetry(now, pto));

    validator.retry(test_now);
    try std.testing.expectEqual(@as(u8, 1), validator.retries);
}

// LocalCidPool tests
test "LocalCidPool: register and issue" {
    var rng = TestRandom{};
    var pool = LocalCidPool{};
    const initial_cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    pool.registerInitialCid(&initial_cid, null, rng.random());

    // Seq 0 should be registered
    try std.testing.expectEqual(@as(usize, 1), pool.activeCount());
    try std.testing.expectEqual(@as(u64, 1), pool.next_seq_num);

    // Issue a new CID
    const entry1 = pool.issueNewCid(8, null, rng.random()).?;
    try std.testing.expectEqual(@as(u64, 1), entry1.seq_num);
    try std.testing.expectEqual(@as(u8, 8), entry1.cid_len);
    try std.testing.expectEqual(@as(usize, 2), pool.activeCount());

    // Issue another
    const entry2 = pool.issueNewCid(8, null, rng.random()).?;
    try std.testing.expectEqual(@as(u64, 2), entry2.seq_num);
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());
}

test "LocalCidPool: retire and replace" {
    var rng = TestRandom{};
    var pool = LocalCidPool{};
    pool.registerInitialCid(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, null, rng.random());

    // Issue 2 more CIDs (seq 1, 2)
    _ = pool.issueNewCid(8, null, rng.random());
    _ = pool.issueNewCid(8, null, rng.random());
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());

    // Retire seq 0
    pool.retireBySeq(0);
    try std.testing.expectEqual(@as(usize, 2), pool.activeCount());

    // Can issue a replacement into the freed slot
    const replacement = pool.issueNewCid(8, null, rng.random()).?;
    try std.testing.expectEqual(@as(u64, 3), replacement.seq_num);
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());
}

test "LocalCidPool: pool full" {
    var rng = TestRandom{};
    var pool = LocalCidPool{};
    pool.registerInitialCid(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, null, rng.random());

    // Fill remaining 7 slots
    var i: usize = 0;
    while (i < LocalCidPool.MAX_POOL_SIZE - 1) : (i += 1) {
        try std.testing.expect(pool.issueNewCid(8, null, rng.random()) != null);
    }
    try std.testing.expectEqual(@as(usize, LocalCidPool.MAX_POOL_SIZE), pool.activeCount());

    // Pool full — should return null
    try std.testing.expect(pool.issueNewCid(8, null, rng.random()) == null);
}

// --- DatagramQueue tests ---

test "DatagramQueue: push and pop" {
    var q = DatagramQueue{};
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.queueLen());
    try std.testing.expect(!q.isFull());

    const data1 = "hello";
    const data2 = "world!";
    try std.testing.expect(q.push(data1, test_now));
    try std.testing.expect(q.push(data2, test_now));
    try std.testing.expect(!q.isEmpty());
    try std.testing.expectEqual(@as(usize, 2), q.queueLen());

    var buf: [1200]u8 = undefined;
    const len1 = q.pop(&buf).?;
    try std.testing.expectEqual(@as(usize, 5), len1);
    try std.testing.expectEqualSlices(u8, "hello", buf[0..len1]);

    const len2 = q.pop(&buf).?;
    try std.testing.expectEqual(@as(usize, 6), len2);
    try std.testing.expectEqualSlices(u8, "world!", buf[0..len2]);

    // Empty now
    try std.testing.expect(q.pop(&buf) == null);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.queueLen());
}

test "DatagramQueue: full queue" {
    var q = DatagramQueue{};
    // Fill the queue (MAX_ITEMS = 32)
    var i: usize = 0;
    while (i < DatagramQueue.DEFAULT_MAX_ITEMS) : (i += 1) {
        try std.testing.expect(!q.isFull());
        try std.testing.expect(q.push("data", test_now));
    }
    // Queue full — push should fail
    try std.testing.expect(q.isFull());
    try std.testing.expectEqual(@as(usize, DatagramQueue.DEFAULT_MAX_ITEMS), q.queueLen());
    try std.testing.expect(!q.push("overflow", test_now));
}

test "DatagramQueue: oversized datagram rejected" {
    var q = DatagramQueue{};
    const big = [_]u8{0xAA} ** (DatagramQueue.MAX_DATAGRAM_SIZE + 1);
    try std.testing.expect(!q.push(&big, test_now));
    try std.testing.expect(q.isEmpty());
}

test "DatagramQueue: pop with small buffer" {
    var q = DatagramQueue{};
    try std.testing.expect(q.push("hello", test_now));
    var small_buf: [2]u8 = undefined;
    // Buffer too small — should return null
    try std.testing.expect(q.pop(&small_buf) == null);
}

test "DatagramQueue: high water mark limits push" {
    var q = DatagramQueue{};
    q.high_water_mark = 3;

    try std.testing.expect(q.push("one", test_now));
    try std.testing.expect(q.push("two", test_now));
    try std.testing.expect(q.push("three", test_now));
    // At high water mark — push should fail
    try std.testing.expect(!q.push("four", test_now));
    try std.testing.expect(q.isFull());
    try std.testing.expectEqual(@as(usize, 3), q.queueLen());

    // Pop one, then push succeeds again
    var buf: [1200]u8 = undefined;
    _ = q.pop(&buf);
    try std.testing.expect(q.push("four", test_now));
}

test "DatagramQueue: max age expiry on pop" {
    var q = DatagramQueue{};
    q.max_age_ns = 10_000_000; // 10ms

    try std.testing.expect(q.push("old", test_now));
    try std.testing.expect(q.push("new", test_now));

    // Both datagrams are fresh — popSkipExpired should return first
    var buf: [1200]u8 = undefined;
    const len = q.popSkipExpired(&buf, test_now);
    try std.testing.expect(len != null);
    try std.testing.expectEqualSlices(u8, "old", buf[0..len.?]);
}

test "DatagramQueue: peekDataSkipExpired with no max age" {
    var q = DatagramQueue{};
    // No max_age set — behaves like peekData
    try std.testing.expect(q.push("data", test_now));
    const peeked = q.peekDataSkipExpired(test_now);
    try std.testing.expect(peeked != null);
    try std.testing.expectEqualSlices(u8, "data", peeked.?);
}

// --- Connection state and method tests ---

fn testConnection(allocator: std.mem.Allocator) Connection {
    return testConnectionForRole(allocator, true);
}

/// State-only fixture without TLS; packet and stream roles match the connection.
fn testConnectionForRole(allocator: std.mem.Allocator, is_server: bool) Connection {
    const dcid_val = "dest1234" ++ ([_]u8{0} ** 12);
    const scid_val = "src12345" ++ ([_]u8{0} ** 12);
    return Connection{
        .allocator = allocator,
        .is_server = is_server,
        .dcid = dcid_val.*,
        .dcid_len = 8,
        .scid = scid_val.*,
        .scid_len = 8,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .pkt_handler = ack_handler.PacketHandler.init(allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(1048576, 6 * 1024 * 1024),
        .streams = stream_mod.StreamsMap.init(allocator, is_server),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),
        .packer = packet_packer.PacketPacker.init(
            is_server,
            dcid_val[0..8],
            scid_val[0..8],
            protocol.SUPPORTED_VERSIONS[0],
        ),
    };
}

test "Connection: close transitions to closing state" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expectEqual(State.first_flight, conn.state);
    conn.close(0, "done", test_now);
    try std.testing.expectEqual(State.closing, conn.state);
    try std.testing.expect(conn.local_err != null);
    try std.testing.expect(conn.local_err.?.is_app);
    try std.testing.expectEqual(@as(u64, 0), conn.local_err.?.code);
}

test "Connection: close is idempotent in terminal states" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    conn.close(1, "first", test_now);
    try std.testing.expectEqual(State.closing, conn.state);
    // Second close should be ignored
    conn.close(2, "second", test_now);
    try std.testing.expectEqual(@as(u64, 1), conn.local_err.?.code);
}

test "Connection: closeWithTransportError" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    conn.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.crypto), "flow control", test_now);
    try std.testing.expectEqual(State.closing, conn.state);
    try std.testing.expect(!conn.local_err.?.is_app);
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.protocol_violation)), conn.local_err.?.code);
}

test "Connection: state queries" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // first_flight
    try std.testing.expect(!conn.isClosed());
    try std.testing.expect(!conn.isDraining());
    try std.testing.expect(!conn.isEstablished());

    // connected
    conn.state = .connected;
    try std.testing.expect(conn.isEstablished());
    try std.testing.expect(!conn.isClosed());

    // draining
    conn.state = .draining;
    try std.testing.expect(conn.isDraining());

    // terminated
    conn.state = .terminated;
    try std.testing.expect(conn.isClosed());
}

test "Connection: datagram send requires enabled" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Datagrams not enabled — should error
    try std.testing.expectError(error.DatagramsNotEnabled, conn.sendDatagram("test", test_now));

    // Enable datagrams and send
    conn.datagrams_enabled = true;
    try conn.sendDatagram("hello datagram", test_now);

    // Verify it's in the send queue (not recv queue)
    try std.testing.expect(!conn.datagram_send_queue.isEmpty());
    try std.testing.expect(conn.datagram_recv_queue.isEmpty());
}

test "Connection: DatagramTooLarge vs DatagramQueueFull" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.datagrams_enabled = true;

    // Too-large payload → permanent error
    const big = [_]u8{0xAA} ** (DatagramQueue.MAX_DATAGRAM_SIZE + 1);
    try std.testing.expectError(error.DatagramTooLarge, conn.sendDatagram(&big, test_now));

    // Fill the queue → transient error
    var i: usize = 0;
    while (i < DatagramQueue.DEFAULT_MAX_ITEMS) : (i += 1) {
        try conn.sendDatagram("x", test_now);
    }
    try std.testing.expect(conn.isDatagramSendQueueFull());
    try std.testing.expectEqual(@as(usize, DatagramQueue.DEFAULT_MAX_ITEMS), conn.datagramSendQueueLen());
    try std.testing.expectError(error.DatagramQueueFull, conn.sendDatagram("overflow", test_now));
}

test "Connection: maxDatagramPayloadSize" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Datagrams not enabled → null
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);

    // Enable datagrams but no peer params → null
    conn.datagrams_enabled = true;
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);

    // Set peer params with max_datagram_frame_size
    conn.peer_params = transport_params.TransportParams{};
    conn.peer_params.?.max_datagram_frame_size = 65536;
    conn.dcid_len = 8;
    // Short header: 1 + 8 + 4 + 16 = 29 overhead
    // max_packet_size default = 1200, payload budget = 1200 - 29 = 1171
    // frame overhead = 3 (type + 2-byte varint), from_pkt = 1168
    // from_peer = 65536 - 3 = 65533, capped by from_pkt and MAX_DATAGRAM_SIZE
    const max_payload = conn.maxDatagramPayloadSize().?;
    try std.testing.expect(max_payload > 0);
    try std.testing.expect(max_payload <= DatagramQueue.MAX_DATAGRAM_SIZE);

    // Disabled peer param → null
    conn.peer_params.?.max_datagram_frame_size = null;
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);
}

test "Connection: datagram receive" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Nothing to receive initially
    var buf: [1200]u8 = undefined;
    try std.testing.expect(conn.recvDatagram(&buf, test_now) == null);

    // Simulate receiving a datagram (push to recv queue)
    try std.testing.expect(conn.datagram_recv_queue.push("incoming data", test_now));

    const len = conn.recvDatagram(&buf, test_now).?;
    try std.testing.expectEqualSlices(u8, "incoming data", buf[0..len]);
    try std.testing.expect(conn.recvDatagram(&buf, test_now) == null);
}

test "Connection: getStats returns counters" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Initial stats should be zero
    const stats0 = conn.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats0.packets_sent);
    try std.testing.expectEqual(@as(u64, 0), stats0.packets_received);
    try std.testing.expectEqual(@as(u64, 0), stats0.packets_lost);
    try std.testing.expectEqual(@as(u64, 0), stats0.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), stats0.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), stats0.datagrams_dropped_incoming);
    try std.testing.expectEqual(@as(u64, 0), stats0.datagrams_lost_outgoing);

    // Manually bump counters to verify aggregation
    conn.total_packets_sent = 10;
    conn.total_packets_received = 20;
    conn.total_packets_lost = 2;
    conn.paths[0].bytes_sent = 5000;
    conn.paths[0].bytes_received = 8000;
    conn.datagrams_dropped_incoming = 3;
    conn.datagrams_lost_outgoing = 1;

    const stats1 = conn.getStats();
    try std.testing.expectEqual(@as(u64, 10), stats1.packets_sent);
    try std.testing.expectEqual(@as(u64, 20), stats1.packets_received);
    try std.testing.expectEqual(@as(u64, 2), stats1.packets_lost);
    try std.testing.expectEqual(@as(u64, 5000), stats1.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8000), stats1.bytes_received);
    try std.testing.expectEqual(@as(u64, 3), stats1.datagrams_dropped_incoming);
    try std.testing.expectEqual(@as(u64, 1), stats1.datagrams_lost_outgoing);
}

test "Connection: getNewToken" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // No token initially
    try std.testing.expect(conn.getNewToken() == null);

    // Simulate receiving a token
    const token = "test-token-12345";
    @memcpy(conn.new_token_buf[0..token.len], token);
    conn.new_token_len = @intCast(token.len);

    const got = conn.getNewToken().?;
    try std.testing.expectEqualSlices(u8, token, got);
}

test "Connection: dropHandshakeKeys clears Initial and Handshake" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Initial keys should be set (from testConnection → pkt_num_spaces default)
    // Set dummy keys to verify they get cleared
    const dummy_seal = conn.pkt_num_spaces[0].crypto_seal;
    _ = dummy_seal;
    conn.dropHandshakeKeys();

    try std.testing.expect(conn.pkt_num_spaces[0].crypto_open == null);
    try std.testing.expect(conn.pkt_num_spaces[0].crypto_seal == null);
    try std.testing.expect(conn.pkt_num_spaces[1].crypto_open == null);
    try std.testing.expect(conn.pkt_num_spaces[1].crypto_seal == null);
}

test "Connection: initiateKeyUpdate without key_update manager" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // No key update manager — should return false
    try std.testing.expect(!conn.initiateKeyUpdate(test_now));
}

test "Connection: getEcnMark" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // ECN validator starts disabled — shouldMark() = false
    try std.testing.expectEqual(ECN_NOT_ECT, conn.getEcnMark());

    // Start ECN validation (transitions to testing)
    conn.ecn_validator.start();
    try std.testing.expectEqual(ECN_ECT0, conn.getEcnMark());

    // If ECN fails
    conn.ecn_validator.state = .failed;
    try std.testing.expectEqual(ECN_NOT_ECT, conn.getEcnMark());
}

test "Connection: a datagram ending in the peer's reset token drains without sending" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    try conn.pkt_num_spaces[@intFromEnum(ack_handler.EncLevel.application)].setupInitial("dest1234", conn.version, true);
    conn.state = .connected;
    const token = [_]u8{0xBB} ** 16;
    conn.peer_cid_pool.addPeerCid(0, conn.dcid[0..conn.dcid_len], token);
    const info: RecvInfo = .{ .to = undefined, .from = undefined, .datagram_size = 40 };

    // Undecryptable junk that doesn't end in the token is dropped.
    var junk: [40]u8 = undefined;
    rng.random().bytes(&junk);
    junk[0] = 0x40 | (junk[0] & 0x3f);
    conn.handleDatagram(&junk, info, test_now, rng.random());
    try std.testing.expectEqual(State.connected, conn.state);

    // Under 21 bytes a datagram is never a reset (RFC 9000 §10.3).
    var tiny: [20]u8 = undefined;
    @memcpy(tiny[0..4], junk[0..4]);
    @memcpy(tiny[4..], &token);
    conn.handleDatagram(&tiny, info, test_now, rng.random());
    try std.testing.expectEqual(State.connected, conn.state);

    var reset = junk;
    @memcpy(reset[reset.len - 16 ..], &token);
    conn.handleDatagram(&reset, info, test_now, rng.random());
    try std.testing.expect(conn.isDraining());
    try std.testing.expect(conn.received_stateless_reset);
    var out: [1500]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try conn.sendAt(&out, test_now, rng.random()));
}

test "Connection: a retired peer CID's reset token is no longer honoured" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    try conn.pkt_num_spaces[@intFromEnum(ack_handler.EncLevel.application)].setupInitial("dest1234", conn.version, true);
    conn.state = .connected;
    const token = [_]u8{0xBB} ** 16;
    conn.peer_cid_pool.addPeerCid(0, conn.dcid[0..conn.dcid_len], token);
    conn.peer_cid_pool.retirePriorTo(1);

    var reset: [40]u8 = undefined;
    rng.random().bytes(&reset);
    reset[0] = 0x40 | (reset[0] & 0x3f);
    @memcpy(reset[reset.len - 16 ..], &token);
    conn.handleDatagram(&reset, .{ .to = undefined, .from = undefined, .datagram_size = 40 }, test_now, rng.random());
    try std.testing.expectEqual(State.connected, conn.state);
}

test "Connection: matchesStatelessReset with no tokens" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    const data = [_]u8{0xAA} ** 32;
    try std.testing.expect(!conn.matchesStatelessReset(&data));
}

test "Connection: matchesStatelessReset with matching token" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Add a peer CID with a known reset token
    const token = [_]u8{0xBB} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    conn.peer_cid_pool.addPeerCid(1, &cid, token);

    // Build a packet whose last 16 bytes are the token
    var data: [32]u8 = undefined;
    @memset(data[0..16], 0xCC); // random prefix
    @memcpy(data[16..32], &token); // token at end
    try std.testing.expect(conn.matchesStatelessReset(&data));
}

test "Connection: openStream" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Set peer's max bidi streams limit (simulating received transport params)
    conn.streams.max_bidi_streams = 100;

    // Server opens bidi stream (stream ID 1 for server-initiated bidi)
    const s = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 1), s.stream_id);
}

test "accept: create server connection" {
    var rng = TestRandom{};
    const local = address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443);
    const remote = address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

    const header = packet.Header{
        .packet_type = .initial,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .dcid = &dcid,
        .scid = &scid,
        .token = &.{},
        .packet_number = 0,
        .packet_number_len = 1,
        .remainder_len = 0,
    };

    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try Connection.acceptInto(
        conn,
        std.testing.allocator,
        header,
        local,
        remote,
        true,
        .{},
        null,
        null,
        null,
        test_now,
        rng.random(),
    );
    defer conn.deinit();

    try std.testing.expect(conn.is_server);
    try std.testing.expectEqual(State.first_flight, conn.state);
    // Server: dcid = client's SCID, scid = generated
    try std.testing.expectEqual(@as(u8, 8), conn.dcid_len);
    try std.testing.expectEqualSlices(u8, &scid, conn.dcid[0..8]);
    try std.testing.expectEqual(@as(u8, 8), conn.scid_len);
    // Path should be initialized
    try std.testing.expect(conn.path_initialized);
}

test "accept: retained transport params own all CID inputs" {
    for ([_]bool{ false, true }) |retried| {
        var rng = TestRandom{};
        var header_dcid: [8]u8 = @splat(0x11);
        var header_scid: [8]u8 = @splat(0x22);
        var original_dcid: [8]u8 = @splat(0x33);
        var retry_scid: [8]u8 = @splat(0x44);
        const header: packet.Header = .{
            .packet_type = .initial,
            .version = protocol.SUPPORTED_VERSIONS[0],
            .dcid = &header_dcid,
            .scid = &header_scid,
            .token = &.{},
            .packet_number = 0,
            .packet_number_len = 1,
            .remainder_len = 0,
        };
        const conn = try std.testing.allocator.create(Connection);
        defer std.testing.allocator.destroy(conn);
        try Connection.acceptInto(
            conn,
            std.testing.allocator,
            header,
            address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443),
            address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345),
            true,
            .{},
            client_test_tls,
            if (retried) &original_dcid else null,
            if (retried) &retry_scid else null,
            test_now,
            rng.random(),
        );
        defer conn.deinit();
        @memset(&header_dcid, 0xee);
        @memset(&header_scid, 0xee);
        @memset(&original_dcid, 0xee);
        @memset(&retry_scid, 0xee);

        const handshake = conn.tls13_hs.?;
        var encoded: [512]u8 = undefined;
        var writer = io.fixedBufferStream(&encoded);
        try handshake.local_transport_params.encode(&writer, rng.random());
        const retained = try transport_params.TransportParams.decode(writer.buffered());
        const expected_odcid: [8]u8 = @splat(if (retried) 0x33 else 0x11);
        try std.testing.expectEqualSlices(
            u8,
            &expected_odcid,
            retained.original_destination_connection_id.?,
        );
        try std.testing.expectEqualSlices(
            u8,
            conn.scid[0..conn.scid_len],
            retained.initial_source_connection_id.?,
        );
        if (retried) {
            try std.testing.expectEqualSlices(
                u8,
                &([_]u8{0x44} ** 8),
                retained.retry_source_connection_id.?,
            );
        } else {
            try std.testing.expectEqual(@as(?[]const u8, null), retained.retry_source_connection_id);
        }
    }
}

test "accept: oversized header and retained CIDs are refused before allocation" {
    const oversized: [packet.CONNECTION_ID_MAX_SIZE + 1]u8 = @splat(0x11);
    for (0..4) |which| {
        var rng = TestRandom{};
        const header: packet.Header = .{
            .packet_type = .initial,
            .version = protocol.SUPPORTED_VERSIONS[0],
            .dcid = if (which == 0) &oversized else "dest1234",
            .scid = if (which == 1) &oversized else "src12345",
            .token = &.{},
            .packet_number = 0,
            .packet_number_len = 1,
            .remainder_len = 0,
        };
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        var conn: Connection = undefined;
        try std.testing.expectError(error.PacketError, Connection.acceptInto(
            &conn,
            failing.allocator(),
            header,
            address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443),
            address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345),
            true,
            .{},
            null,
            if (which == 2) &oversized else null,
            if (which == 3) &oversized else null,
            test_now,
            rng.random(),
        ));
        try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
    }
}

test "accept: a client may choose a zero-length SCID" {
    var rng = TestRandom{};
    // RFC 9000 §5.1 allows it and Safari does it; we answer to an empty DCID.
    const local = address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443);
    const remote = address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345);
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var header = packet.Header{
        .packet_type = .initial,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .dcid = &dcid,
        .scid = &.{},
        .token = &.{},
        .packet_number = 0,
        .packet_number_len = 1,
        .remainder_len = 0,
    };

    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try Connection.acceptInto(conn, std.testing.allocator, header, local, remote, true, .{}, null, null, null, test_now, rng.random());
    defer conn.deinit();
    try std.testing.expectEqual(@as(u8, 0), conn.dcid_len);
    try std.testing.expectEqual(@as(u8, 8), conn.scid_len);

    // A short header still cannot open one.
    header.packet_type = .one_rtt;
    try std.testing.expectError(
        error.PacketError,
        Connection.acceptInto(conn, std.testing.allocator, header, local, remote, true, .{}, null, null, null, test_now, rng.random()),
    );
}

test "PathValidator: checkTimeout after max retries" {
    var rng = TestRandom{};
    var validator = PathValidator{};
    _ = validator.startChallenge(test_now, rng.random());

    // Exhaust retries
    validator.retries = PathValidator.MAX_RETRIES;
    validator.challenge_sent_time = 0;

    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000;
    validator.checkTimeout(now, pto);

    try std.testing.expectEqual(PathValidationState.failed, validator.state);
}

test "NetworkPath: amplification limit" {
    var path = NetworkPath.init(
        address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443),
        address.Address.initIpv4(.{ 192, 168, 1, 1 }, 12345),
        true,
    );

    // Not validated — 3x amplification limit applies
    try std.testing.expect(!path.is_validated);
    try std.testing.expect(!path.canSend(1)); // 0 received * 3 = 0 budget

    path.bytes_received = 100;
    try std.testing.expect(path.canSend(300)); // 300 <= 300
    try std.testing.expect(!path.canSend(301)); // 301 > 300

    // After validation, no limit
    path.is_validated = true;
    try std.testing.expect(path.canSend(1_000_000));
}

// Keep-alive tests

test "keep_alive_period = 0 means no keep-alive interval" {
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{ .keep_alive_period = 0 }, null, null, test_now, rng.random());
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 0), conn.keep_alive_interval_ns);
}

test "keep_alive_period within idle_timeout/2 is used directly" {
    // keep_alive_period = 10s, idle_timeout = 30s → interval = 10s
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{
        .keep_alive_period = 10_000,
        .max_idle_timeout = 30_000,
    }, null, null, test_now, rng.random());
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 10_000_000_000), conn.keep_alive_interval_ns);
}

test "keep_alive_period capped at idle_timeout/2" {
    // keep_alive_period = 20s, idle_timeout = 30s → interval = 15s (capped)
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{
        .keep_alive_period = 20_000,
        .max_idle_timeout = 30_000,
    }, null, null, test_now, rng.random());
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 15_000_000_000), conn.keep_alive_interval_ns);
}

test "sendKeepAlive queues PING when connected" {
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{}, null, null, test_now, rng.random());
    defer conn.deinit();

    // Not connected yet — should be no-op
    conn.sendKeepAlive();
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.len);

    // Simulate connected state
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.sendKeepAlive();
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.len);
}

test "nextTimeoutNs includes keep-alive deadline" {
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{
        .keep_alive_period = 5_000, // 5s
        .max_idle_timeout = 30_000,
    }, null, null, test_now, rng.random());
    defer conn.deinit();

    conn.state = .connected;
    conn.handshake_confirmed = true;

    const timeout_with_ka = conn.nextTimeoutNs(test_now);
    try std.testing.expect(timeout_with_ka != null);

    // Now disable keep-alive and check that the deadline changes
    conn.keep_alive_interval_ns = 0;
    const timeout_without_ka = conn.nextTimeoutNs(test_now);
    try std.testing.expect(timeout_without_ka != null);

    // Keep-alive deadline should be earlier than idle timeout alone
    try std.testing.expect(timeout_with_ka.? <= timeout_without_ka.?);
}

test "keep_alive_ping_sent resets on packet receipt simulation" {
    var rng = TestRandom{};
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    try connectInto(conn, std.testing.allocator, "example.com", .{
        .keep_alive_period = 5_000,
        .max_idle_timeout = 30_000,
    }, null, null, test_now, rng.random());
    defer conn.deinit();

    conn.keep_alive_ping_sent = true;
    // Simulate what recv() does
    conn.last_packet_received_time = test_now;
    conn.keep_alive_ping_sent = false;
    try std.testing.expect(!conn.keep_alive_ping_sent);
}

test "RESET_STREAM on a peer uni stream releases connection flow control" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    // Peer opens uni stream 2, sends 10 bytes, then resets at final size 100.
    var payload = "0123456789".*;
    try conn.processFrame(&.{ .stream = .{
        .stream_id = 2,
        .offset = 0,
        .length = payload.len,
        .data = &payload,
        .fin = false,
    } }, .application, 0, rng.random());

    const before = conn.conn_flow_ctrl.base.receive_window;
    try conn.processFrame(&.{ .reset_stream = .{
        .stream_id = 2,
        .error_code = 7,
        .final_size = 100,
    } }, .application, 0, rng.random());

    // The peer counted all 100 bytes against the connection window when it
    // sent them; the 10 unread and the 90 that never arrived are all credited.
    conn.queueFlowControlUpdates();
    try std.testing.expectEqual(@as(u64, 100), conn.conn_flow_ctrl.base.highest_received);
    try std.testing.expectEqual(@as(u64, 100), conn.conn_flow_ctrl.base.bytes_read);
    try std.testing.expect(conn.conn_flow_ctrl.base.receive_window >= before);
    try std.testing.expectEqual(@as(u64, 1), conn.streams.consumed_uni_streams);

    const rs = conn.streams.recv_streams.get(2).?;
    try std.testing.expectEqual(@as(?u64, 7), rs.reset_err);
}

test "a retransmitted uni FIN is counted against MAX_STREAMS only once" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var payload = "hi".*;
    const fin_frame: Frame = .{ .stream = .{
        .stream_id = 2,
        .offset = 0,
        .length = payload.len,
        .data = &payload,
        .fin = true,
    } };
    try conn.processFrame(&fin_frame, .application, 0, rng.random());
    try conn.processFrame(&fin_frame, .application, 0, rng.random());

    try std.testing.expectEqual(@as(u64, 1), conn.streams.consumed_uni_streams);
    try std.testing.expectEqual(@as(u64, 0), conn.streams.open_uni_streams);
}

test "a uni STREAM retransmit after reclamation is dropped, not resurrected" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var payload = "hi".*;
    const fin_frame: Frame = .{ .stream = .{
        .stream_id = 2,
        .offset = 0,
        .length = payload.len,
        .data = &payload,
        .fin = true,
    } };
    try conn.processFrame(&fin_frame, .application, 0, rng.random());

    const rs = conn.streams.recv_streams.get(2).?;
    const data = rs.read().?;
    std.testing.allocator.free(data);
    _ = rs.read();
    conn.streams.releaseRecvStream(2);
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.recv_streams.get(2) == null);

    // Retransmit: silently ignored, and it must not open a second stream.
    try conn.processFrame(&fin_frame, .application, 0, rng.random());
    try std.testing.expect(conn.streams.recv_streams.get(2) == null);
    try std.testing.expectEqual(@as(u64, 1), conn.streams.consumed_uni_streams);
}

test "STREAMS_BLOCKED is answered with credit the peer does not already have" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(4, 4);

    // The peer opens all four streams we allowed and closes three of them.
    var id: u64 = 0;
    while (id < 16) : (id += 4) _ = try conn.streams.getOrCreateStream(id);
    conn.streams.consumed_bidi_streams = 3;

    try conn.processFrame(&.{ .streams_blocked_bidi = 4 }, .application, 0, rng.random());

    const frame = conn.pending_frames.pop().?;
    // Echoing 4 — the limit it is already at — would leave it blocked.
    try std.testing.expectEqual(@as(u64, 7), frame.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 7), conn.streams.max_incoming_bidi_streams);
    try std.testing.expectEqual(@as(u64, 0), conn.streams.consumed_bidi_streams);
}

test "STREAMS_BLOCKED below our limit resends it, and grants nothing twice" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(4, 4);

    // A stale view of the limit: our MAX_STREAMS was lost in flight.
    conn.streams.max_incoming_bidi_streams = 9;
    try conn.processFrame(&.{ .streams_blocked_bidi = 4 }, .application, 0, rng.random());
    try std.testing.expectEqual(@as(u64, 9), conn.pending_frames.pop().?.max_streams_bidi);

    // At the real limit with no closed streams there is nothing to give.
    try conn.processFrame(&.{ .streams_blocked_bidi = 9 }, .application, 0, rng.random());
    try std.testing.expect(conn.pending_frames.pop() == null);
}

test "STREAMS_BLOCKED on uni streams grants uni credit" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(4, 4);
    conn.streams.consumed_uni_streams = 2;

    try conn.processFrame(&.{ .streams_blocked_uni = 4 }, .application, 0, rng.random());
    try std.testing.expectEqual(@as(u64, 6), conn.pending_frames.pop().?.max_streams_uni);
}

test "RESET_STREAM opens a uni stream we had not heard of" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    // The peer's STREAM frames were all lost; the reset is the first we see it.
    try conn.processFrame(&.{ .reset_stream = .{
        .stream_id = 2,
        .error_code = 3,
        .final_size = 500,
    } }, .application, 0, rng.random());

    try std.testing.expect(conn.streams.recv_streams.get(2) != null);
    conn.queueFlowControlUpdates();
    try std.testing.expectEqual(@as(u64, 500), conn.conn_flow_ctrl.base.bytes_read);
    try std.testing.expectEqual(@as(u64, 1), conn.streams.consumed_uni_streams);
}

test "RESET_STREAM beyond MAX_STREAMS is a protocol violation" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(2, 2);

    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .reset_stream = .{
        .stream_id = 2 + 5 * 4,
        .error_code = 3,
        .final_size = 10,
    } }, .application, 0, rng.random()));
}

// RFC 9000 §21.7: reaching the reassembly cap ends the connection rather than
// dropping data, so the peer learns instead of stalling on a stream we stopped
// buffering.
test "a stream past the reassembly cap closes the connection" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var payload = [_]u8{'x'};
    // Peer-initiated bidi stream with a hole at 0, so nothing ever drains and
    // every frame lands as its own run.
    var i: u64 = 0;
    while (i < limits.max_reassembly_chunks) : (i += 1) {
        try conn.processFrame(&.{ .stream = .{
            .stream_id = 0,
            .offset = i * 2 + 2,
            .length = payload.len,
            .fin = false,
            .data = &payload,
        } }, .application, 0, rng.random());
    }

    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .stream = .{
        .stream_id = 0,
        .offset = 4000,
        .length = payload.len,
        .fin = false,
        .data = &payload,
    } }, .application, 0, rng.random()));
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(TransportError.internal_error)),
        conn.local_err.?.code,
    );
}

// Uni streams reach the sorter down a different path than bidi ones, so the
// cap needs its own cover here.
test "a uni stream past the reassembly cap closes the connection" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var payload = [_]u8{'x'};
    var i: u64 = 0;
    while (i < limits.max_reassembly_chunks) : (i += 1) {
        try conn.processFrame(&.{ .stream = .{
            .stream_id = 2,
            .offset = i * 2 + 2,
            .length = payload.len,
            .fin = false,
            .data = &payload,
        } }, .application, 0, rng.random());
    }

    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .stream = .{
        .stream_id = 2,
        .offset = 4000,
        .length = payload.len,
        .fin = false,
        .data = &payload,
    } }, .application, 0, rng.random()));
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(TransportError.internal_error)),
        conn.local_err.?.code,
    );
}

// RFC 9000 §7.5: exceeding the CRYPTO buffer is a MUST-close, and the peer is
// still unauthenticated when it happens.
test "CRYPTO past the buffer ceiling closes the connection" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    var payload = [_]u8{'x'};
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .crypto = .{
        .offset = limits.max_crypto_stream_offset,
        .data = &payload,
    } }, .application, 0, rng.random()));
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(TransportError.crypto_buffer_exceeded)),
        conn.local_err.?.code,
    );
}

/// What the control-frame queue held for one stream. Drains the queue.
const PendingForStream = struct { reset_final_size: ?u64 = null, blocked_limit: ?u64 = null };

fn drainPendingFor(conn: *Connection, stream_id: u64) PendingForStream {
    var out: PendingForStream = .{};
    while (conn.pending_frames.pop()) |f| {
        switch (f) {
            .reset_stream => |rs| if (rs.stream_id == stream_id) {
                out.reset_final_size = rs.final_size;
            },
            .stream_data_blocked => |sdb| if (sdb.stream_id == stream_id) {
                out.blocked_limit = sdb.limit;
            },
            else => {},
        }
    }
    return out;
}

test "RESET_STREAM reports the bytes sent as its final size, not the bytes written" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const s = try conn.streams.openBidiStream();
    try s.send.writeData(&([_]u8{'x'} ** 100));
    _ = s.send.popStreamFrame(40).?;
    s.send.reset(5);
    conn.queueFlowControlUpdates();

    try std.testing.expectEqual(@as(?u64, 40), drainPendingFor(&conn, s.stream_id).reset_final_size);
}

test "a reset uni stream sends RESET_STREAM" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const ss = try conn.streams.openUniStream();
    try ss.writeData("hello");
    _ = ss.popStreamFrame(100).?;
    ss.reset(9);
    conn.queueFlowControlUpdates();

    try std.testing.expectEqual(@as(?u64, 5), drainPendingFor(&conn, ss.stream_id).reset_final_size);
}

test "a uni stream blocked on MAX_STREAM_DATA sends STREAM_DATA_BLOCKED" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.streams.setPeerInitialMaxStreamData(1000, 1000, 4);

    const ss = try conn.streams.openUniStream();
    try ss.writeData("0123456789");
    _ = ss.popStreamFrame(100).?;
    conn.queueFlowControlUpdates();

    try std.testing.expectEqual(@as(?u64, 4), drainPendingFor(&conn, ss.stream_id).blocked_limit);
}

test "STOP_SENDING on a uni stream we opened stops it and keeps the connection" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const ss = try conn.streams.openUniStream();
    try ss.writeData("hello");
    try conn.processFrame(&.{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = 9 } }, .application, 0, rng.random());

    try std.testing.expect(conn.local_err == null);
    try std.testing.expectEqual(@as(?u64, 9), ss.peer_stop_sending);
    try std.testing.expectEqual(@as(?u64, 9), ss.reset_err);
}

/// Pop `ss`'s next STREAM frame and record it as sent in a 1-RTT packet, the
/// way the packer does. Returns the packet number.
fn sendStreamFrameOf(conn: *Connection, ss: *stream_mod.SendStream, random: std.Random) !u64 {
    const f = ss.popStreamFrame(1 << 16).?.stream;
    var pkt: ack_handler.SentPacket = .{
        .pn = conn.pkt_handler.nextPacketNumber(.application, random),
        .time_sent = 0,
        .size = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };
    pkt.addStreamFrame(.{ .stream_id = f.stream_id, .offset = f.offset, .length = f.length, .fin = f.fin });
    try conn.pkt_handler.onPacketSent(pkt);
    return pkt.pn;
}

fn ackPacket(conn: *Connection, pn: u64, random: std.Random) !void {
    try conn.processFrame(&.{ .ack = .{ .largest_ack = pn, .ack_delay = 0, .first_ack_range = 0 } }, .application, std.time.ns_per_s, random);
}

test "a uni stream is reclaimed once its FIN is acked" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const ss = try conn.streams.openUniStream();
    const id = ss.stream_id;
    try ss.writeData("hello");
    ss.close();
    const pn = try sendStreamFrameOf(&conn, ss, rng.random());

    // Sent is not received: a lost FIN would need the buffer back.
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.send_streams.get(id) != null);

    try ackPacket(&conn, pn, rng.random());
    conn.streams.drainDisposalQueue();
    try std.testing.expectEqual(@as(u32, 0), conn.streams.send_streams.count());
}

test "a reset uni stream is reclaimed once its RESET_STREAM is queued" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    // One we reset, one the peer stopped.
    const ours = try conn.streams.openUniStream();
    const theirs = try conn.streams.openUniStream();
    try ours.writeData("hello");
    try theirs.writeData("hello");
    ours.reset(9);
    try conn.processFrame(&.{ .stop_sending = .{ .stream_id = theirs.stream_id, .error_code = 7 } }, .application, 0, rng.random());

    // Until RESET_STREAM is out, the stream is the only record that it is owed.
    conn.streams.drainDisposalQueue();
    try std.testing.expectEqual(@as(u32, 2), conn.streams.send_streams.count());

    conn.queueFlowControlUpdates();
    conn.streams.drainDisposalQueue();
    try std.testing.expectEqual(@as(u32, 0), conn.streams.send_streams.count());
}

test "a pinned uni stream outlives the peer's STOP_SENDING" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const ss = try conn.streams.openUniStream();
    ss.pinned = true;
    try conn.processFrame(&.{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = 7 } }, .application, 0, rng.random());
    conn.queueFlowControlUpdates();
    conn.streams.drainDisposalQueue();

    try std.testing.expectEqual(@as(?*stream_mod.SendStream, ss), conn.streams.send_streams.get(ss.stream_id));
}

test "a closed bidi stream is reclaimed when its last byte is acked after the close" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    // Both FINs cross and the send pass marks the stream closed; only then
    // does the ACK for our last byte arrive.
    var req = "GET".*;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = req.len, .data = &req, .fin = true } }, .application, 0, rng.random());
    const s = conn.streams.getStream(0).?;
    try s.send.writeData("response");
    s.send.close();
    const pn = try sendStreamFrameOf(&conn, &s.send, rng.random());

    conn.queueFlowControlUpdates();
    conn.streams.drainDisposalQueue();
    try std.testing.expect(s.closed_for_gc);
    try std.testing.expect(conn.streams.getStream(0) != null);

    try ackPacket(&conn, pn, rng.random());
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.getStream(0) == null);
}

test "a bidi stream whose FIN arrives ahead of a hole outlives our acked FIN" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    // The request's tail and FIN overtake its head.
    var tail = "world".*;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 5, .length = tail.len, .data = &tail, .fin = true } }, .application, 0, rng.random());
    const s = conn.streams.getStream(0).?;
    try s.send.writeData("response");
    s.send.close();
    const pn = try sendStreamFrameOf(&conn, &s.send, rng.random());
    try ackPacket(&conn, pn, rng.random());
    conn.queueFlowControlUpdates();
    conn.streams.drainDisposalQueue();
    try std.testing.expect(!s.closed_for_gc);
    try std.testing.expect(conn.streams.getStream(0) != null);

    // The head's retransmission still finds the stream, and completes it.
    var head = "hello".*;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = head.len, .data = &head, .fin = false } }, .application, 0, rng.random());
    try std.testing.expect(s.closed_for_gc);
    var body: [10]u8 = undefined;
    var n: usize = 0;
    while (s.recv.read()) |d| {
        @memcpy(body[n..][0..d.len], d);
        n += d.len;
        std.testing.allocator.free(d);
    }
    try std.testing.expectEqualStrings("helloworld", body[0..n]);
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.getStream(0) == null);
}

test "a PTO with only a uni stream's tail in flight resends the tail" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.last_packet_received_time = test_now;
    conn.last_packet_sent_time = test_now;

    // The tail went out long ago, and no later ACK will declare it lost.
    const ss = try conn.streams.openUniStream();
    try ss.writeData("tail");
    ss.close();
    _ = try sendStreamFrameOf(&conn, ss, rng.random());

    try conn.onTimeout(test_now, rng.random());
    try std.testing.expect(ss.hasRetransmitData());
}

test "a PTO probe resends a uni stream's unacked tail" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.handshake_confirmed = true;

    const ss = try conn.streams.openUniStream();
    try ss.writeData("hello");
    ss.close();
    _ = ss.popStreamFrame(100).?;
    try std.testing.expect(!ss.hasRetransmitData());

    try std.testing.expect(conn.queueStreamPtoRetransmissions());
    try std.testing.expect(ss.hasRetransmitData());
}

test "late frames for a local stream we reclaimed are dropped, not a STREAM_STATE_ERROR" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const id = (try conn.streams.openBidiStream()).stream_id;
    _ = conn.streams.queueDisposal(id);
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.getStream(id) == null);

    // Our ACK of the peer's FIN was lost, so it retransmits; STOP_SENDING and
    // MAX_STREAM_DATA can cross the reclamation the same way.
    var payload = "late".*;
    try conn.processFrame(&.{ .stream = .{ .stream_id = id, .offset = 0, .length = payload.len, .data = &payload, .fin = true } }, .application, 0, rng.random());
    try conn.processFrame(&.{ .stop_sending = .{ .stream_id = id, .error_code = 1 } }, .application, 0, rng.random());
    try conn.processFrame(&.{ .max_stream_data = .{ .stream_id = id, .max = 1 << 20 } }, .application, 0, rng.random());
    try std.testing.expect(conn.local_err == null);
}

test "frames naming a local stream never opened are a STREAM_STATE_ERROR" {
    var rng = TestRandom{};
    var payload = "x".*;
    // Server-initiated bidi 1 and uni 3; testConnection has opened neither.
    const frames = [_]Frame{
        .{ .stream = .{ .stream_id = 1, .offset = 0, .length = 1, .data = &payload, .fin = false } },
        .{ .stop_sending = .{ .stream_id = 3, .error_code = 1 } },
        .{ .max_stream_data = .{ .stream_id = 3, .max = 100 } },
    };
    for (&frames) |*f| {
        var conn = testConnection(std.testing.allocator);
        defer conn.deinit();
        try std.testing.expectError(error.ProtocolViolation, conn.processFrame(f, .application, 0, rng.random()));
    }
}

test "sendCapacity counts bytes written on every stream against MAX_DATA" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.conn_flow_ctrl.base.send_window = 1000;

    const a = try conn.streams.openUniStream();
    const b = try conn.streams.openBidiStream();
    try a.writeData(&([_]u8{'a'} ** 300));
    try b.send.writeData(&([_]u8{'b'} ** 500));
    try std.testing.expectEqual(@as(u64, 200), conn.sendCapacity());
    try std.testing.expectEqual(@as(?u64, 200), conn.streamSendCapacity(a.stream_id));

    // Sending spends credit the write already counted.
    _ = a.popStreamFrame(100).?;
    try std.testing.expectEqual(@as(u64, 200), conn.sendCapacity());

    // A write past it is buffered, not refused.
    try b.send.writeData(&([_]u8{'b'} ** 400));
    try std.testing.expectEqual(@as(u64, 0), conn.sendCapacity());

    try conn.processFrame(&.{ .max_data = 2000 }, .application, 0, rng.random());
    try std.testing.expectEqual(@as(u64, 800), conn.sendCapacity());
}

test "streamSendCapacity is bounded by MAX_STREAM_DATA and ends with the stream" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.streams.setPeerInitialMaxStreamData(1000, 1000, 64);
    conn.conn_flow_ctrl.base.send_window = 1 << 20;

    const ss = try conn.streams.openUniStream();
    try ss.writeData(&([_]u8{'x'} ** 40));
    try std.testing.expectEqual(@as(?u64, 24), conn.streamSendCapacity(ss.stream_id));

    try conn.processFrame(&.{ .max_stream_data = .{ .stream_id = ss.stream_id, .max = 100 } }, .application, 0, rng.random());
    try std.testing.expectEqual(@as(?u64, 60), conn.streamSendCapacity(ss.stream_id));

    ss.close();
    try std.testing.expectEqual(@as(?u64, 0), conn.streamSendCapacity(ss.stream_id));
    try std.testing.expectEqual(@as(?u64, null), conn.streamSendCapacity(ss.stream_id + 4));
}

test "a reset gives back the credit its unsent bytes had claimed" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);
    conn.conn_flow_ctrl.base.send_window = 1000;

    const ss = try conn.streams.openUniStream();
    try ss.writeData(&([_]u8{'x'} ** 600));
    _ = ss.popStreamFrame(100).?;
    try std.testing.expectEqual(@as(u64, 400), conn.sendCapacity());

    // Only what went out stays spent; that is the final size RESET_STREAM names.
    try conn.processFrame(&.{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = 1 } }, .application, 0, rng.random());
    try std.testing.expectEqual(@as(u64, 900), conn.sendCapacity());

    // Nothing written after the reset can go, so none of it counts.
    try ss.writeData("late");
    try std.testing.expectEqual(@as(u64, 900), conn.sendCapacity());
}

test "a handshake-space PTO with nothing to resend still probes" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    conn.handshake_confirmed = false;
    conn.last_packet_received_time = test_now;
    conn.last_packet_sent_time = test_now;

    // Initial space: an ack-eliciting packet went out long ago and was acked,
    // so nothing is in flight and there is nothing queued to resend.
    const initial = &conn.pkt_handler.sent[@intFromEnum(ack_handler.EncLevel.initial)];
    initial.last_ack_eliciting_sent_time = test_now - 10 * std.time.ns_per_s;

    try conn.onTimeout(test_now, rng.random());

    // Without a probe, last_ack_eliciting_sent_time never moves, the deadline
    // stays expired, and this fires again on every tick forever.
    const f = conn.pending_frames.pop();
    try std.testing.expect(f != null);
    try std.testing.expect(f.? == .ping);
}

test "an ACK for a packet number never sent is a PROTOCOL_VIOLATION" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Two packets sent: 0 and 1. Acking 1 is fine, acking 2 is not.
    _ = conn.pkt_handler.nextPacketNumber(.application, rng.random());
    _ = conn.pkt_handler.nextPacketNumber(.application, rng.random());
    try conn.processFrame(&.{ .ack = .{ .largest_ack = 1, .ack_delay = 0, .first_ack_range = 1, .ack_range_count = 0 } }, .application, 0, rng.random());
    try std.testing.expect(conn.local_err == null);

    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .ack = .{ .largest_ack = 2, .ack_delay = 0, .first_ack_range = 0, .ack_range_count = 0 } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.protocol_violation)), conn.local_err.?.code);
}

test "an ACK_ECN for a packet number never sent is a PROTOCOL_VIOLATION" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .ack_ecn = .{
        .largest_ack = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_range_count = 0,
        .ecn_ect0 = 0,
        .ecn_ect1 = 0,
        .ecn_ce = 0,
    } }, .initial, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.protocol_violation)), conn.local_err.?.code);
}

test "STREAM data past a bidi stream's window is a FLOW_CONTROL_ERROR" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);
    conn.streams.local_max_stream_data_bidi_remote = 100;

    var ok = [_]u8{'a'} ** 100;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = ok.len, .data = &ok, .fin = false } }, .application, 0, rng.random());

    var over = [_]u8{'b'};
    try std.testing.expectError(error.FlowControlError, conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 100, .length = 1, .data = &over, .fin = false } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.flow_control_error)), conn.local_err.?.code);
}

test "STREAM data past a uni stream's window is a FLOW_CONTROL_ERROR" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);
    conn.streams.local_max_stream_data_uni = 100;

    // A far offset alone is enough: no byte below it has to arrive first.
    var over = [_]u8{'b'};
    try std.testing.expectError(error.FlowControlError, conn.processFrame(&.{ .stream = .{ .stream_id = 2, .offset = 100, .length = 1, .data = &over, .fin = false } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.flow_control_error)), conn.local_err.?.code);
}

test "RESET_STREAM with a final size past the stream window is a FLOW_CONTROL_ERROR" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);
    conn.streams.local_max_stream_data_uni = 100;

    try std.testing.expectError(error.FlowControlError, conn.processFrame(&.{ .reset_stream = .{ .stream_id = 2, .error_code = 0, .final_size = 101 } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.flow_control_error)), conn.local_err.?.code);
}

test "a peer uni stream keeps getting MAX_STREAM_DATA past its initial window" {
    var rng = TestRandom{};
    const alloc = std.testing.allocator;
    var conn = testConnection(alloc);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    // The peer honours both windows, as a real one would; if we never raise
    // them it runs out of credit below `total` and the test fails.
    var stream_max: u64 = conn.streams.local_max_stream_data_uni;
    var conn_max: u64 = conn.conn_flow_ctrl.base.receive_window;
    const total: u64 = 3 * 1024 * 1024;
    var chunk = [_]u8{'u'} ** 1200;
    var off: u64 = 0;
    var read_total: u64 = 0;
    while (off < total) {
        const limit = @min(stream_max, conn_max);
        if (off >= limit) return error.TestUnexpectedResult; // stalled
        const n: usize = @intCast(@min(chunk.len, limit - off, total - off));
        try conn.processFrame(&.{ .stream = .{ .stream_id = 2, .offset = off, .length = n, .data = chunk[0..n], .fin = false } }, .application, 0, rng.random());
        off += n;

        const rs = conn.streams.recv_streams.get(2).?;
        while (rs.read()) |d| {
            read_total += d.len;
            alloc.free(d);
        }
        conn.queueFlowControlUpdates();
        while (conn.pending_frames.pop()) |f| switch (f) {
            .max_stream_data => |m| if (m.stream_id == 2) {
                stream_max = @max(stream_max, m.max);
            },
            .max_data => |m| conn_max = @max(conn_max, m),
            else => {},
        };
    }
    try std.testing.expectEqual(total, read_total);
    try std.testing.expect(stream_max > conn.streams.local_max_stream_data_uni);
}

test "a closing connection resends its close with exponential backoff, not per packet" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.close(0, "", test_now);
    // As if the first CONNECTION_CLOSE already went out.
    conn.close_pkt_len = 32;
    @memset(conn.close_pkt_buf[0..32], 0xcc);

    var header: packet.Header = .{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .one_rtt,
        .dcid = &.{},
        .scid = &.{},
    };
    var junk = [_]u8{0} ** 8;
    var out: [1500]u8 = undefined;
    var resent: usize = 0;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var fbs = io.fixedBufferStream(&junk);
        try conn.recv(&header, &fbs, .{ .to = undefined, .from = undefined }, test_now, rng.random());
        if (try conn.sendAt(&out, test_now, rng.random()) > 0) resent += 1;
    }
    // Packets 1, 2, 4, ..., 64.
    try std.testing.expectEqual(@as(usize, 7), resent);
}

/// Record `frames` as carried by a packet sent now, then send and ack three
/// more so packet-threshold loss detection declares the first one lost.
fn loseControlFrames(conn: *Connection, frames: []const frame_mod.PendingControlFrame, random: std.Random) !void {
    const now: i64 = 1_000_000_000;
    var lost: ack_handler.SentPacket = .{
        .pn = conn.pkt_handler.nextPacketNumber(.application, random),
        .time_sent = now,
        .size = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };
    for (frames) |f| {
        lost.control_frames[lost.control_frame_count] = ack_handler.SentControlFrame.from(f).?;
        lost.control_frame_count += 1;
    }
    try conn.pkt_handler.onPacketSent(lost);
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        try conn.pkt_handler.onPacketSent(.{
            .pn = conn.pkt_handler.nextPacketNumber(.application, random),
            .time_sent = now,
            .size = 100,
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });
    }
    const largest = conn.pkt_handler.next_pn[@intFromEnum(ack_handler.EncLevel.application)] - 1;
    try conn.processFrame(&.{ .ack = .{ .largest_ack = largest, .ack_delay = 0, .first_ack_range = 2, .ack_range_count = 0 } }, .application, now + 1_000_000, random);
}

test "a lost RESET_STREAM is rebuilt from its record after the uni stream is freed" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    const ss = try conn.streams.openUniStream();
    const id = ss.stream_id;
    try ss.writeData("hello");
    _ = ss.popStreamFrame(100).?;
    ss.reset(9);
    conn.queueFlowControlUpdates();
    var queued: ?frame_mod.PendingControlFrame = null;
    while (conn.pending_frames.pop()) |f| {
        if (f == .reset_stream) queued = f;
    }
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.send_streams.get(id) == null);

    try loseControlFrames(&conn, &.{queued.?}, rng.random());
    try std.testing.expectEqual(@as(?u64, 5), drainPendingFor(&conn, id).reset_final_size);
}

test "a lost MAX_STREAM_DATA is resent at the current window, not the lost one" {
    var rng = TestRandom{};
    const alloc = std.testing.allocator;
    var conn = testConnection(alloc);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);
    conn.streams.local_max_stream_data_uni = 1000;

    var data = [_]u8{'x'} ** 1000;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 2, .offset = 0, .length = data.len, .data = &data, .fin = false } }, .application, 0, rng.random());
    const rs = conn.streams.recv_streams.get(2).?;
    while (rs.read()) |d| alloc.free(d);
    conn.queueFlowControlUpdates();
    var lost_frame: ?frame_mod.PendingControlFrame = null;
    while (conn.pending_frames.pop()) |f| {
        if (f == .max_stream_data) lost_frame = f;
    }
    try std.testing.expectEqual(@as(u64, 2000), lost_frame.?.max_stream_data.max);
    rs.receive_window = 2500; // raised again meanwhile

    try loseControlFrames(&conn, &.{lost_frame.?}, rng.random());
    var resent: ?u64 = null;
    while (conn.pending_frames.pop()) |f| {
        if (f == .max_stream_data) resent = f.max_stream_data.max;
    }
    try std.testing.expectEqual(@as(?u64, 2500), resent);
}

test "a lost STOP_SENDING is not resent once the stream's final size is known" {
    var rng = TestRandom{};
    const alloc = std.testing.allocator;
    var conn = testConnection(alloc);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var data = [_]u8{'x'} ** 10;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = data.len, .data = &data, .fin = false } }, .application, 0, rng.random());
    const stop: frame_mod.PendingControlFrame = .{ .stop_sending = .{ .stream_id = 0, .error_code = 3 } };

    try loseControlFrames(&conn, &.{stop}, rng.random());
    var count: usize = 0;
    while (conn.pending_frames.pop()) |f| {
        if (f == .stop_sending) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);

    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 10, .length = 0, .data = &.{}, .fin = true } }, .application, 0, rng.random());
    try loseControlFrames(&conn, &.{stop}, rng.random());
    while (conn.pending_frames.pop()) |f| try std.testing.expect(f != .stop_sending);
}

test "a RESET_STREAM that finds the queue full is queued on a later pass" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxStreams(10, 10);

    while (conn.pending_frames.hasRoomFor(1)) conn.pending_frames.push(.{ .path_challenge = .{0} ** 8 });
    const s = try conn.streams.openBidiStream();
    s.send.reset(4);
    conn.queueFlowControlUpdates();
    try std.testing.expect(!s.send.reset_stream_sent);

    _ = conn.pending_frames.pop();
    conn.queueFlowControlUpdates();
    try std.testing.expect(s.send.reset_stream_sent);
    try std.testing.expectEqual(@as(?u64, 0), drainPendingFor(&conn, s.stream_id).reset_final_size);
}

test "a full window of unread in-order data is not mistaken for reassembly gaps" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    conn.conn_flow_ctrl.base.receive_window = 16 << 20;

    // What a paused consumer leaves behind: 5000 frames, far more than the
    // gap cap, none of them out of order.
    var payload = [_]u8{'x'} ** 1200;
    var i: u64 = 0;
    while (i < 5000) : (i += 1) {
        try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = i * payload.len, .length = payload.len, .fin = false, .data = &payload } }, .application, 0, rng.random());
    }
    try std.testing.expect(conn.local_err == null);
}

test "a paused stream's window arriving reordered is not mistaken for reassembly gaps" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);
    conn.conn_flow_ctrl.base.receive_window = 16 << 20;

    // 5000 frames, each delayed by up to 32 slots of jitter; none lost.
    const n = 5000;
    var order: [n]struct { idx: u64, arrival: u64 } = undefined;
    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const shuffle = prng.random();
    for (&order, 0..) |*o, k| o.* = .{ .idx = k, .arrival = k + shuffle.uintLessThan(u64, 32) };
    std.mem.sort(@TypeOf(order[0]), &order, {}, struct {
        fn lt(_: void, a: @TypeOf(order[0]), b: @TypeOf(order[0])) bool {
            return a.arrival < b.arrival;
        }
    }.lt);

    var payload: [1200]u8 = undefined;
    for (order) |o| {
        const offset = o.idx * payload.len;
        for (&payload, 0..) |*b, k| b.* = @intCast((offset + @as(u64, k)) % 251);
        try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = offset, .length = payload.len, .fin = false, .data = &payload } }, .application, 0, rng.random());
    }
    try std.testing.expect(conn.local_err == null);

    const s = conn.streams.getStream(0).?;
    var got: u64 = 0;
    while (s.recv.read()) |chunk| {
        defer std.testing.allocator.free(chunk);
        for (chunk, 0..) |v, k| {
            const expected: u8 = @intCast((got + @as(u64, k)) % 251);
            try std.testing.expectEqual(expected, v);
        }
        got += chunk.len;
    }
    try std.testing.expectEqual(@as(u64, n * payload.len), got);
}

test "NEW_CONNECTION_ID: a new CID does not replace the DCID in use" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    var before: [20]u8 = undefined;
    const before_len = conn.packer.dcid_len;
    @memcpy(before[0..before_len], conn.packer.dcid_buf[0..before_len]);
    var cid = [_]u8{0xcd} ** 8;
    try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = 1, .retire_prior_to = 0, .conn_id = &cid, .stateless_reset_token = .{0} ** 16 } }, .application, 0, rng.random());
    try std.testing.expectEqualSlices(u8, before[0..before_len], conn.packer.dcid_buf[0..conn.packer.dcid_len]);
    try std.testing.expectEqual(@as(u64, 0), conn.dcid_seq);

    // Retiring seq 0 is what moves us.
    var cid2 = [_]u8{0xef} ** 8;
    try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = 2, .retire_prior_to = 1, .conn_id = &cid2, .stateless_reset_token = .{0} ** 16 } }, .application, 0, rng.random());
    try std.testing.expectEqualSlices(u8, &cid, conn.packer.dcid_buf[0..conn.packer.dcid_len]);
    try std.testing.expectEqual(@as(u64, 1), conn.dcid_seq);
}

test "NEW_CONNECTION_ID: a huge Retire Prior To retires only the CIDs we hold" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    var cid = [_]u8{0xab} ** 8;
    const top: u64 = (1 << 62) - 1;
    try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = top, .retire_prior_to = top, .conn_id = &cid, .stateless_reset_token = .{0} ** 16 } }, .application, 0, rng.random());
    try std.testing.expect(conn.local_err == null);
    try std.testing.expectEqual(top, conn.active_cid_seq);
    // Only the handshake DCID (seq 0) was ever issued to us.
    try std.testing.expectEqualSlices(u64, &.{0}, conn.retiring_cids.items);
    try std.testing.expectEqual(@as(usize, 0), conn.control_retry.items.len);
    try std.testing.expectEqual(@as(u8, 1), conn.pending_frames.len);
    try std.testing.expect(conn.peer_cid_pool.contains(top));
}

test "NEW_CONNECTION_ID: unacked retirements past twice the limit close the connection" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    var cid = [_]u8{0xab} ** 8;
    var token = [_]u8{0} ** 16;
    const limit = conn.local_params.active_connection_id_limit;
    try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = 100, .retire_prior_to = 100, .conn_id = &cid, .stateless_reset_token = .{0} ** 16 } }, .application, 0, rng.random());
    // Late CIDs below Retire Prior To are retired on arrival; a retransmit
    // of one is not retired twice.
    var seq: u64 = 1;
    while (seq < 2 * limit) : (seq += 1) {
        std.mem.writeInt(u64, &cid, seq, .big);
        std.mem.writeInt(u64, token[8..16], seq, .big);
        try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = seq, .retire_prior_to = 0, .conn_id = &cid, .stateless_reset_token = token } }, .application, 0, rng.random());
        try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = seq, .retire_prior_to = 0, .conn_id = &cid, .stateless_reset_token = token } }, .application, 0, rng.random());
    }
    try std.testing.expect(conn.local_err == null);
    try std.testing.expectEqual(@as(usize, @intCast(2 * limit)), conn.retiring_cids.items.len);

    // An ACK frees a slot.
    conn.onRetireCidAcked(0, 0);
    std.mem.writeInt(u64, &cid, 50, .big);
    std.mem.writeInt(u64, token[8..16], 50, .big);
    try conn.processFrame(&.{ .new_connection_id = .{ .seq_num = 50, .retire_prior_to = 0, .conn_id = &cid, .stateless_reset_token = token } }, .application, 0, rng.random());
    try std.testing.expect(conn.local_err == null);
    try std.testing.expectEqual(@as(usize, @intCast(2 * limit)), conn.retiring_cids.items.len);

    std.mem.writeInt(u64, &cid, 51, .big);
    std.mem.writeInt(u64, token[8..16], 51, .big);
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&.{ .new_connection_id = .{ .seq_num = 51, .retire_prior_to = 0, .conn_id = &cid, .stateless_reset_token = token } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.connection_id_limit_error)), conn.local_err.?.code);
    try std.testing.expectEqual(State.closing, conn.state);
}

test "connection flow control: the window bounds the sum over streams" {
    var rng = TestRandom{};
    const alloc = std.testing.allocator;
    var conn = testConnection(alloc);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(100, 100);
    const win = conn.conn_flow_ctrl.base.receive_window;
    const buf = try alloc.alloc(u8, @intCast(win / 2));
    defer alloc.free(buf);
    @memset(buf, 'z');

    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = buf.len, .data = buf, .fin = false } }, .application, 0, rng.random());
    try conn.processFrame(&.{ .stream = .{ .stream_id = 4, .offset = 0, .length = buf.len, .data = buf, .fin = false } }, .application, 0, rng.random());
    // A retransmission of counted bytes charges nothing.
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = buf.len, .data = buf, .fin = false } }, .application, 0, rng.random());
    try std.testing.expectEqual(win, conn.conn_flow_ctrl.base.highest_received);
    try std.testing.expect(conn.local_err == null);

    // Each stream is well inside its own window, but the sum is not.
    try std.testing.expectError(error.FlowControlError, conn.processFrame(&.{ .stream = .{ .stream_id = 8, .offset = 0, .length = 1, .data = buf[0..1], .fin = false } }, .application, 0, rng.random()));
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.flow_control_error)), conn.local_err.?.code);
}

test "connection flow control: MAX_DATA is granted for data read, not data received" {
    var rng = TestRandom{};
    const alloc = std.testing.allocator;
    var conn = testConnection(alloc);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(100, 100);
    const win = conn.conn_flow_ctrl.base.receive_window;
    const buf = try alloc.alloc(u8, @intCast(win));
    defer alloc.free(buf);
    @memset(buf, 'z');

    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = buf.len, .data = buf, .fin = false } }, .application, 0, rng.random());
    conn.queueFlowControlUpdates();
    try std.testing.expectEqual(win, conn.conn_flow_ctrl.base.receive_window);
    try std.testing.expectEqual(@as(u64, 0), conn.conn_flow_ctrl.base.bytes_read);

    const rs = &conn.streams.getStream(0).?.recv;
    while (rs.read()) |d| alloc.free(d);
    conn.queueFlowControlUpdates();
    try std.testing.expectEqual(win, conn.conn_flow_ctrl.base.bytes_read);
    try std.testing.expect(conn.conn_flow_ctrl.base.receive_window > win);
}

test "connection flow control: a repeated RESET_STREAM counts its final size once" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.streams.setMaxIncomingStreams(10, 10);

    var payload = "0123456789".*;
    try conn.processFrame(&.{ .stream = .{ .stream_id = 0, .offset = 0, .length = payload.len, .data = &payload, .fin = false } }, .application, 0, rng.random());
    const reset: Frame = .{ .reset_stream = .{ .stream_id = 0, .error_code = 1, .final_size = 1000 } };
    try conn.processFrame(&reset, .application, 0, rng.random());
    try conn.processFrame(&reset, .application, 0, rng.random());
    conn.queueFlowControlUpdates();
    conn.queueFlowControlUpdates();

    try std.testing.expectEqual(@as(u64, 1000), conn.conn_flow_ctrl.base.highest_received);
    try std.testing.expectEqual(@as(u64, 1000), conn.conn_flow_ctrl.base.bytes_read);
}

test "a server with no token key issues no NEW_TOKEN at all" {
    var rng = TestRandom{};
    const local = address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443);
    const remote = address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345);
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const header = packet.Header{
        .packet_type = .initial,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .dcid = &dcid,
        .scid = &scid,
        .token = &.{},
        .packet_number = 0,
        .packet_number_len = 1,
        .remainder_len = 0,
    };

    const keyed = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(keyed);
    try Connection.acceptInto(
        keyed,
        std.testing.allocator,
        header,
        local,
        remote,
        true,
        .{ .token_key = @splat(0x11) },
        null,
        null,
        null,
        test_now,
        rng.random(),
    );
    defer keyed.deinit();
    try std.testing.expect(keyed.newTokenFrame(test_now, rng.random()) != null);

    // A connection with no token key has no secret to seal one with, and the
    // zero key it would otherwise use is a key every reader of the wire has:
    // a token sealed under it proves nothing and outlives the connection that
    // issued it. No token, no frame.
    const unkeyed = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(unkeyed);
    try Connection.acceptInto(
        unkeyed,
        std.testing.allocator,
        header,
        local,
        remote,
        true,
        .{},
        null,
        null,
        null,
        test_now,
        rng.random(),
    );
    defer unkeyed.deinit();
    try std.testing.expectEqual(@as(?[16]u8, null), unkeyed.token_key);
    try std.testing.expect(unkeyed.newTokenFrame(test_now, rng.random()) == null);
}

test "handleDatagram: a version negotiation packet ends the walk, not its length field" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // RFC 9000 §6.1: long header, version zero, both connection ids, then the
    // versions. There is no Length field, so there is nothing in the packet
    // that says how long it is — the whole datagram is the packet, and a
    // server ignores it (a client is the only end that acts on one).
    const local = address.Address.initIpv4(.{ 0, 0, 0, 0 }, 443);
    const remote = address.Address.initIpv4(.{ 192, 168, 1, 100 }, 12345);
    var datagram = [_]u8{0} ** 64;
    datagram[0] = 0xc0;
    std.mem.writeInt(u32, datagram[1..5], 0, .big);
    datagram[5] = 8;
    @memcpy(datagram[6..14], conn.dcid[0..conn.dcid_len]);
    datagram[14] = 8;
    @memcpy(datagram[15..23], conn.scid[0..conn.scid_len]);
    std.mem.writeInt(u32, datagram[23..27], 0x1a2a3a4a, .big);
    std.mem.writeInt(u32, datagram[27..31], 0x5a5a5a5a, .big);

    conn.handleDatagram(&datagram, .{
        .to = local,
        .from = remote,
        .datagram_size = datagram.len,
    }, test_now, rng.random());

    // Ignored, so not closed, not acknowledged and not counted as received:
    // the packet was read as a packet and nothing in it was acted on.
    try std.testing.expect(!conn.isClosed());
    try std.testing.expectEqual(@as(u64, 0), conn.getStats().packets_received);
}

test "sendAt: a closing packet waits for a buffer that can hold it" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // A close packet the cache can hold is re-sent on the trigger. A caller
    // whose buffer is shorter than that has not refused the packet — it has
    // asked for one it cannot hold, and the answer is a retry, not a truncated
    // copy and not a consumed trigger.
    conn.state = .closing;
    conn.close_pkt_len = conn.close_pkt_buf.len;
    @memset(&conn.close_pkt_buf, 0xaa);
    conn.needs_close_retransmit = true;

    var short: [16]u8 = undefined;
    @memset(&short, 0x5a);
    try std.testing.expectEqual(@as(usize, 0), try conn.sendAt(&short, test_now, rng.random()));
    // Nothing was written and the trigger stands, so the next pass with room
    // still has the packet to send.
    try std.testing.expectEqualSlices(u8, &[_]u8{0x5a} ** 16, &short);
    try std.testing.expect(conn.needs_close_retransmit);

    var roomy: [300]u8 = undefined;
    const len = try conn.sendAt(&roomy, test_now, rng.random());
    try std.testing.expectEqual(@as(usize, conn.close_pkt_len), len);
    try std.testing.expectEqualSlices(u8, &conn.close_pkt_buf, roomy[0..len]);
    try std.testing.expect(!conn.needs_close_retransmit);
}

test "sendAt: a closing flight longer than the cache is rebuilt, not replayed truncated" {
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // A closing connection sends the CRYPTO data it still owes at the same
    // time (RFC 9000 §10.2.3), so its flight is a whole datagram and not one
    // CONNECTION_CLOSE packet: here a full Initial budget's worth.
    const keys = try quic_crypto.deriveInitialKeyMaterial(
        conn.dcid[0..conn.dcid_len],
        protocol.SUPPORTED_VERSIONS[0],
        true,
    );
    conn.pkt_num_spaces[0].crypto_seal = keys[1];
    try conn.crypto_streams.getStream(0).writeData("x" ** 4096);
    conn.close(7, "", test_now);

    var first: [1500]u8 = undefined;
    const first_len = try conn.sendAt(&first, test_now, rng.random());
    try std.testing.expect(first_len > conn.close_pkt_buf.len);

    // A prefix of a packet is not a packet: the CONNECTION_CLOSE inside it
    // carries a Length field covering bytes that never arrived, which is a
    // packet error (RFC 9000 §12.2) rather than the close the peer is owed.
    // So a flight too long for the cache is not cached at all, and 0 says the
    // next pass rebuilds it.
    try std.testing.expectEqual(@as(u16, 0), conn.close_pkt_len);

    // The next trigger rebuilds the flight whole.
    conn.needs_close_retransmit = true;
    var second: [1500]u8 = undefined;
    const second_len = try conn.sendAt(&second, test_now, rng.random());
    try std.testing.expect(second_len > conn.close_pkt_buf.len);
    try std.testing.expectEqual(@as(u16, 0), conn.close_pkt_len);
    try std.testing.expect(!std.mem.eql(u8, first[0..first_len], second[0..second_len]));
}

/// One `sendAt` over a flight with frames in it, under whatever the allocator
/// answers.
fn sendAtUnderAnyRefusal(gpa: std.mem.Allocator) !void {
    var rng = TestRandom{};
    var conn = testConnection(gpa);
    defer conn.deinit();
    // A client, because a server's anti-amplification budget stops a
    // connection that has received nothing at all before the packer is asked
    // for anything — and the pass under test has to reach the packer.
    conn.is_server = false;
    conn.packer.is_server = false;
    const keys = try quic_crypto.deriveInitialKeyMaterial(
        conn.dcid[0..conn.dcid_len],
        protocol.SUPPORTED_VERSIONS[0],
        false,
    );
    conn.pkt_num_spaces[0].crypto_seal = keys[1];
    try conn.crypto_streams.getStream(0).writeData("the CRYPTO the packet is built from");
    var out: [1500]u8 = undefined;

    if (conn.sendAt(&out, test_now, rng.random())) |written| {
        // The run that answered everything: one packet, recorded.
        try std.testing.expect(written > 0);
        try std.testing.expectEqual(@as(usize, 1), conn.pkt_handler.sent[0].sent_packets.count());
        return;
    } else |err| {
        try std.testing.expectEqual(error.OutOfMemory, err);
        // The packer had already taken the CRYPTO off its stream and encrypted
        // it by the time the recording allocates, so a refusal here is a
        // connection holding a flight it consumed and will never send. It
        // cannot be left open: RFC 9000 §10.2 closes it with an internal error,
        // and only then does the failure reach the caller.
        try std.testing.expect(conn.state == .closing);
        try std.testing.expect(!conn.local_err.?.is_app);
        try std.testing.expectEqual(
            @as(u64, @intFromEnum(TransportError.internal_error)),
            conn.local_err.?.code,
        );
        return error.OutOfMemory;
    }
}

test "sendAt: a refused packet recording closes the connection with the frames already gone" {
    // `packSinglePacket` documents that its two errors close the connection,
    // because the frames it had taken are lost with them — but the calls that
    // run it propagate `error.OutOfMemory` bare, leaving an open connection
    // that believes it sent a flight it swallowed. The sweep is what says every
    // allocation in the pass is covered, the one inside the recording
    // included.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, sendAtUnderAnyRefusal, .{});
}

/// A Retry as a peer sends it: the packet with its integrity tag, and the
/// header the connection reads it from. `buf` has to outlive both.
fn retryPacket(
    buf: []u8,
    conn: *const Connection,
    new_scid: []u8,
    token: []u8,
) !struct { header: packet.Header, raw: []const u8 } {
    var fbs = io.fixedBufferStream(buf);
    const client_header = packet.Header{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = conn.odcid_buf[0..conn.odcid_len],
        .scid = conn.scid[0..conn.scid_len],
    };
    try packet.retry(client_header, new_scid, token, &fbs);
    const raw = buf[0..fbs.seek];
    var parse_fbs = io.fixedBufferStream(raw);
    return .{ .header = try packet.Header.parse(&parse_fbs, 0), .raw = raw };
}

test "handleRetryPacket: a Retry whose token cannot be carried forward is refused whole" {
    // Three Retries this connection cannot act on, all with a valid integrity
    // tag and all refused for the same reason. One carries a token longer than
    // the buffer tokens are kept in; one carries none at all, which RFC 9000
    // §17.2.5 says a client discards; and one carries that same absence in the
    // one shape the parser does not produce but a `Header` can hold — a token
    // that is present and zero bytes long. Any of them would leave the next
    // Initial carrying the token it already had, while `retry_received` turned
    // every later Retry away — so one such packet costs the handshake its
    // address validation for good. All three are refused before anything
    // moves, and a Retry this connection can use is still accepted afterwards.
    var rng = TestRandom{};
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.is_server = false;
    @memcpy(conn.odcid_buf[0..conn.dcid_len], conn.dcid[0..conn.dcid_len]);
    conn.odcid_len = conn.dcid_len;

    // The state a connection between Retries is in: a token from an earlier
    // one, a send offset part way into the ClientHello, a packet number spent.
    @memcpy(conn.retry_token_buf[0..4], "prev");
    conn.retry_token_len = 4;
    conn.packer.initial_token = conn.retry_token_buf[0..4];
    try conn.crypto_streams.getStream(0).writeData("a ClientHello part way out");
    _ = conn.crypto_streams.getStream(0).popCryptoFrame(7);
    conn.pkt_num_spaces[0].next_packet_number = 3;
    conn.got_peer_conn_id = true;
    // Owned copies, not views: the arrays a borrow would point into are the
    // ones a Retry rewrites, and a borrow of a mutated array still compares
    // equal to itself.
    var dcid_before: [packet.CONNECTION_ID_MAX_SIZE]u8 = undefined;
    @memcpy(dcid_before[0..conn.dcid_len], conn.dcid[0..conn.dcid_len]);
    const dcid_len_before = conn.dcid_len;
    var packer_dcid_before: [packet.CONNECTION_ID_MAX_SIZE]u8 = undefined;
    @memcpy(packer_dcid_before[0..conn.packer.dcid_len], conn.packer.getDcid());
    const packer_dcid_len_before = conn.packer.dcid_len;
    var token_before: [conn.retry_token_buf.len]u8 = undefined;
    const token_len_before = conn.retry_token_len;
    @memcpy(token_before[0..token_len_before], conn.retry_token_buf[0..token_len_before]);
    const pn_before = conn.pkt_num_spaces[0].next_packet_number;
    const send_offset_before = conn.crypto_streams.getStream(0).send_offset;

    // The shapes that refusal has to cover: what the wire parser leaves null
    // for an empty token, and the explicit empty slice a caller that built the
    // `Header` itself can hand over instead.
    const refusals = [_]struct { token_len: usize, empty_token_present: bool }{
        .{ .token_len = conn.retry_token_buf.len + 8, .empty_token_present = false },
        .{ .token_len = 0, .empty_token_present = false },
        .{ .token_len = 0, .empty_token_present = true },
    };
    for (refusals) |refusal| {
        var scid: [8]u8 = undefined;
        rng.random().bytes(&scid);
        var token: [conn.retry_token_buf.len + 8]u8 = undefined;
        rng.random().bytes(token[0..refusal.token_len]);
        var buf: [512]u8 = undefined;
        const refused = try retryPacket(&buf, &conn, &scid, token[0..refusal.token_len]);
        var header = refused.header;
        if (refusal.empty_token_present) {
            header.token = &[_]u8{};
            try std.testing.expectEqual(@as(usize, 0), header.token.?.len);
        } else if (refusal.token_len == 0) {
            // A zero-length token parses as no token at all, which is the other
            // shape RFC 9000 §17.2.5 has a client discard.
            try std.testing.expectEqual(@as(?[]const u8, null), header.token);
        } else {
            try std.testing.expectEqual(@as(usize, refusal.token_len), header.token.?.len);
        }
        try conn.handleRetryPacket(&header, refused.raw);

        // Nothing moved: not the destination id, not the token, not the packet
        // number, not the send offset, and not the latch that turns Retries
        // away.
        try std.testing.expectEqual(dcid_len_before, conn.dcid_len);
        try std.testing.expectEqualSlices(
            u8,
            dcid_before[0..dcid_len_before],
            conn.dcid[0..conn.dcid_len],
        );
        try std.testing.expectEqual(packer_dcid_len_before, conn.packer.dcid_len);
        try std.testing.expectEqualSlices(
            u8,
            packer_dcid_before[0..packer_dcid_len_before],
            conn.packer.getDcid(),
        );
        try std.testing.expectEqual(token_len_before, conn.retry_token_len);
        try std.testing.expectEqualSlices(
            u8,
            token_before[0..token_len_before],
            conn.retry_token_buf[0..conn.retry_token_len],
        );
        try std.testing.expectEqual(pn_before, conn.pkt_num_spaces[0].next_packet_number);
        try std.testing.expectEqual(
            send_offset_before,
            conn.crypto_streams.getStream(0).send_offset,
        );
        try std.testing.expect(!conn.retry_received);
        try std.testing.expect(conn.got_peer_conn_id);
    }

    // And the refusals cost nothing: a Retry this connection can use is taken.
    var good_scid: [8]u8 = undefined;
    rng.random().bytes(&good_scid);
    var token: [32]u8 = undefined;
    rng.random().bytes(&token);
    var good_buf: [256]u8 = undefined;
    const good = try retryPacket(&good_buf, &conn, &good_scid, &token);
    try conn.handleRetryPacket(&good.header, good.raw);

    try std.testing.expect(conn.retry_received);
    try std.testing.expectEqualSlices(u8, &good_scid, conn.dcid[0..conn.dcid_len]);
    try std.testing.expectEqual(@as(u16, token.len), conn.retry_token_len);
    try std.testing.expectEqualSlices(u8, &token, conn.retry_token_buf[0..conn.retry_token_len]);
    try std.testing.expectEqual(@as(u64, 0), conn.pkt_num_spaces[0].next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_streams.getStream(0).send_offset);
    try std.testing.expect(!conn.got_peer_conn_id);
}

test "native path opening rejects absent multipath before touching packet state" {
    var conn: Connection = undefined;
    conn.state = .connected;
    conn.local_params = .{};
    conn.peer_params = .{};
    conn.handshake_confirmed = true;
    conn.is_server = false;
    var prng = std.Random.DefaultPrng.init(17);
    try std.testing.expectError(
        error.MultipathNotNegotiated,
        conn.openPath(.unset, .unset, 0, prng.random()),
    );
}

test "native MP control bytes fail closed without negotiation" {
    var bytes = [_]u8{ 0x7e, 0x7a, 0x01 };
    var used: usize = 0;
    const parsed = try Frame.parseSized(&bytes, &used);
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.peer_params = .{};
    conn.state = .connected;
    var prng = std.Random.DefaultPrng.init(19);
    try std.testing.expectError(
        error.ProtocolViolation,
        conn.processFrame(&parsed, .application, 0, prng.random()),
    );
}

test "native path packet numbers and source decoded ACK route independently" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 8 };
    conn.native_paths = try native_path.process(.{}, .{
        .negotiate = .{ .local_max = 1, .peer_max = 8 },
    });
    conn.native_paths.entries[1].opened = true;
    const other = try conn.ensurePathTransport();
    var random = std.Random.DefaultPrng.init(41);
    const pn0 = conn.pkt_handler.nextPacketNumber(.application, random.random());
    const pn1 = other.handler.nextPacketNumber(.application, random.random());
    try std.testing.expectEqual(pn0, pn1);
    try conn.pkt_handler.onPacketSent(.{
        .pn = pn0,
        .time_sent = 1,
        .size = 100,
        .enc_level = .application,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try other.handler.onPacketSent(.{
        .pn = pn1,
        .time_sent = 1,
        .size = 100,
        .enc_level = .application,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // Noq PATH_ACK type 0x3e, path 1, PN 0, delay 0, ranges 0, first 0.
    var bytes = [_]u8{ 0x3e, 1, 0, 0, 0, 0 };
    const parsed = try Frame.parse(&bytes);
    try conn.processFrame(&parsed, .application, 100_000, random.random());
    try std.testing.expectEqual(@as(usize, 1), conn.pkt_handler.sent[2].sent_packets.count());
    try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].sent_packets.count());
    try std.testing.expectEqual(@as(u8, 0), conn.transport_path);
    conn.receive_path = 1;
    conn.activateTransport(1);
    var ordinary_bytes = [_]u8{ 0x02, 0, 0, 0, 0 };
    const ordinary = try Frame.parse(&ordinary_bytes);
    try conn.processFrame(&ordinary, .application, 100_001, random.random());
    try std.testing.expectEqual(@as(usize, 0), conn.pkt_handler.sent[2].sent_packets.count());
    try std.testing.expectEqual(@as(u8, 1), conn.transport_path);
    var ordinary_ecn_bytes = [_]u8{ 0x03, 0, 0, 0, 0, 0, 0, 0 };
    const ordinary_ecn = try Frame.parse(&ordinary_ecn_bytes);
    try conn.processFrame(&ordinary_ecn, .application, 100_002, random.random());
    conn.activateTransport(0);
}

test "native path CID duplicate changes and unvalidated selection are rejected" {
    var cid_bytes: [8]u8 = "native01".*;
    var changed_cid_bytes: [8]u8 = "native02".*;
    var conn = testConnectionForRole(std.testing.allocator, false);
    defer conn.deinit();
    conn.state = .connected;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 8 };
    conn.handshake_confirmed = true;
    var random = std.Random.DefaultPrng.init(43);
    const cid: Frame = .{ .path_new_connection_id = .{
        .path_id = 1,
        .cid = .{
            .seq_num = 0,
            .retire_prior_to = 0,
            .conn_id = cid_bytes[0..],
            .stateless_reset_token = .{1} ** 16,
        },
    } };
    try conn.processFrame(&cid, .application, 0, random.random());
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 5678);
    const id = try conn.openPath(local, peer, 0, random.random());
    try std.testing.expectError(error.PathNotValidated, conn.selectPath(id));
    try std.testing.expectEqual(@as(u8, 0), conn.active_path_idx);
    try std.testing.expectError(error.AlreadyOpen, conn.openPath(local, peer, 1, random.random()));
    var changed = cid;
    changed.path_new_connection_id.cid.conn_id = changed_cid_bytes[0..];
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&changed, .application, 0, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
    try std.testing.expectEqual(@as(u64, 0x0a), conn.local_err.?.code);
    try std.testing.expectError(error.ClosedPath, conn.openPath(local, peer, 2, random.random()));
}

test "native NAT probe offer commits only real packet and preserves primary route" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.is_server = false;
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.nat_state = .init(false, 32, 32);
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const relay = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2345);
    const direct = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3456);
    conn.paths[0] = NetworkPath.init(local, relay, true);
    conn.path_initialized = true;
    try conn.addNatTraversalAddress(local);
    const added = try conn.processNat(.{ .receiveAdd = .{
        .sequence = 0,
        .address = direct,
    } });
    _ = added;
    var random = std.Random.DefaultPrng.init(47);
    try conn.initiateNatTraversalRound(0, random.random());
    var tiny: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try conn.sendAt(&tiny, 0, random.random()));
    try std.testing.expect(conn.peerAddress().eql(relay));
    try std.testing.expectEqual(@as(u16, 0), conn.nat_state.?.challenge_count);
    const keys = try quic_crypto.deriveInitialKeyMaterial("probe-connection", conn.version, false);
    conn.installAppKeys(keys[0], keys[1]);
    conn.key_update = quic_crypto.KeyUpdateManager.init(.{1} ** 32, .{2} ** 32, keys[0].hp_key, keys[1].hp_key);
    conn.key_update.?.onPeerKeyUpdate(0, conn.maxActivePathPto());
    conn.packer.key_phase = conn.key_update.?.key_phase;
    conn.pkt_handler.recv[2].ack_queued = true;
    var wire: [1500]u8 = undefined;
    const length = try conn.sendAt(&wire, 1, random.random());
    try std.testing.expect(length > 0);
    try std.testing.expectEqual(@as(u64, 0), conn.pkt_handler.bytes_in_flight);
    try std.testing.expect(conn.pkt_handler.recv[2].ack_queued);
    try std.testing.expect(conn.lastSendPeer().eql(direct));
    try std.testing.expect(conn.paths[0].peer_addr.eql(relay));
    try std.testing.expectEqual(@as(u16, 1), conn.nat_state.?.challenge_count);
    try std.testing.expect(conn.key_update.?.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 1), conn.key_update.?.packets_sent_with_current);
    conn.pending_frames.push(.{ .ping = {} });
    try std.testing.expect(try conn.sendAt(&wire, 2, random.random()) > 0);
    try std.testing.expect(!conn.key_update.?.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 2), conn.key_update.?.packets_sent_with_current);
}

test "native direct validation uses authenticated path1 packets and preserves primary connection" {
    var cid_bytes: [8]u8 = "path-one".*;
    var client = testConnection(std.testing.allocator);
    defer client.deinit();
    client.is_server = false;
    client.packer.is_server = false;
    client.state = .connected;
    client.handshake_confirmed = true;
    client.local_params.initial_max_path_id = 1;
    client.peer_params = .{ .initial_max_path_id = 8 };
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const relay = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2345);
    const direct = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3456);
    client.paths[0] = NetworkPath.init(local, relay, true);
    client.paths[0].is_validated = true;
    client.path_initialized = true;
    const keys = try quic_crypto.deriveInitialKeyMaterial("same-connection", client.version, false);
    client.installAppKeys(keys[0], keys[1]);
    var random = std.Random.DefaultPrng.init(53);
    const cid: Frame = .{ .path_new_connection_id = .{
        .path_id = 1,
        .cid = .{
            .seq_num = 0,
            .retire_prior_to = 0,
            .conn_id = cid_bytes[0..],
            .stateless_reset_token = .{3} ** 16,
        },
    } };
    try client.processFrame(&cid, .application, 0, random.random());
    const id = try client.openPath(local, direct, 0, random.random());
    var small: [1199]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try client.sendAt(&small, 0, random.random()));
    try std.testing.expectEqual(@as(u64, 0), client.path1_transport.?.handler.next_pn[2]);
    var wire: [1500]u8 = undefined;
    const length = try client.sendAt(&wire, 0, random.random());
    try std.testing.expectEqual(@as(usize, 1200), length);
    try std.testing.expect(client.lastSendPeer().eql(direct));
    try std.testing.expect(client.peerAddress().eql(relay));
    try std.testing.expectEqual(@as(u64, 0), client.pkt_handler.next_pn[2]);
    try std.testing.expect(client.path1_transport.?.handler.next_pn[2] != 0);
    const peer_keys = try quic_crypto.deriveInitialKeyMaterial("same-connection", client.version, true);
    var read_space: packet.PacketNumSpace = .{
        .crypto_open = peer_keys[0],
        .crypto_seal = peer_keys[1],
    };
    var reader = io.fixedBufferStream(wire[0..length]);
    var header = try packet.Header.parse(&reader, 8);
    const payload = try packet.decryptForPath(&header, &reader, &read_space, 1);
    const challenge = (try Frame.parse(payload)).path_challenge;
    client.receive_path = id;
    client.received_local = local;
    client.received_peer = relay;
    try client.processFrame(&.{ .path_response = challenge }, .application, 1, random.random());
    try std.testing.expect(!client.paths[id].is_validated);
    client.received_peer = direct;
    try client.processFrame(&.{ .path_response = challenge }, .application, 2, random.random());
    try std.testing.expect(client.paths[id].is_validated);
    try client.selectPath(id);
    try std.testing.expect(client.peerAddress().eql(direct));
    try std.testing.expect(client.paths[0].peer_addr.eql(relay));
    try std.testing.expectEqual(native_path.Status.available, client.pathSnapshot(id).?.status);
}

test "native observed report is a real packet with post-send sequence and loss rescheduling" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.is_server = false;
    conn.packer.is_server = false;
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.address_discovery_role = .send_only;
    conn.peer_params = .{ .address_discovery_role = .receive_only };
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const remote = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    conn.paths[0] = NetworkPath.init(local, remote, true);
    conn.path_initialized = true;
    conn.observed_paths[0].schedule(.send_only, .receive_only);
    const keys = try quic_crypto.deriveInitialKeyMaterial("observed-real", conn.version, false);
    conn.installAppKeys(keys[0], keys[1]);
    var random = std.Random.DefaultPrng.init(59);
    var small: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try conn.sendAt(&small, 0, random.random()));
    try std.testing.expectEqual(@as(u64, 0), conn.observed_next_sequence);
    try std.testing.expect(conn.observed_paths[0].pending);
    var wire: [1500]u8 = undefined;
    const length = try conn.sendAt(&wire, 0, random.random());
    try std.testing.expect(length > 0);
    try std.testing.expectEqual(@as(u64, 1), conn.observed_next_sequence);
    try std.testing.expect(!conn.observed_paths[0].pending);
    const peer_keys = try quic_crypto.deriveInitialKeyMaterial("observed-real", conn.version, true);
    var space: packet.PacketNumSpace = .{
        .crypto_open = peer_keys[0],
        .crypto_seal = peer_keys[1],
    };
    var reader = io.fixedBufferStream(wire[0..length]);
    var header = try packet.Header.parse(&reader, 8);
    const payload = try packet.decrypt(&header, &reader, &space);
    const report = (try Frame.parse(payload)).observed_address;
    try std.testing.expectEqual(@as(u64, 0), report.sequence);
    try std.testing.expect(report.address.eql(remote));
    var iterator = conn.pkt_handler.sent[2].sent_packets.iterator();
    const sent = iterator.next().?.value_ptr.*;
    conn.requeueLostControlFrames(sent, 1, random.random());
    try std.testing.expect(conn.observed_paths[0].pending);
}

test "native frame failures close and never opened PATH_ACK differs from abandoned" {
    var random = std.Random.DefaultPrng.init(91);
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    const add: Frame = .{ .add_address = .{
        .sequence = 0,
        .address = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000),
    } };
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&add, .application, 10, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
    conn.state = .connected;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    const ack: Frame = .{ .path_ack = .{ .path_id = 1, .ack = .{ .largest_ack = 0, .ack_delay = 0, .first_ack_range = 0, .ack_range_count = 0, .ack_ranges = undefined } } };
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&ack, .application, 11, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
    conn.native_paths.entries[1] = .{ .opened = true, .abandoned = true };
    conn.state = .connected;
    try conn.processFrame(&ack, .application, 12, random.random());
    try std.testing.expectEqual(State.connected, conn.state);
}

test "native credit increase issues CID once within bounded ceiling" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 0 };
    conn.native_paths = try native_path.process(.{}, .{
        .negotiate = .{ .local_max = 1, .peer_max = 0 },
    });
    var random = std.Random.DefaultPrng.init(92);
    conn.is_server = false;
    conn.state = .connected;
    conn.handshake_confirmed = true;
    const other = try conn.ensurePathTransport();
    other.dcid_len = 8;
    @memcpy(other.dcid[0..8], "peerpath");
    conn.direct_ready = .{
        .local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000),
        .peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000),
    };
    const credit: Frame = .{ .max_path_id = 9 };
    try conn.processFrame(&credit, .application, 10, random.random());
    try std.testing.expectEqual(@as(u32, 1), conn.native_paths.peer_max_path_id);
    try std.testing.expectEqual(@as(u64, 1), conn.path1_transport.?.next_local_cid_seq);
    try std.testing.expect(conn.native_paths.entries[1].opened);
    try std.testing.expect(conn.direct_ready == null);
    try conn.processFrame(&credit, .application, 11, random.random());
    try std.testing.expectEqual(@as(u64, 1), conn.path1_transport.?.next_local_cid_seq);
}

test "shared key retention PTO includes slow active path but excludes abandoned" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.native_paths.entries[1].opened = true;
    const other = try conn.ensurePathTransport();
    other.handler.rtt_stats.smoothed_rtt = 9_000_000_000;
    const expected = @max(conn.pkt_handler.rtt_stats.pto(), other.handler.rtt_stats.pto());
    conn.activateTransport(1);
    try std.testing.expectEqual(expected, conn.maxActivePathPto());
    conn.native_paths.entries[1].abandoned = true;
    try std.testing.expectEqual(conn.pkt_handler.rtt_stats.pto(), conn.maxActivePathPto());
    conn.native_paths.entries[1].abandoned = false;
    conn.native_paths.entries[0].abandoned = true;
    conn.pkt_handler.rtt_stats.smoothed_rtt = 20_000_000_000;
    try std.testing.expectEqual(other.handler.rtt_stats.pto(), conn.maxActivePathPto());
}

test "native queued challenge retry is not consumed by timeout" {
    var conn = testConnectionForRole(std.testing.allocator, false);
    defer conn.deinit();
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    var random = std.Random.DefaultPrng.init(93);
    var cid_bytes: [8]u8 = "retrycid".*;
    const cid: Frame = .{ .path_new_connection_id = .{ .path_id = 1, .cid = .{
        .seq_num = 0,
        .retire_prior_to = 0,
        .conn_id = &cid_bytes,
        .stateless_reset_token = .{9} ** 16,
    } } };
    try conn.processFrame(&cid, .application, 0, random.random());
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 5678);
    try std.testing.expectEqual(@as(u8, 1), try conn.openPath(local, peer, 0, random.random()));
    const before = conn.paths[1].validator.retries;
    conn.activateTransport(1);
    const pto = conn.packetHandler().*.rtt_stats.pto();
    const timeout_at = pto + 1;
    try std.testing.expect(conn.paths[1].validator.needsRetry(timeout_at, pto));
    const queued = conn.path_control[1].len;
    try conn.onPathTimeout(timeout_at, random.random());
    try std.testing.expectEqual(before, conn.paths[1].validator.retries);
    try std.testing.expectEqual(PathValidationState.pending, conn.paths[1].validator.state);
    try std.testing.expect(conn.challenge_queued[1]);
    try std.testing.expectEqual(queued, conn.path_control[1].len);
}

test "native path zero CID conflicts and current CID retirement close" {
    var cid_bytes: [8]u8 = "samecid1".*;
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    var random = std.Random.DefaultPrng.init(94);
    const other = try conn.ensurePathTransport();
    other.peer_cids.addPeerCid(0, "samecid1", .{1} ** 16);
    const cid: Frame = .{ .path_new_connection_id = .{ .path_id = 0, .cid = .{
        .seq_num = 1,
        .retire_prior_to = 0,
        .conn_id = cid_bytes[0..],
        .stateless_reset_token = .{1} ** 16,
    } } };
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&cid, .application, 1, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
    conn.state = .connected;
    conn.local_cid_pool.registerInitialCid("current0", null, random.random());
    conn.received_cid_len = 8;
    @memcpy(conn.received_cid[0..8], "current0");
    const retire: Frame = .{ .path_retire_connection_id = .{ .path_id = 0, .seq_num = 0 } };
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&retire, .application, 2, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
}

test "native blocked CID requests reject impossible identifiers and sequence credit" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.state = .connected;
    var random = std.Random.DefaultPrng.init(95);
    const blocked: Frame = .{ .path_cids_blocked = .{ .path_id = 2, .next_seq = 0 } };
    try std.testing.expectError(error.ProtocolViolation, conn.processFrame(&blocked, .application, 1, random.random()));
    try std.testing.expectEqual(State.closing, conn.state);
}

test "native reciprocal probe rejects lifted candidate policy before scheduling" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.nat_state = .init(false, 32, 32);
    conn.supportedIPv6 = false;
    conn.receive_path = 0;
    conn.received_peer = address.Address.initIpv6(.{0} ** 16, 1234, 0);
    conn.received_local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 4321);
    var random = std.Random.DefaultPrng.init(96);
    const challenge: Frame = .{ .path_challenge = .{1} ** 8 };
    try conn.processFrame(&challenge, .application, 1, random.random());
    try std.testing.expect(conn.nat_reply == null);
}

test "native matching response cannot validate an unsent direct challenge" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.native_paths.entries[1].opened = true;
    conn.receive_path = 1;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    conn.paths[1] = NetworkPath.init(local, peer, false);
    conn.received_local = local;
    conn.received_peer = peer;
    var random = std.Random.DefaultPrng.init(97);
    try conn.probePath(1, 0, random.random());
    const response: Frame = .{ .path_response = conn.paths[1].validator.challenge_data };
    try conn.processFrame(&response, .application, 1, random.random());
    try std.testing.expect(!conn.paths[1].is_validated);
}

test "native IPv4 socket admits mapped candidates canonically" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.supportedIPv6 = false;
    conn.nat_state = .init(false, 32, 32);
    const mapped = address.Address.initIpv6([_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 }, 1000, 0);
    try std.testing.expect(conn.admitCandidate(mapped));
    try conn.addNatTraversalAddress(mapped);
    try std.testing.expectEqual(@as(usize, 1), conn.nat_state.?.localCandidates().len);
    try std.testing.expect(conn.nat_state.?.localCandidates()[0].address == .ipv4);
    conn.is_server = false;
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.paths[0] = NetworkPath.init(address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000), address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3000), true);
    conn.path_initialized = true;
    _ = try conn.processNat(.{ .receiveAdd = .{ .sequence = 0, .address = mapped } });
    var random = std.Random.DefaultPrng.init(98);
    try conn.initiateNatTraversalRound(0, random.random());
    const keys = try quic_crypto.deriveInitialKeyMaterial("mapped-candidate", conn.version, false);
    conn.installAppKeys(keys[0], keys[1]);
    var wire: [1500]u8 = undefined;
    try std.testing.expect(try conn.sendAt(&wire, 1, random.random()) > 0);
    try std.testing.expect(conn.lastSendPeer().* == .ipv4);
    try std.testing.expect(conn.pkt_handler.next_pn[2] > 0);
}

test "native wrong-side NAT and forbidden observed reports close transport" {
    var random = std.Random.DefaultPrng.init(99);
    const candidate = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    var server = testConnection(std.testing.allocator);
    defer server.deinit();
    server.is_server = true;
    server.state = .connected;
    server.nat_state = .init(true, 32, 32);
    const add: Frame = .{ .add_address = .{ .sequence = 0, .address = candidate } };
    try std.testing.expectError(error.ProtocolViolation, server.processFrame(&add, .application, 1, random.random()));
    try std.testing.expectEqual(State.closing, server.state);
    var client = testConnection(std.testing.allocator);
    defer client.deinit();
    client.is_server = false;
    client.state = .connected;
    client.nat_state = .init(false, 32, 32);
    const reach: Frame = .{ .reach_address = .{ .round = 0, .address = candidate } };
    try std.testing.expectError(error.ProtocolViolation, client.processFrame(&reach, .application, 1, random.random()));
    try std.testing.expectEqual(State.closing, client.state);
    var receiver = testConnection(std.testing.allocator);
    defer receiver.deinit();
    receiver.state = .connected;
    const report: Frame = .{ .observed_address = .{ .sequence = 0, .address = candidate } };
    try std.testing.expectError(error.ProtocolViolation, receiver.processFrame(&report, .application, 1, random.random()));
    try std.testing.expectEqual(State.closing, receiver.state);
}

test "authenticated pure NAT probe preserves virtual route but nonprobing packet migrates" {
    var receiver = testConnectionForRole(std.testing.allocator, false);
    defer receiver.deinit();
    receiver.state = .connected;
    receiver.handshake_confirmed = true;
    receiver.local_params.initial_max_path_id = 1;
    receiver.peer_params = .{ .initial_max_path_id = 1 };
    receiver.native_paths = try native_path.process(.{}, .{
        .negotiate = .{ .local_max = 1, .peer_max = 1 },
    });
    receiver.nat_state = .init(false, 32, 32);
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const relay = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    const direct = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3000);
    receiver.paths[0] = NetworkPath.init(local, relay, true);
    receiver.paths[0].is_validated = true;
    receiver.path_initialized = true;
    const receiver_keys = try quic_crypto.deriveInitialKeyMaterial("offpath-receive", receiver.version, false);
    receiver.installAppKeys(receiver_keys[0], receiver_keys[1]);
    var sender = testConnectionForRole(std.testing.allocator, true);
    defer sender.deinit();
    sender.state = .connected;
    sender.handshake_confirmed = true;
    sender.local_params.initial_max_path_id = 1;
    sender.peer_params = .{ .initial_max_path_id = 1 };
    sender.paths[0] = NetworkPath.init(direct, local, true);
    sender.paths[0].is_validated = true;
    sender.path_initialized = true;
    const sender_keys = try quic_crypto.deriveInitialKeyMaterial("offpath-receive", sender.version, true);
    sender.installAppKeys(sender_keys[0], sender_keys[1]);
    sender.packer.application_path_id = 0;
    var random = std.Random.DefaultPrng.init(100);
    var wire: [1500]u8 = undefined;
    const probe_length = try sender.packer.packOffPath(&wire, &sender.pkt_handler, sender.appSeal().?, .{ .challenge = .{1} ** 8 }, random.random());
    // Inspect a copy: decryption mutates the packet, while recv must consume
    // the original ciphertext with its own packet-number state.
    var inspected_wire: [1500]u8 = undefined;
    @memcpy(inspected_wire[0..probe_length], wire[0..probe_length]);
    var inspect_space: packet.PacketNumSpace = .{
        .crypto_open = receiver_keys[0],
        .crypto_seal = receiver_keys[1],
    };
    var inspect_reader = io.fixedBufferStream(inspected_wire[0..probe_length]);
    var inspect_header = try packet.Header.parse(&inspect_reader, sender.packer.dcid_len);
    var remaining = try packet.decrypt(&inspect_header, &inspect_reader, &inspect_space);
    const probe_pn = inspect_header.packet_number;
    var found_challenge = false;
    while (remaining.len > 0) {
        var consumed: usize = undefined;
        const frame = try Frame.parseSized(remaining, &consumed);
        try std.testing.expect(consumed > 0);
        try std.testing.expect(frame.isProbing());
        if (frame == .path_challenge) {
            try std.testing.expectEqualSlices(u8, &([_]u8{1} ** 8), &frame.path_challenge);
            found_challenge = true;
        }
        remaining = remaining[consumed..];
    }
    try std.testing.expect(found_challenge);
    var probe_reader = io.fixedBufferStream(wire[0..probe_length]);
    var probe_header = try packet.Header.parse(&probe_reader, sender.packer.dcid_len);
    try receiver.recv(&probe_header, &probe_reader, .{ .from = direct, .to = local, .datagram_size = probe_length }, 1, random.random());
    try std.testing.expect(receiver.paths[0].peer_addr.eql(relay));
    try std.testing.expectEqual(@as(u64, 0), receiver.paths[0].bytes_received);
    try std.testing.expect(receiver.paths[0].is_validated);
    try std.testing.expect(receiver.nat_reply != null);
    try std.testing.expectEqual(@as(?u64, probe_pn), receiver.pkt_handler.recv[2].largest_received);
    sender.pending_frames.push(.{ .ping = {} });
    const length = try sender.sendAt(&wire, 2, random.random());
    try std.testing.expect(length > 0);
    @memcpy(inspected_wire[0..length], wire[0..length]);
    inspect_reader = io.fixedBufferStream(inspected_wire[0..length]);
    inspect_header = try packet.Header.parse(&inspect_reader, sender.packer.dcid_len);
    remaining = try packet.decrypt(&inspect_header, &inspect_reader, &inspect_space);
    try std.testing.expect(inspect_header.packet_number > probe_pn);
    const ping_pn = inspect_header.packet_number;
    var found_ping = false;
    while (remaining.len > 0) {
        var consumed: usize = undefined;
        const frame = try Frame.parseSized(remaining, &consumed);
        try std.testing.expect(consumed > 0);
        if (frame == .ping) found_ping = true;
        remaining = remaining[consumed..];
    }
    try std.testing.expect(found_ping);
    var reader = io.fixedBufferStream(wire[0..length]);
    var header = try packet.Header.parse(&reader, sender.packer.dcid_len);
    try receiver.recv(&header, &reader, .{ .from = direct, .to = local, .datagram_size = length }, 2, random.random());
    try std.testing.expectEqual(@as(?u64, ping_pn), receiver.pkt_handler.recv[2].largest_received);
    try std.testing.expect(receiver.paths[0].peer_addr.eql(direct));
    try std.testing.expect(!receiver.paths[0].is_validated);
    try std.testing.expect(receiver.paths[0].bytes_received > 0);
}

fn nativeTestWire(
    out: []u8,
    seal: *const quic_crypto.Seal,
    path_id: u32,
    pn: u64,
    phase: bool,
    plaintext: []const u8,
    cid: []const u8,
) []u8 {
    out[0] = packet.FIXED_BIT | 3 | (if (phase) packet.KEY_PHASE_BIT else @as(u8, 0));
    @memcpy(out[1..9], cid);
    std.mem.writeInt(u32, out[9..13], @truncate(pn), .big);
    const length = seal.encryptPayloadForPath(path_id, pn, out[0..13], plaintext, out[13..]);
    const mask = seal.newMask(out[13..][0..quic_crypto.SAMPLE_LEN]);
    out[0] ^= mask[0] & 0x1f;
    for (0..4) |i| out[9 + i] ^= mask[1 + i];
    return out[0 .. 13 + length];
}

fn configureNativeTestIngress(conn: *Connection, peer_cid_bytes: *[8]u8, random: std.Random) !void {
    conn.handshake_confirmed = true;
    conn.state = .connected;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    conn.paths[0] = NetworkPath.init(local, peer, true);
    conn.paths[1] = NetworkPath.init(local, peer, true);
    conn.path_initialized = true;
    conn.paths[0].is_validated = true;
    conn.paths[1].is_validated = true;
    if (!conn.native_paths.negotiated) {
        conn.native_paths = try native_path.process(conn.native_paths, .{ .negotiate = .{
            .local_max = conn.local_params.initial_max_path_id,
            .peer_max = conn.peer_params.?.initial_max_path_id,
        } });
    }
    conn.local_cid_pool.registerInitialCid("keyguard", null, random);
    try conn.issuePathCid(random);
    const peer_cid: Frame = .{ .path_new_connection_id = .{ .path_id = 1, .cid = .{
        .seq_num = 0,
        .retire_prior_to = 0,
        .conn_id = peer_cid_bytes[0..],
        .stateless_reset_token = .{3} ** 16,
    } } };
    try conn.processFrame(&peer_cid, .application, 0, random);
    const keys = quic_crypto.KeyUpdateManager.init(.{0x31} ** 32, .{0x31} ** 32, .{0x42} ** quic_crypto.max_key_len, .{0x42} ** quic_crypto.max_key_len);
    conn.installAppKeys(keys.current_open, keys.current_seal);
}

fn recvNativeTestFrame(
    conn: *Connection,
    frame: Frame,
    carrying_path: u1,
    now: i64,
    random: std.Random,
) !void {
    var cid: ?[]const u8 = null;
    for (&conn.local_cid_pool.entries) |*entry| {
        if (entry.occupied and entry.path_id == carrying_path) {
            cid = entry.getCid();
            break;
        }
    }
    const destination_cid = cid orelse return error.TestMissingPathConnectionId;
    const pn = if (carrying_path == 1) conn.path1_transport.?.space.next_packet_number else conn.pkt_num_spaces[2].next_packet_number;
    var plaintext: [128]u8 = undefined;
    var writer = io.fixedBufferStream(&plaintext);
    try frame.write(&writer);
    var bytes: [256]u8 = undefined;
    const wire = nativeTestWire(&bytes, conn.appSeal().?, carrying_path, pn, false, plaintext[0..writer.seek], destination_cid);
    var reader = io.fixedBufferStream(wire);
    var header = try packet.Header.parse(&reader, 8);
    try conn.recv(&header, &reader, .{
        .from = conn.paths[carrying_path].peer_addr,
        .to = conn.paths[carrying_path].local_addr,
        .datagram_size = wire.len,
    }, now, random);
}

fn sendNativeTestPing(conn: *Connection, path_id: u1, now: i64, random: std.Random) !u64 {
    try conn.selectPath(path_id);
    conn.pending_frames.push(.{ .ping = {} });
    var wire: [1500]u8 = undefined;
    try std.testing.expect(try conn.sendAt(&wire, now, random) > 0);
    try std.testing.expectEqual(@as(u8, path_id), conn.send_path);
    const handler = if (path_id == 0) &conn.pkt_handler else &conn.path1_transport.?.handler;
    const pn = handler.next_pn[2] - 1;
    const sent = handler.sent[2].sent_packets.get(pn).?;
    try std.testing.expect(sent.ecn_marked);
    return pn;
}

test "recv authenticated invalid next keys closes before rotating shared keys on either path" {
    const secret = [_]u8{0x31} ** 32;
    const hp = [_]u8{0x42} ** quic_crypto.max_key_len;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    var random = std.Random.DefaultPrng.init(101);
    for ([_]u8{ 0, 1 }) |path_id| {
        // Lower PN, equal PN, and increasing PN for a second unacknowledged update.
        for ([_]u64{ 9, 10, 11 }) |pn| {
            var conn = testConnection(std.testing.allocator);
            defer conn.deinit();
            conn.is_server = true;
            conn.state = .connected;
            conn.handshake_confirmed = true;
            conn.local_params.initial_max_path_id = 1;
            conn.peer_params = .{ .initial_max_path_id = 1 };
            conn.native_paths = try native_path.process(.{}, .{
                .negotiate = .{ .local_max = 1, .peer_max = 1 },
            });
            conn.native_paths.entries[1].opened = true;
            conn.paths[0] = NetworkPath.init(local, peer, true);
            conn.paths[1] = NetworkPath.init(local, peer, true);
            conn.path_initialized = true;
            conn.local_cid_pool.registerInitialCid("keyguard", null, random.random());
            conn.local_cid_pool.entries[0].path_id = path_id;
            conn.key_update = quic_crypto.KeyUpdateManager.init(secret, secret, hp, hp);
            var sender = quic_crypto.KeyUpdateManager.init(secret, secret, hp, hp);
            sender.rollKeys(0, 100);
            if (pn == 11) {
                conn.key_update.?.onPeerKeyUpdate(0, conn.maxActivePathPto());
                sender.rollKeys(1, 100);
            }
            conn.installAppKeys(conn.key_update.?.current_open, conn.key_update.?.current_seal);
            const other = try conn.ensurePathTransport();
            conn.pkt_num_spaces[2].next_packet_number = if (path_id == 0) 11 else 101;
            other.space.next_packet_number = if (path_id == 1) 11 else 101;
            const handler = if (path_id == 0) &conn.pkt_handler else &other.handler;
            try handler.onPacketReceived(.application, 10, true, 0, 0);
            const original_keys = conn.key_update.?;
            const original_watermarks = [2]u64{
                conn.pkt_num_spaces[2].next_packet_number, other.space.next_packet_number,
            };
            var bytes: [128]u8 = undefined;
            const wire = nativeTestWire(&bytes, &sender.current_seal, path_id, pn, sender.key_phase, &.{ 0x01, 0x00, 0x00, 0x00 }, "keyguard");
            var reader = io.fixedBufferStream(wire);
            var header = try packet.Header.parse(&reader, 8);
            try std.testing.expectError(error.KeyUpdateError, conn.recv(&header, &reader, .{ .from = peer, .to = local, .datagram_size = wire.len }, 2, random.random()));
            try std.testing.expectEqual(State.closing, conn.state);
            try std.testing.expectEqual(@as(u64, 0x0e), conn.local_err.?.code);
            try std.testing.expect(!header.key_update_authenticated);
            try std.testing.expectEqualDeep(original_keys, conn.key_update.?);
            try std.testing.expectEqual(original_watermarks[0], conn.pkt_num_spaces[2].next_packet_number);
            try std.testing.expectEqual(original_watermarks[1], other.space.next_packet_number);
            try std.testing.expectEqual(@as(?u64, 10), handler.recv[2].largest_received);
        }
    }
}

test "recv current and previous generation duplicates remain connected on either path" {
    const secret = [_]u8{0x31} ** 32;
    const hp = [_]u8{0x42} ** quic_crypto.max_key_len;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    var random = std.Random.DefaultPrng.init(102);
    for ([_]u8{ 0, 1 }) |path_id| {
        var conn = testConnection(std.testing.allocator);
        defer conn.deinit();
        conn.is_server = true;
        conn.state = .connected;
        conn.handshake_confirmed = true;
        conn.local_params.initial_max_path_id = 1;
        conn.peer_params = .{ .initial_max_path_id = 1 };
        conn.native_paths = try native_path.process(.{}, .{
            .negotiate = .{ .local_max = 1, .peer_max = 1 },
        });
        conn.native_paths.entries[1].opened = true;
        conn.paths[0] = NetworkPath.init(local, peer, true);
        conn.paths[1] = NetworkPath.init(local, peer, true);
        conn.path_initialized = true;
        conn.local_cid_pool.registerInitialCid("keyguard", null, random.random());
        conn.local_cid_pool.entries[0].path_id = path_id;
        conn.key_update = quic_crypto.KeyUpdateManager.init(secret, secret, hp, hp);
        var sender = quic_crypto.KeyUpdateManager.init(secret, secret, hp, hp);
        const previous_seal = sender.current_seal;
        sender.rollKeys(0, 100);
        conn.key_update.?.onPeerKeyUpdate(0, conn.maxActivePathPto());
        conn.key_update.?.first_acked_with_current = true;
        conn.installAppKeys(conn.key_update.?.current_open, conn.key_update.?.current_seal);
        const other = try conn.ensurePathTransport();
        conn.pkt_num_spaces[2].next_packet_number = 11;
        other.space.next_packet_number = 11;
        const handler = if (path_id == 0) &conn.pkt_handler else &other.handler;
        try handler.onPacketReceived(.application, 10, true, 0, 0);
        const original_keys = conn.key_update.?;
        for ([_]bool{ false, true }) |previous| {
            var bytes: [128]u8 = undefined;
            const wire = nativeTestWire(&bytes, if (previous) &previous_seal else &sender.current_seal, path_id, 10, !previous, &.{ 0x01, 0x00, 0x00, 0x00 }, "keyguard");
            var reader = io.fixedBufferStream(wire);
            var header = try packet.Header.parse(&reader, 8);
            try conn.recv(&header, &reader, .{ .from = peer, .to = local, .datagram_size = wire.len }, 2, random.random());
            try std.testing.expectEqual(State.connected, conn.state);
            try std.testing.expect(conn.local_err == null);
            try std.testing.expectEqualDeep(original_keys, conn.key_update.?);
            try std.testing.expectEqual(@as(u64, 11), conn.pkt_num_spaces[2].next_packet_number);
            try std.testing.expectEqual(@as(u64, 11), other.space.next_packet_number);
            try std.testing.expectEqual(@as(?u64, 10), handler.recv[2].largest_received);
        }
    }
}

test "lifted physical policy omits virtual observed report but emits configured WAN report" {
    const Admission = struct {
        fn admit(candidate: address.Address) bool {
            return candidate.eql(address.Address.initIpv4(.{ 203, 0, 113, 7 }, 2000));
        }
    };
    var conn = testConnectionForRole(std.testing.allocator, false);
    defer conn.deinit();
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.address_discovery_role = .send_only;
    conn.peer_params = .{ .address_discovery_role = .receive_only };
    conn.candidateAdmission = Admission.admit;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const virtual = address.Address.initIpv6([_]u8{ 0xfd, 0x15 } ++ [_]u8{0} ** 14, 2000, 0);
    const wan = address.Address.initIpv4(.{ 203, 0, 113, 7 }, 2000);
    conn.paths[0] = NetworkPath.init(local, virtual, true);
    conn.path_initialized = true;
    conn.observed_paths[0].schedule(.send_only, .receive_only);
    const keys = try quic_crypto.deriveInitialKeyMaterial("observed-physical", conn.version, false);
    conn.installAppKeys(keys[0], keys[1]);
    var random = std.Random.DefaultPrng.init(103);
    var wire: [1500]u8 = undefined;
    const peer_keys = try quic_crypto.deriveInitialKeyMaterial("observed-physical", conn.version, true);
    var space: packet.PacketNumSpace = .{ .crypto_open = peer_keys[0], .crypto_seal = peer_keys[1] };
    const virtual_length = try conn.sendAt(&wire, 0, random.random());
    try std.testing.expect(virtual_length > 0);
    var virtual_reader = io.fixedBufferStream(wire[0..virtual_length]);
    var virtual_header = try packet.Header.parse(&virtual_reader, 8);
    var remaining = try packet.decrypt(&virtual_header, &virtual_reader, &space);
    while (remaining.len > 0) {
        var consumed: usize = undefined;
        const frame = try Frame.parseSized(remaining, &consumed);
        try std.testing.expect(consumed > 0);
        try std.testing.expect(frame != .observed_address);
        remaining = remaining[consumed..];
    }
    var sent_packets = conn.pkt_handler.sent[2].sent_packets.iterator();
    while (sent_packets.next()) |entry| {
        for (entry.value_ptr.*.getControlFrames()) |control| {
            try std.testing.expect(control != .observed_address);
        }
    }
    try std.testing.expect(conn.observed_queued[0] == null);
    try std.testing.expectEqual(@as(u64, 0), conn.observed_next_sequence);
    try std.testing.expect(conn.paths[0].peer_addr.eql(virtual));
    conn.paths[0].peer_addr = wan;
    const length = try conn.sendAt(&wire, 1, random.random());
    try std.testing.expect(length > 0);
    var reader = io.fixedBufferStream(wire[0..length]);
    var header = try packet.Header.parse(&reader, 8);
    remaining = try packet.decrypt(&header, &reader, &space);
    var found_report = false;
    while (remaining.len > 0) {
        var consumed: usize = undefined;
        const frame = try Frame.parseSized(remaining, &consumed);
        try std.testing.expect(consumed > 0);
        if (frame == .observed_address) {
            try std.testing.expect(frame.observed_address.address.eql(wan));
            try std.testing.expectEqual(@as(u64, 0), frame.observed_address.sequence);
            found_report = true;
        }
        remaining = remaining[consumed..];
    }
    try std.testing.expect(found_report);
    try std.testing.expectEqual(@as(u64, 1), conn.observed_next_sequence);
}

test "native retirement ACK and ACK_ECN release only matching path credit repeatedly" {
    var peer_cid_bytes: [8]u8 = "peerpath".*;
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.native_paths.entries[1].opened = true;
    const other = try conn.ensurePathTransport();
    var random = std.Random.DefaultPrng.init(104);
    try configureNativeTestIngress(&conn, &peer_cid_bytes, random.random());
    other.handler.next_pn[2] = 50;
    for (0..12) |sequence| {
        const sent_at: i64 = @intCast((sequence + 1) * 1_000_000_000);
        for ([_]u1{ 0, 1 }) |id| {
            try conn.retirePeerCid(id, sequence, sent_at);
            try conn.selectPath(id);
            var outgoing: [1500]u8 = undefined;
            try std.testing.expect(try conn.sendAt(&outgoing, sent_at + @as(i64, id) * 1_000_000, random.random()) > 0);
            try std.testing.expectEqual(@as(u8, id), conn.send_path);
            const handler = if (id == 0) &conn.pkt_handler else &other.handler;
            const sent = handler.sent[2].sent_packets.get(handler.next_pn[2] - 1).?;
            var found_retirement = false;
            for (sent.getControlFrames()) |control| {
                if (control == .path_retire_connection_id and
                    control.path_retire_connection_id.path_id == id and
                    control.path_retire_connection_id.seq_num == sequence)
                    found_retirement = true;
            }
            try std.testing.expect(found_retirement);
        }
        const ack1: Frame = if (sequence % 2 == 0) .{ .path_ack = .{ .path_id = 1, .ack = .{
            .largest_ack = other.handler.next_pn[2] - 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
        } } } else .{ .path_ack_ecn = .{ .path_id = 1, .ack = .{
            .largest_ack = other.handler.next_pn[2] - 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 0,
        } } };
        try recvNativeTestFrame(&conn, ack1, @intCast(sequence % 2), sent_at + 2_000_000, random.random());
        try std.testing.expectEqual(@as(usize, 0), other.retiring_cids.items.len);
        try std.testing.expectEqual(@as(usize, 1), conn.retiring_cids.items.len);
        const ack0: Frame = if (sequence % 2 == 0) .{ .ack = .{
            .largest_ack = conn.pkt_handler.next_pn[2] - 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
        } } else .{ .ack_ecn = .{
            .largest_ack = conn.pkt_handler.next_pn[2] - 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 0,
        } };
        try recvNativeTestFrame(&conn, ack0, @intCast((sequence + 1) % 2), sent_at + 2_000_000, random.random());
        try std.testing.expectEqual(@as(usize, 0), conn.retiring_cids.items.len);
        try std.testing.expectEqual(State.connected, conn.state);
    }
}

test "recv abandon retains live replacement and receiving path through following ordinary ACK" {
    const secret = [_]u8{0x31} ** 32;
    const hp = [_]u8{0x42} ** quic_crypto.max_key_len;
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    var random = std.Random.DefaultPrng.init(105);
    for ([_]u8{ 0, 1 }) |carrying_path| {
        var conn = testConnection(std.testing.allocator);
        defer conn.deinit();
        conn.is_server = true;
        conn.state = .connected;
        conn.handshake_confirmed = true;
        conn.local_params.initial_max_path_id = 1;
        conn.peer_params = .{ .initial_max_path_id = 1, .initial_max_streams_uni = 1, .initial_max_stream_data_uni = 4096, .initial_max_data = 4096 };
        conn.native_paths = try native_path.process(.{}, .{
            .negotiate = .{ .local_max = 1, .peer_max = 1 },
        });
        conn.native_paths.entries[1] = .{ .opened = true, .validated = true };
        conn.native_paths.selected = 1;
        conn.active_path_idx = 1;
        conn.paths[0] = NetworkPath.init(local, peer, true);
        const direct_peer = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3000);
        conn.paths[1] = NetworkPath.init(local, direct_peer, false);
        conn.paths[0].is_validated = true;
        conn.paths[1].is_validated = true;
        conn.path_initialized = true;
        conn.local_cid_pool.registerInitialCid("keyguard", null, random.random());
        conn.local_cid_pool.entries[0].path_id = carrying_path;
        const keys = quic_crypto.KeyUpdateManager.init(secret, secret, hp, hp);
        conn.installAppKeys(keys.current_open, keys.current_seal);
        const other = try conn.ensurePathTransport();
        other.handler.next_pn[2] = 50;
        const pn0 = conn.pkt_handler.nextPacketNumber(.application, random.random());
        const pn1 = other.handler.nextPacketNumber(.application, random.random());
        try std.testing.expectEqual(@as(u64, 0), pn0);
        try std.testing.expectEqual(@as(u64, 50), pn1);
        try conn.pkt_handler.onPacketSent(.{ .pn = pn0, .time_sent = 1, .size = 100, .enc_level = .application, .ack_eliciting = true, .in_flight = true });
        try other.handler.onPacketSent(.{ .pn = pn1, .time_sent = 1, .size = 100, .enc_level = .application, .ack_eliciting = true, .in_flight = true });
        var payload: [64]u8 = undefined;
        var writer = io.fixedBufferStream(&payload);
        try (Frame{ .path_abandon = .{ .path_id = 1, .error_code = 0 } }).write(&writer);
        try (Frame{ .ack = .{ .largest_ack = pn0, .ack_delay = 0, .first_ack_range = 0, .ack_range_count = 0, .ack_ranges = undefined } }).write(&writer);
        var bytes: [128]u8 = undefined;
        const wire = nativeTestWire(&bytes, &keys.current_seal, carrying_path, 7, false, payload[0..writer.seek], "keyguard");
        var reader = io.fixedBufferStream(wire);
        var header = try packet.Header.parse(&reader, 8);
        try conn.recv(&header, &reader, .{ .from = if (carrying_path == 0) peer else direct_peer, .to = local, .datagram_size = wire.len }, 100, random.random());
        try std.testing.expectEqual(State.connected, conn.state);
        try std.testing.expect(conn.native_paths.entries[1].abandoned);
        try std.testing.expectEqual(@as(u8, 0), conn.active_path_idx);
        try std.testing.expectEqual(@as(u8, 0), conn.native_paths.selected);
        try std.testing.expectEqual(@as(u8, 0), conn.transport_path);
        try std.testing.expectEqual(@as(usize, 0), conn.pkt_handler.sent[2].sent_packets.count());
        try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].sent_packets.count());
        try std.testing.expectEqual(if (carrying_path == 0) @as(?u64, 7) else null, conn.pkt_handler.recv[2].largest_received);
        try std.testing.expectEqual(if (carrying_path == 1) @as(?u64, 7) else null, other.handler.recv[2].largest_received);
        try std.testing.expectEqual(if (carrying_path == 0) @as(u64, wire.len) else 0, conn.paths[0].bytes_received);
        try std.testing.expectEqual(if (carrying_path == 1) @as(u64, wire.len) else 0, conn.paths[1].bytes_received);
        try std.testing.expect(conn.paths[0].is_validated);
        try std.testing.expect(conn.paths[1].is_validated);
        try std.testing.expect(conn.paths[0].is_initial);
        try std.testing.expect(!conn.paths[1].is_initial);
        conn.streams.setMaxStreams(0, 1);
        conn.streams.setPeerInitialMaxStreamData(0, 0, 4096);
        conn.conn_flow_ctrl.base.send_window = 4096;
        const stream = try conn.openUniStream();
        const application = "application survives native path abandonment";
        try stream.writeData(application);
        stream.close();
        var outgoing: [1500]u8 = undefined;
        const length = try conn.sendAt(&outgoing, 200, random.random());
        try std.testing.expect(length > 0);
        try std.testing.expectEqual(@as(u8, 0), conn.send_path);
        try std.testing.expect(conn.lastSendPeer().eql(peer));
        try std.testing.expect(!conn.lastSendPeer().eql(direct_peer));
        const peer_space: packet.PacketNumSpace = .{
            .crypto_open = keys.current_open,
            .crypto_seal = keys.current_seal,
        };
        var outgoing_reader = io.fixedBufferStream(outgoing[0..length]);
        var outgoing_header = try packet.Header.parse(&outgoing_reader, 8);
        const plaintext = try packet.decryptForPath(&outgoing_header, &outgoing_reader, &peer_space, 0);
        var remaining = plaintext;
        var found_application = false;
        while (remaining.len > 0) {
            var consumed: usize = undefined;
            const frame = try Frame.parseSized(remaining, &consumed);
            try std.testing.expect(consumed > 0);
            if (frame == .stream and frame.stream.stream_id == stream.stream_id) {
                try std.testing.expectEqual(@as(u64, 0), frame.stream.offset);
                try std.testing.expectEqualStrings(application, frame.stream.data);
                try std.testing.expect(frame.stream.fin);
                found_application = true;
            }
            remaining = remaining[consumed..];
        }
        try std.testing.expect(found_application);
    }
}

test "PATH_ACK_ECN keeps per-path CE baselines and ignores duplicate or offpath-only feedback" {
    var peer_cid_bytes: [8]u8 = "peerpath".*;
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 1 };
    conn.native_paths.entries[1].opened = true;
    const other = try conn.ensurePathTransport();
    conn.ecn_validator.start();
    other.ecn_state.start();
    var random = std.Random.DefaultPrng.init(106);
    try configureNativeTestIngress(&conn, &peer_cid_bytes, random.random());
    other.handler.next_pn[2] = 50;
    const before0 = conn.cc.congestion_window;
    const before1 = other.cc.congestion_window;
    for ([_]u1{ 0, 1 }) |id| {
        const pn = try sendNativeTestPing(&conn, id, 1, random.random());
        try std.testing.expectEqual(if (id == 0) @as(u64, 0) else 50, pn);
        const ack: Frame = .{ .path_ack_ecn = .{ .path_id = id, .ack = .{
            .largest_ack = pn,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 1,
        } } };
        try recvNativeTestFrame(&conn, ack, id ^ 1, 100 + @as(i64, id), random.random());
    }
    try std.testing.expectEqual(@as(u64, 1), conn.peer_ecn_ce[2]);
    try std.testing.expectEqual(@as(u64, 1), other.peer_ecn_ce);
    try std.testing.expect(conn.cc.congestion_window < before0);
    try std.testing.expect(other.cc.congestion_window < before1);
    try std.testing.expectEqual(@as(u64, 1), conn.ecn_validator.acked_ect0_count);
    try std.testing.expectEqual(@as(u64, 1), other.ecn_state.acked_ect0_count);
    const original0 = conn.cc;
    const original1 = other.cc;
    const original_ecn1 = other.ecn_state;
    const original_ecn0 = conn.ecn_validator;
    for ([_]bool{ false, true }) |off_path_only| {
        if (off_path_only) {
            var wire: [1500]u8 = undefined;
            conn.packer.application_path_id = 0;
            try std.testing.expect(try conn.packer.packOffPath(&wire, &conn.pkt_handler, conn.appSeal().?, .{ .challenge = .{1} ** 8 }, random.random()) > 0);
        }
        const target_path: u1 = if (off_path_only) 0 else 1;
        const pn = if (target_path == 0) conn.pkt_handler.next_pn[2] - 1 else other.handler.next_pn[2] - 1;
        const ack: Frame = .{ .path_ack_ecn = .{ .path_id = target_path, .ack = .{
            .largest_ack = pn,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 99,
        } } };
        try recvNativeTestFrame(&conn, ack, if (off_path_only) 1 else 0, 200, random.random());
        try std.testing.expectEqual(@as(u64, 1), other.peer_ecn_ce);
        try std.testing.expectEqual(@as(u64, 1), conn.peer_ecn_ce[2]);
        try std.testing.expectEqualDeep(original0, conn.cc);
        try std.testing.expectEqualDeep(original1, other.cc);
        try std.testing.expectEqualDeep(original_ecn1, other.ecn_state);
        try std.testing.expectEqualDeep(original_ecn0, conn.ecn_validator);
    }
    const lower = try sendNativeTestPing(&conn, 1, 300, random.random());
    const higher = try sendNativeTestPing(&conn, 1, 301, random.random());
    const higher_ack: Frame = .{ .path_ack_ecn = .{ .path_id = 1, .ack = .{
        .largest_ack = higher,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_range_count = 0,
        .ack_ranges = undefined,
        .ecn_ect0 = 0,
        .ecn_ect1 = 0,
        .ecn_ce = 2,
    } } };
    try recvNativeTestFrame(&conn, higher_ack, 0, 400, random.random());
    try std.testing.expectEqual(@as(usize, 1), other.handler.sent[2].sent_packets.count());
    const newest_validator = other.ecn_state;
    const lower_ack: Frame = .{ .path_ack_ecn = .{ .path_id = 1, .ack = .{
        .largest_ack = lower,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_range_count = 0,
        .ack_ranges = undefined,
        .ecn_ect0 = 0,
        .ecn_ect1 = 0,
        .ecn_ce = 0,
    } } };
    try recvNativeTestFrame(&conn, lower_ack, 1, 401, random.random());
    try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].sent_packets.count());
    try std.testing.expectEqual(@as(u64, 2), other.peer_ecn_ce);
    try std.testing.expectEqualDeep(newest_validator, other.ecn_state);
    const pn0 = try sendNativeTestPing(&conn, 0, 500, random.random());
    const ordinary: Frame = .{ .ack_ecn = .{
        .largest_ack = pn0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_range_count = 0,
        .ack_ranges = undefined,
        .ecn_ect0 = 0,
        .ecn_ect1 = 0,
        .ecn_ce = 2,
    } };
    const direct_cc = other.cc;
    try recvNativeTestFrame(&conn, ordinary, 1, 600, random.random());
    try std.testing.expectEqual(@as(u8, 0), conn.transport_path);
    try std.testing.expectEqual(@as(u64, 2), conn.peer_ecn_ce[2]);
    try std.testing.expectEqual(@as(u64, 2), other.peer_ecn_ce);
    try std.testing.expectEqualDeep(direct_cc, other.cc);
}

test "native remote PATH_ABANDON unknown and duplicate closed paths never close connection" {
    var peer_cid_bytes: [8]u8 = "peerpath".*;
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.state = .connected;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{ .initial_max_path_id = 0 };
    conn.native_paths = try native_path.process(.{}, .{
        .negotiate = .{ .local_max = 1, .peer_max = 0 },
    });
    var random = std.Random.DefaultPrng.init(107);
    try configureNativeTestIngress(&conn, &peer_cid_bytes, random.random());
    const abandon: Frame = .{ .path_abandon = .{ .path_id = 1, .error_code = 0 } };
    try recvNativeTestFrame(&conn, abandon, 0, 1, random.random());
    try std.testing.expectEqual(State.connected, conn.state);
    const unknown: Frame = .{ .path_abandon = .{ .path_id = 7, .error_code = 0 } };
    try recvNativeTestFrame(&conn, unknown, 0, 1, random.random());
    conn.local_params.initial_max_path_id = 0;
    conn.native_paths.local_max_path_id = 0;
    const bounded = conn.native_paths;
    try recvNativeTestFrame(&conn, abandon, 0, 1, random.random());
    try std.testing.expectEqualDeep(bounded, conn.native_paths);
    try std.testing.expectEqual(State.connected, conn.state);
    conn.local_params.initial_max_path_id = 1;
    conn.native_paths.local_max_path_id = 1;
    conn.native_paths.peer_max_path_id = 1;
    conn.native_paths.entries[1] = .{ .opened = true, .validated = true };
    conn.native_paths.selected = 1;
    conn.active_path_idx = 1;
    try recvNativeTestFrame(&conn, abandon, 1, 2, random.random());
    const closed = conn.native_paths;
    try recvNativeTestFrame(&conn, abandon, 0, 3, random.random());
    try std.testing.expectEqualDeep(closed, conn.native_paths);
    try std.testing.expectEqual(State.connected, conn.state);
    try std.testing.expect(conn.local_err == null);
    try std.testing.expectEqual(@as(u8, 0), conn.active_path_idx);
}

test "ordered CE feedback for already in-flight packet does not restart native path recovery" {
    var random = std.Random.DefaultPrng.init(108);
    for ([_]u1{ 0, 1 }) |path_id| {
        var peer_cid_bytes: [8]u8 = "peerpath".*;
        var conn = testConnection(std.testing.allocator);
        defer conn.deinit();
        conn.local_params.initial_max_path_id = 1;
        conn.peer_params = .{ .initial_max_path_id = 1 };
        conn.native_paths.entries[1].opened = true;
        const other = try conn.ensurePathTransport();
        try configureNativeTestIngress(&conn, &peer_cid_bytes, random.random());
        conn.paths[1].is_initial = false;
        conn.ecn_validator.start();
        other.ecn_state.start();
        other.handler.next_pn[2] = 50;
        const first = try sendNativeTestPing(&conn, path_id, 0, random.random());
        const second = try sendNativeTestPing(&conn, path_id, 50, random.random());
        const handler = if (path_id == 0) &conn.pkt_handler else &other.handler;
        try std.testing.expectEqual(@as(i64, 0), handler.sent[2].sent_packets.get(first).?.time_sent);
        try std.testing.expectEqual(@as(i64, 50), handler.sent[2].sent_packets.get(second).?.time_sent);
        const cc = if (path_id == 0) &conn.cc else &other.cc;
        const original_window = cc.congestion_window;
        const first_ack: Frame = .{ .path_ack_ecn = .{ .path_id = path_id, .ack = .{
            .largest_ack = first,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 1,
        } } };
        try recvNativeTestFrame(&conn, first_ack, path_id ^ 1, 100, random.random());
        try std.testing.expect(cc.congestion_window < original_window);
        try std.testing.expectEqual(@as(?i64, 100), cc.congestion_recovery_start_time);
        try std.testing.expectEqual(@as(usize, 1), handler.sent[2].sent_packets.count());
        const recovery_window = cc.congestion_window;
        const recovery_start = cc.congestion_recovery_start_time;
        const cubic_epoch = cc.epoch_start;
        const second_ack: Frame = .{ .path_ack_ecn = .{ .path_id = path_id, .ack = .{
            .largest_ack = second,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_range_count = 0,
            .ack_ranges = undefined,
            .ecn_ect0 = 0,
            .ecn_ect1 = 0,
            .ecn_ce = 2,
        } } };
        try recvNativeTestFrame(&conn, second_ack, path_id, 200, random.random());
        try std.testing.expectEqual(@as(usize, 0), handler.sent[2].sent_packets.count());
        const peer_ce = if (path_id == 0) conn.peer_ecn_ce[2] else other.peer_ecn_ce;
        const validator = if (path_id == 0) &conn.ecn_validator else &other.ecn_state;
        try std.testing.expectEqual(@as(u64, 2), peer_ce);
        try std.testing.expectEqual(@as(u64, 2), validator.acked_ect0_count);
        try std.testing.expectEqual(recovery_window, cc.congestion_window);
        try std.testing.expectEqual(recovery_start, cc.congestion_recovery_start_time);
        try std.testing.expectEqual(cubic_epoch, cc.epoch_start);
    }
}

test "native teardown releases both owned packet handlers regardless of active transport" {
    var random = std.Random.DefaultPrng.init(109);
    for ([_]u8{ 0, 1 }) |active| {
        var conn = testConnectionForRole(std.testing.allocator, false);
        defer conn.deinit();
        const other = try conn.ensurePathTransport();
        for ([_]*ack_handler.PacketHandler{ &conn.pkt_handler, &other.handler }) |handler| {
            const pn = handler.nextPacketNumber(.application, random.random());
            try handler.onPacketSent(.{
                .pn = pn,
                .time_sent = 1,
                .size = 100,
                .enc_level = .application,
                .ack_eliciting = true,
                .in_flight = true,
            });
            try std.testing.expectEqual(@as(usize, 1), handler.sent[2].sent_packets.count());
        }
        conn.activateTransport(active);
    }
}

test "native control recording OOM finishes the connection and discards the output" {
    // Both the packet pool and its index allocate after the challenge was consumed.
    for (0..2) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var conn = testConnectionForRole(failing.allocator(), false);
        defer conn.deinit();
        conn.state = .connected;
        conn.handshake_confirmed = true;
        const keys = try quic_crypto.deriveInitialKeyMaterial(
            "control-recording",
            conn.version,
            false,
        );
        conn.installAppKeys(keys[0], keys[1]);
        conn.path_control[0].push(.{ .path_challenge = .{0x5a} ** 8 });
        var random = std.Random.DefaultPrng.init(110);
        var output: [1500]u8 = undefined;
        var accepted_length: usize = 0;
        if (conn.sendAt(&output, 1, random.random())) |written| {
            accepted_length = written;
            return error.TestExpectedControlRecordingRefusal;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
        // An error publishes no prefix; the buffer is deliberately not inspected.
        try std.testing.expectEqual(@as(usize, 0), accepted_length);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), conn.path_control[0].len);
        try std.testing.expectEqual(@as(usize, 0), conn.pkt_handler.sent[2].sent_packets.count());
        try std.testing.expectEqual(@as(u64, 0), conn.pkt_handler.bytes_in_flight);
        try std.testing.expectEqual(State.closing, conn.state);
        try std.testing.expect(!conn.local_err.?.is_app);
        try std.testing.expectEqual(
            @as(u64, @intFromEnum(TransportError.internal_error)),
            conn.local_err.?.code,
        );
    }
}

fn deliverNativeReliabilityPacket(
    receiver: *Connection,
    output: []u8,
    open: quic_crypto.Open,
    stream_id: u64,
    application: []const u8,
    now: i64,
    random: std.Random,
) !bool {
    const space: packet.PacketNumSpace = .{ .crypto_open = open };
    var reader = io.fixedBufferStream(output);
    var header = try packet.Header.parse(&reader, 8);
    const plaintext = try packet.decryptForPath(&header, &reader, &space, 0);
    var remaining = plaintext;
    var delivered = false;
    for (0..1500) |_| {
        if (remaining.len == 0) break;
        var consumed: usize = undefined;
        const frame = try Frame.parseSized(remaining, &consumed);
        try std.testing.expect(consumed > 0);
        if (frame == .stream and frame.stream.stream_id == stream_id) {
            try std.testing.expectEqual(@as(u64, 0), frame.stream.offset);
            try std.testing.expectEqualStrings(application, frame.stream.data);
            try std.testing.expect(frame.stream.fin);
            try receiver.processFrame(&frame, .application, now, random);
            delivered = true;
        }
        remaining = remaining[consumed..];
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.len);
    return delivered;
}

test "native abandoned path retransmits outstanding STREAM FIN and surviving PTO completes" {
    // Lose path1's only flight; path0 is idle, so no unrelated PTO can rescue it.
    var random = std.Random.DefaultPrng.init(111);
    var conn = testConnectionForRole(std.testing.allocator, false);
    defer conn.deinit();
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.local_params.initial_max_path_id = 1;
    conn.peer_params = .{
        .initial_max_path_id = 1,
        .initial_max_streams_uni = 1,
        .initial_max_stream_data_uni = 4096,
        .initial_max_data = 4096,
    };
    conn.native_paths = try native_path.process(.{}, .{
        .negotiate = .{ .local_max = 1, .peer_max = 1 },
    });
    conn.native_paths.entries[1] = .{ .opened = true, .validated = true };
    const local = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    const relay = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 2000);
    const direct = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 3000);
    conn.paths[0] = NetworkPath.init(local, relay, true);
    conn.paths[1] = NetworkPath.init(local, direct, false);
    conn.paths[0].is_validated = true;
    conn.paths[1].is_validated = true;
    conn.path_initialized = true;
    const other = try conn.ensurePathTransport();
    @memcpy(other.dcid[0..8], "path-one");
    other.dcid_len = 8;
    const keys = try quic_crypto.deriveInitialKeyMaterial("path-reliability", conn.version, false);
    conn.installAppKeys(keys[0], keys[1]);
    const peer_keys = try quic_crypto.deriveInitialKeyMaterial(
        "path-reliability",
        conn.version,
        true,
    );
    conn.streams.setMaxStreams(0, 1);
    conn.streams.setPeerInitialMaxStreamData(0, 0, 4096);
    conn.conn_flow_ctrl.base.send_window = 4096;
    const stream = try conn.openUniStream();
    const stream_id = stream.stream_id;
    const application = "outstanding path1 bytes and FIN survive";
    try stream.writeData(application);
    stream.close();
    try conn.selectPath(1);
    var output: [1500]u8 = undefined;
    try std.testing.expect(try conn.sendAt(&output, 1, random.random()) > 0);
    try std.testing.expectEqual(@as(u8, 1), conn.send_path);
    try std.testing.expectEqual(@as(u64, 0), conn.pkt_handler.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), conn.pkt_handler.sent[2].ack_eliciting_in_flight);
    try std.testing.expect(conn.pkt_handler.getPtoTimeout() == null);
    try std.testing.expect(!stream.hasData());
    const abandoned_deadline = other.handler.getPtoTimeout().?;
    try conn.processFrame(&.{ .path_abandon = .{
        .path_id = 1,
        .error_code = 0,
    } }, .application, 2, random.random());
    try std.testing.expectEqual(State.connected, conn.state);
    try std.testing.expectEqual(@as(u8, 0), conn.active_path_idx);
    try std.testing.expect(stream.hasRetransmitData());
    try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].sent_packets.count());
    try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].live);
    try std.testing.expectEqual(@as(u64, 0), other.handler.bytes_in_flight);
    try std.testing.expect(other.handler.getPtoTimeout() == null);
    try conn.onTimeout(abandoned_deadline, random.random());
    // This retry is lost too: recovery must now be driven by path0's own PTO.
    const retried = try conn.sendAt(&output, abandoned_deadline, random.random());
    try std.testing.expect(retried > 0);
    try std.testing.expectEqual(@as(u8, 0), conn.send_path);
    try std.testing.expect(conn.lastSendPeer().eql(relay));
    try std.testing.expect(!stream.hasRetransmitData());
    try conn.processFrame(&.{ .path_abandon = .{
        .path_id = 1,
        .error_code = 0,
    } }, .application, abandoned_deadline + 1, random.random());
    try conn.processFrame(&.{ .path_ack = .{
        .path_id = 1,
        .ack = .{
            .largest_ack = other.handler.next_pn[2] - 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
    } }, .application, abandoned_deadline + 1, random.random());
    try std.testing.expect(!stream.hasRetransmitData());
    try std.testing.expectEqual(@as(usize, 0), other.handler.sent[2].live);
    var receiver = testConnection(std.testing.allocator);
    defer receiver.deinit();
    receiver.streams.setMaxIncomingStreams(0, 1);
    try std.testing.expect(try deliverNativeReliabilityPacket(
        &receiver,
        output[0..retried],
        peer_keys[0],
        stream_id,
        application,
        abandoned_deadline,
        random.random(),
    ));
    // Use a new receiver so the retry above remains lost to the actual consumer.
    var final_receiver = testConnection(std.testing.allocator);
    defer final_receiver.deinit();
    final_receiver.streams.setMaxIncomingStreams(0, 1);
    const surviving_deadline = conn.pkt_handler.getPtoTimeout().?;
    try conn.onTimeout(surviving_deadline, random.random());
    var delivered = false;
    for (0..4) |_| {
        const length = try conn.sendAt(&output, surviving_deadline, random.random());
        if (length == 0) break;
        try std.testing.expectEqual(@as(u8, 0), conn.send_path);
        if (try deliverNativeReliabilityPacket(
            &final_receiver,
            output[0..length],
            peer_keys[0],
            stream_id,
            application,
            surviving_deadline,
            random.random(),
        )) {
            delivered = true;
            const pn = conn.pkt_handler.next_pn[2] - 1;
            try conn.processFrame(&.{ .ack = .{
                .largest_ack = pn,
                .ack_delay = 0,
                .first_ack_range = 0,
            } }, .application, surviving_deadline + 1, random.random());
            break;
        }
    }
    try std.testing.expect(delivered);
    const received = final_receiver.streams.getRecvStream(stream_id).?;
    const data = received.read().?;
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualStrings(application, data);
    try std.testing.expectEqual(@as(?u64, application.len), received.sorter.fin_offset);
    try std.testing.expect(received.read() == null);
    try std.testing.expect(received.finished);
    conn.streams.drainDisposalQueue();
    try std.testing.expect(conn.streams.send_streams.get(stream_id) == null);
}
