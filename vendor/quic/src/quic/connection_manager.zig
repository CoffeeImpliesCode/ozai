//! Server-side CID routing, connection ownership and bounded stateless replies.
//! `recvDatagram` processes caller-owned bytes; the caller sends any response
//! and supplies time and entropy. No socket or clock is owned here.
//! Entries and their connections are borrowed until deferred destruction.
//! Serialize calls, finish each event pass before `freeDeadEntries`, and release
//! the manager exactly once with `deinit`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const address = @import("../address.zig");
const io = @import("../io_compat.zig");

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const protocol = @import("protocol.zig");
const stateless_reset = @import("stateless_reset.zig");
const quic_lb = @import("quic_lb.zig");
const tls13 = @import("tls13.zig");
const crypto = @import("crypto.zig");
const frame_mod = @import("frame.zig");

// Upstream hung an H3 connection, an h0 connection and a WebTransport
// session off every `ConnEntry`, and `destroyProtocols` tore the three down
// in a fixed order. They are gone because nothing can set them: ozai speaks
// raw QUIC, and the socket-owning event loop that created them was never
// vendored. A field that is always null and a teardown branch that is never
// taken are dead weight. What is left — the entry table, `recvDatagram`,
// the connection lifecycle — is the whole ingress seam.

/// Fixed-size CID key for use in HashMap lookups.
pub const CidKey = struct {
    /// Inline CID bytes; only the prefix selected by `len` participates in routing.
    buf: [20]u8 = .{0} ** 20,
    /// Initialized prefix length in bytes, in 0..20.
    len: u8 = 0,

    /// Copy up to 20 bytes; a longer input is truncated rather than rejected.
    pub fn fromSlice(s: []const u8) CidKey {
        var key = CidKey{};
        key.len = @intCast(@min(s.len, 20));
        @memcpy(key.buf[0..key.len], s[0..key.len]);
        return key;
    }

    /// Borrow the initialized prefix until this key is changed or released.
    pub fn getSlice(self: *const CidKey) []const u8 {
        return self.buf[0..self.len];
    }
};

/// A peer's stateless reset token under a keyed PRF: the map lookup then
/// cannot time-leak token bytes (RFC 9000 §10.3.1).
pub const ResetKey = [16]u8;

/// Hash/equality context for CidKey in HashMap.
pub const CidKeyContext = struct {
    /// Hash only the initialized prefix; requires `key.len <= 20`.
    pub fn hash(_: CidKeyContext, key: CidKey) u64 {
        return std.hash.Wyhash.hash(0, key.buf[0..key.len]);
    }

    /// Compare lengths and initialized prefixes; both lengths must be at most 20.
    pub fn eql(_: CidKeyContext, a: CidKey, b: CidKey) bool {
        if (a.len != b.len) return false;
        return std.mem.eql(u8, a.buf[0..a.len], b.buf[0..b.len]);
    }
};

/// Per-connection wrapper holding the heap-allocated Connection.
///
/// Heap-allocated, so its address is stable from `acceptConnection` until
/// `freeDeadEntries` releases it.
pub const ConnEntry = struct {
    /// Manager-owned connection; invalid after this entry is freed.
    conn: *connection.Connection,
    /// Unique per manager, never reused.
    id: u64 = 0,

    /// Borrowed application context. The manager neither calls nor releases it.
    datagram_handler_ctx: ?*anyopaque = null,

    /// Synchronous notification on the thread calling `wake`; no call when
    /// this or `wake_ctx` is null. Retain callback code and context until cleared
    /// or the entry is freed; this method queues no work and adds no synchronization.
    wake_fn: ?*const fn (ctx: *anyopaque) void = null,
    /// Borrowed context shared by `wake_fn` and `repoll_fn`.
    wake_ctx: ?*anyopaque = null,

    /// Synchronous notification on the thread calling `repoll`, using
    /// `wake_ctx`. Either null suppresses the call. Keep code and context alive
    /// until cleared or the entry is freed; the caller performs the next poll.
    repoll_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Stream IDs whose FIN the application has received; owned map.
    finished_streams: std.AutoArrayHashMapUnmanaged(u64, void) = .empty,

    /// Routing keys registered for this entry; only the counted prefix is valid.
    registered_cids: [9]CidKey = .{CidKey{}} ** 9,
    /// Initialized routing keys, at most the nine inline slots.
    registered_cid_count: u8 = 0,
    /// Client's current Initial DCID, retained for retransmission routing.
    /// `acceptConnection` copies it; null on a manually constructed entry.
    initial_dcid: ?CidKey = null,

    /// Reset-map keys for peer CIDs; only `reset_key_count` slots are initialized.
    reset_keys: [16]ResetKey = undefined,
    /// Initialized reset keys, in 0..16 across the two native paths.
    reset_key_count: u8 = 0,
    /// Last synchronized generations for path zero and one; null before synchronization.
    reset_pool_gens: ?[2]u32 = null,

    /// Tell the owner there is data to send; see `wake_fn`.
    pub fn wake(self: *ConnEntry) void {
        if (self.wake_fn) |f| f(self.wake_ctx orelse return);
    }

    /// Ask the owner for another poll pass; see `repoll_fn`.
    pub fn repoll(self: *ConnEntry) void {
        if (self.repoll_fn) |f| f(self.wake_ctx orelse return);
    }

    fn addRegisteredCid(self: *ConnEntry, key: CidKey) void {
        std.debug.assert(self.registered_cid_count < self.registered_cids.len);
        std.debug.assert(!self.hasRegisteredCid(key));
        self.registered_cids[self.registered_cid_count] = key;
        self.registered_cid_count += 1;
    }

    fn hasRegisteredCid(self: *const ConnEntry, key: CidKey) bool {
        return containsCid(self.registered_cids[0..self.registered_cid_count], key);
    }

    fn removeRegisteredCid(self: *ConnEntry, index: usize) void {
        std.debug.assert(index < self.registered_cid_count);
        self.registered_cid_count -= 1;
        self.registered_cids[index] = self.registered_cids[self.registered_cid_count];
        self.registered_cids[self.registered_cid_count] = .{};
    }
};

fn containsCid(keys: []const CidKey, key: CidKey) bool {
    std.debug.assert(keys.len <= 9);
    for (keys) |registered| {
        if (CidKeyContext.eql(.{}, registered, key)) return true;
    }
    return false;
}

fn activeCid(pool: *const connection.LocalCidPool, key: CidKey) bool {
    for (&pool.entries) |*entry| {
        if (!entry.occupied or entry.retired or entry.cid_len != key.len) continue;
        if (std.mem.eql(u8, entry.getCid(), key.getSlice())) return true;
    }
    return false;
}

fn unregisteredCids(entry: *const ConnEntry, keys: *[9]CidKey) u8 {
    var count: u8 = 0;
    if (entry.initial_dcid) |key| {
        if (!entry.hasRegisteredCid(key)) {
            keys[count] = key;
            count += 1;
        }
    }
    for (&entry.conn.local_cid_pool.entries) |*cid_entry| {
        if (!cid_entry.occupied or cid_entry.retired or cid_entry.cid_len == 0) continue;
        const key = CidKey.fromSlice(cid_entry.getCid());
        if (entry.hasRegisteredCid(key) or containsCid(keys[0..count], key)) continue;
        std.debug.assert(count < keys.len);
        keys[count] = key;
        count += 1;
    }
    return count;
}

/// Smallest datagram that may open a connection or earn a Version
/// Negotiation reply (RFC 9000 14.1, 6).
pub const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Shortest client-chosen DCID on a connection's first Initial (RFC 9000 7.2).
pub const MIN_INITIAL_DCID_LEN: usize = 8;

/// Largest datagram a stateless reset is never sent for: anything this short
/// may itself be a reset, and answering one invites a loop (RFC 9000 10.3.3).
pub const MIN_RESET_TRIGGER: usize = 43;

/// Token bucket for the replies we send without connection state — Version
/// Negotiation, stateless reset, CONNECTION_REFUSED. Each costs a send an
/// off-path attacker can trigger with a spoofed source, so their rate is
/// capped server-wide rather than tied to what arrives.
pub const ReplyLimiter = struct {
    /// Replies allowed per second, and the burst held in reserve. Zero
    /// disables stateless replies altogether.
    per_second: u32 = 200,
    /// Available reply credits, in 0..per_second for a consistently configured bucket.
    tokens: u32 = 200,
    /// Last refill time in nanoseconds, using the same epoch as `allow`.
    last_refill_ns: i64 = 0,

    /// Spend one reply credit, or return false without sending anything.
    /// `now` is nanoseconds in the bucket's epoch. A backward time step resets
    /// the refill origin without granting credits; zero rate always refuses.
    pub fn allow(self: *ReplyLimiter, now: i64) bool {
        if (self.per_second == 0) return false;
        const elapsed = now - self.last_refill_ns;
        if (elapsed > 0) {
            const earned: u64 = @intCast(@divTrunc(@as(i128, elapsed) * @as(i128, self.per_second), std.time.ns_per_s));
            if (earned > 0) {
                self.tokens = @intCast(@min(@as(u64, self.tokens) + earned, self.per_second));
                self.last_refill_ns = now;
            }
        } else if (elapsed < 0) {
            self.last_refill_ns = now;
        }
        if (self.tokens == 0) return false;
        self.tokens -= 1;
        return true;
    }
};

/// One `ReplyLimiter` per kind of stateless reply, so junk that triggers one
/// kind — spoofed short headers soliciting resets, say — cannot spend the
/// budget that CONNECTION_REFUSED or Version Negotiation owe real clients.
pub const ReplyLimits = struct {
    /// Independent Version Negotiation reply budget.
    version_negotiation: ReplyLimiter = .{},
    /// Independent stateless reset reply budget.
    stateless_reset: ReplyLimiter = .{},
    /// Independent CONNECTION_REFUSED reply budget.
    refusal: ReplyLimiter = .{},

    /// Each kind gets `per_second`, with a burst of the same size.
    pub fn init(per_second: u32) ReplyLimits {
        const l: ReplyLimiter = .{ .per_second = per_second, .tokens = per_second };
        return .{ .version_negotiation = l, .stateless_reset = l, .refusal = l };
    }
};

/// Manages multiple QUIC connections, routing packets by DCID.
///
/// Owns connections, entries and routing tables through the retained allocator.
/// Copies share those resources; release one owner exactly once with `deinit`.
/// Serialize calls and use of borrowed entries. The allocator and TLS
/// configuration's borrowed slices must outlive the manager and its connections.
pub const ConnectionManager = struct {
    /// Initial live-connection limit; callers may change `max_connections`.
    pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

    /// Retained allocator for maps, entries and connections; borrowed until teardown.
    allocator: Allocator,

    /// New connections past this many live ones are refused.
    max_connections: usize = DEFAULT_MAX_CONNECTIONS,
    /// Next entry identity, starting at one. Acceptance increments it; must not wrap.
    next_entry_id: u64 = 1,
    /// Owned routing map; values borrow entries also held in `entries`.
    cid_map: std.HashMap(CidKey, *ConnEntry, CidKeyContext, 80),
    /// Owned live-entry list; entries and their connections are owned allocations.
    entries: std.ArrayList(*ConnEntry),

    /// Peer-issued stateless reset tokens, so a reset from a client that
    /// lost state finds its connection even though its DCID is random.
    reset_token_map: std.AutoHashMapUnmanaged(ResetKey, *ConnEntry) = .empty,
    /// Per-manager copied key for keyed reset-token lookup; drawn by `init`.
    reset_lookup_key: [16]u8,
    /// Removals from the two maps above since their tombstones were cleared.
    /// std's HashMap never clears them itself, and every connection ID a
    /// server hands out is inserted and later removed: see `noteRemovals`.
    removed_since_rehash: usize = 0,

    /// Copied server TLS settings; nested slices and pointers retain their borrows.
    tls_config: tls13.TlsConfig,
    /// Copied settings applied when a connection is accepted.
    conn_config: connection.ConnectionConfig,
    /// Copied key for sealing and validating address-validation Retry tokens.
    retry_token_key: [16]u8,
    /// Copied key shared by connection-issued tokens and stateless reset replies.
    static_reset_key: [16]u8,
    /// Short-header CID length in bytes, in 0..20. Derived from QUIC-LB, or eight.
    local_cid_len: u8 = 8,

    /// When true, Initial packets without a valid token get a Retry response.
    require_retry: bool = false,

    /// Also send Retry once this many connections are live, so a loaded
    /// server spends state only on clients that proved their address.
    retry_threshold: ?usize = null,

    /// When true, every new connection is answered with CONNECTION_REFUSED,
    /// as it is at `max_connections`. Set while a server drains.
    refuse_new: bool = false,

    /// Budgets for stateless replies; see `ReplyLimits`.
    reply_limits: ReplyLimits = .{},

    /// Report packets for another server as `foreign` instead of answering
    /// them with a stateless reset. Needs `conn_config.quic_lb`: a
    /// Handshake or 1-RTT packet whose unknown DCID decodes, under the same
    /// config_id, to a server id other than ours belongs to a sibling server
    /// — typically another worker thread on the same port.
    steer_foreign: bool = false,
    /// Scratch for `RecvAction.foreign`; only the returned prefix is valid,
    /// and the next foreign-ID extraction overwrites it.
    foreign_id: [15]u8 = undefined,

    /// Removed entries awaiting `freeDeadEntries`; still owned, not live-routable.
    /// Acceptance reserves these slots before publishing an entry.
    dead_entries: std.ArrayList(*ConnEntry) = .empty,

    /// Create an empty manager retaining both configurations by value.
    /// TLS certificate, ALPN and resumption-ticket slices are borrowed, not
    /// copied. Keep them alive and unchanged until all users are released.
    /// Draws one lookup key from `random`; performs no allocation or I/O.
    pub fn init(
        allocator: Allocator,
        tls_config: tls13.TlsConfig,
        conn_config: connection.ConnectionConfig,
        retry_token_key: [16]u8,
        static_reset_key: [16]u8,
        random: std.Random,
    ) ConnectionManager {
        // The SipHash key that hides a reset token behind a keyed PRF. Drawn
        // once here and never again; every other draw in this file is
        // forwarded from the caller's own `random`.
        var lookup_key: [16]u8 = undefined;
        random.bytes(&lookup_key);
        // Connections must advertise tokens under the key our resets use.
        var cc = conn_config;
        cc.static_reset_key = static_reset_key;
        return .{
            .allocator = allocator,
            .cid_map = std.HashMap(CidKey, *ConnEntry, CidKeyContext, 80).init(allocator),
            .entries = .{ .items = &.{}, .capacity = 0 },
            .reset_lookup_key = lookup_key,
            .tls_config = tls_config,
            .conn_config = cc,
            .retry_token_key = retry_token_key,
            .static_reset_key = static_reset_key,
            .local_cid_len = if (conn_config.quic_lb) |lb| quic_lb.cidLength(&lb) else 8,
        };
    }

    /// Release every live and deferred entry and connection, then routing state.
    /// Invalidates every borrowed entry, connection and stream. This does not
    /// release the caller's allocator or borrowed configuration slices.
    /// Call exactly once; copies and a repeated call are not protected.
    pub fn deinit(self: *ConnectionManager) void {
        // Free deferred-dead entries first
        self.freeDeadEntries();
        // Clean up all live connections
        for (self.entries.items) |entry| {
            entry.finished_streams.deinit(self.allocator);
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.destroy(entry);
        }
        self.entries.deinit(self.allocator);
        self.dead_entries.deinit(self.allocator);
        self.cid_map.deinit();
        self.reset_token_map.deinit(self.allocator);
    }

    fn resetKey(self: *const ConnectionManager, token: *const [16]u8) ResetKey {
        var out: ResetKey = undefined;
        std.crypto.auth.siphash.SipHash128(1, 3).create(&out, token, &self.reset_lookup_key);
        return out;
    }

    /// The connection whose peer issued the reset token `datagram` ends in.
    pub fn findByResetToken(self: *ConnectionManager, datagram: []const u8) ?*ConnEntry {
        if (datagram.len < stateless_reset.MIN_PACKET_LEN) return null;
        const key = self.resetKey(datagram[datagram.len - stateless_reset.TOKEN_LEN ..][0..stateless_reset.TOKEN_LEN]);
        return self.reset_token_map.get(key);
    }

    fn dropResetKeys(self: *ConnectionManager, entry: *ConnEntry) void {
        for (entry.reset_keys[0..entry.reset_key_count]) |k| {
            if (self.reset_token_map.get(k)) |owner| {
                if (owner == entry) _ = self.reset_token_map.remove(k);
            }
        }
        self.noteRemovals(entry.reset_key_count);
        entry.reset_key_count = 0;
    }

    /// Rehash the routing maps in place once removals pass a quarter of their
    /// capacity. A removal leaves a tombstone and returns the slot to the
    /// free count, so a long-running server's maps never grow past them;
    /// they fill with tombstones, and every packet's lookup probes through
    /// them. O(1) per removal, amortised.
    fn noteRemovals(self: *ConnectionManager, n: usize) void {
        self.removed_since_rehash += n;
        if (self.removed_since_rehash <= (self.cid_map.capacity() + self.reset_token_map.capacity()) / 4) return;
        self.removed_since_rehash = 0;
        if (self.cid_map.capacity() > 0) self.cid_map.rehash();
        if (self.reset_token_map.capacity() > 0) self.reset_token_map.rehash(std.hash_map.AutoContext(ResetKey){});
    }

    fn resetKeys(self: *const ConnectionManager, entry: *const ConnEntry, keys: *[16]ResetKey) u8 {
        var count: u8 = 0;
        for (0..2) |path_id| {
            for (entry.conn.peerPathCidEntries(@intCast(path_id))) |*cid_entry| {
                if (!cid_entry.occupied) continue;
                const key = self.resetKey(&cid_entry.stateless_reset_token);
                var duplicate = false;
                for (keys[0..count]) |existing| {
                    if (std.mem.eql(u8, &existing, &key)) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;
                std.debug.assert(count < keys.len);
                keys[count] = key;
                count += 1;
            }
        }
        return count;
    }

    /// Look up a connection entry by destination CID.
    pub fn findByDcid(self: *ConnectionManager, dcid: []const u8) ?*ConnEntry {
        const key = CidKey.fromSlice(dcid);
        return self.cid_map.get(key);
    }

    /// Accept a new incoming connection from an Initial packet.
    /// Heap-allocates the Connection: it is ~185 KB, and the entry table
    /// holds pointers either way.
    pub fn acceptConnection(
        self: *ConnectionManager,
        header: packet.Header,
        local: address.Address,
        remote: address.Address,
        odcid: ?[]const u8,
        retry_scid: ?[]const u8,
        now: i64,
        random: std.Random,
    ) !*ConnEntry {
        if (self.entries.items.len >= self.max_connections) {
            return error.TooManyConnections;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.dead_entries.ensureTotalCapacity(
            self.allocator,
            self.entries.items.len + self.dead_entries.items.len + 1,
        );

        // Allocate at the final address: transport parameters borrow inline CIDs.
        const conn = try self.allocator.create(connection.Connection);
        errdefer self.allocator.destroy(conn);
        try connection.Connection.acceptInto(
            conn,
            self.allocator,
            header,
            local,
            remote,
            true, // is_server
            self.conn_config,
            self.tls_config,
            odcid,
            retry_scid,
            now,
            random,
        );

        // Create entry
        errdefer conn.deinit();
        const entry = try self.allocator.create(ConnEntry);
        errdefer self.allocator.destroy(entry);
        const client_dcid_key = CidKey.fromSlice(header.dcid);
        entry.* = .{
            .conn = conn,
            .id = self.next_entry_id,
            .initial_dcid = client_dcid_key,
        };
        self.next_entry_id += 1;

        // Register server's SCID in the routing map
        const scid_key = CidKey.fromSlice(conn.scid[0..conn.scid_len]);
        try self.cid_map.put(scid_key, entry);
        entry.addRegisteredCid(scid_key);
        errdefer _ = self.cid_map.remove(scid_key);

        // Also register the client's initial DCID so retransmitted Initials route correctly
        try self.cid_map.put(client_dcid_key, entry);
        if (!entry.hasRegisteredCid(client_dcid_key)) entry.addRegisteredCid(client_dcid_key);

        self.entries.appendAssumeCapacity(entry);

        return entry;
    }

    /// Synchronize local CID routes and peer reset tokens, retaining Initial routing.
    /// Retirement is reconciled against the current pool, even after slot reuse.
    /// `error.OutOfMemory` leaves indexed keys, registration counts and the
    /// synchronized generation unchanged; map capacity may grow. Retry before
    /// sending newly issued CIDs. Requires a live entry owned by this manager.
    pub fn syncCids(self: *ConnectionManager, entry: *ConnEntry) error{OutOfMemory}!void {
        var new_cids: [9]CidKey = undefined;
        const new_cid_count = unregisteredCids(entry, &new_cids);
        var cid_growth: u32 = 0;
        for (new_cids[0..new_cid_count]) |key| {
            if (!self.cid_map.contains(key)) cid_growth += 1;
        }

        const peer_generations = [2]u32{
            entry.conn.peerPathCidGeneration(0),
            entry.conn.peerPathCidGeneration(1),
        };
        const update_resets = if (entry.reset_pool_gens) |previous|
            !std.mem.eql(u32, &previous, &peer_generations)
        else
            true;
        var reset_keys: [16]ResetKey = undefined;
        const reset_count = if (update_resets) self.resetKeys(entry, &reset_keys) else 0;
        var reset_growth: u32 = 0;
        for (reset_keys[0..reset_count]) |key| {
            if (!self.reset_token_map.contains(key)) reset_growth += 1;
        }
        try self.cid_map.ensureUnusedCapacity(cid_growth);
        try self.reset_token_map.ensureUnusedCapacity(self.allocator, reset_growth);

        var removed: usize = 0;
        var index: usize = 0;
        while (index < entry.registered_cid_count) {
            const key = entry.registered_cids[index];
            const initial = if (entry.initial_dcid) |cid| CidKeyContext.eql(.{}, cid, key) else false;
            if (initial or activeCid(&entry.conn.local_cid_pool, key)) {
                index += 1;
                continue;
            }
            if (self.cid_map.remove(key)) removed += 1;
            entry.removeRegisteredCid(index);
        }
        for (new_cids[0..new_cid_count]) |key| {
            self.cid_map.putAssumeCapacity(key, entry);
            entry.addRegisteredCid(key);
        }
        self.noteRemovals(removed);
        if (update_resets) {
            self.dropResetKeys(entry);
            for (reset_keys[0..reset_count]) |key| {
                self.reset_token_map.putAssumeCapacity(key, entry);
            }
            @memcpy(entry.reset_keys[0..reset_count], reset_keys[0..reset_count]);
            entry.reset_key_count = reset_count;
            entry.reset_pool_gens = peer_generations;
        }
    }

    /// Remove a terminated connection. It leaves the routing map at once, but
    /// its memory stands until `freeDeadEntries`, so an owner still holding
    /// the pointer this cycle reads a closed connection, not freed memory.
    pub fn removeConnection(self: *ConnectionManager, entry: *ConnEntry) void {
        // Unregister all CIDs from the routing map
        for (entry.registered_cids[0..entry.registered_cid_count]) |key| {
            _ = self.cid_map.remove(key);
        }
        self.noteRemovals(entry.registered_cid_count);
        self.dropResetKeys(entry);

        // Swap-remove from entries list
        var idx: usize = 0;
        while (idx < self.entries.items.len) : (idx += 1) {
            if (self.entries.items[idx] == entry) {
                _ = self.entries.swapRemove(idx);
                break;
            }
        }

        // Queue for deferred free (entry memory stays valid until freeDeadEntries).
        // Never allocates for an entry acceptConnection made; only one added
        // by hand can hit OOM here, and freeing it now beats leaking it.
        self.dead_entries.append(self.allocator, entry) catch self.freeDead(entry);
    }

    /// Free entries that were invalidated by removeConnection.
    /// Call after all event processing is complete for the current cycle.
    pub fn freeDeadEntries(self: *ConnectionManager) void {
        for (self.dead_entries.items) |entry| self.freeDead(entry);
        self.dead_entries.clearRetainingCapacity();
    }

    fn freeDead(self: *ConnectionManager, entry: *ConnEntry) void {
        entry.finished_streams.deinit(self.allocator);
        entry.conn.deinit();
        self.allocator.destroy(entry.conn);
        self.allocator.destroy(entry);
    }

    /// Result of processing a received UDP datagram.
    pub const RecvAction = union(enum) {
        /// Datagram was delivered to an existing or newly accepted connection.
        /// Borrowed until the entry is freed by `freeDeadEntries` or `deinit`.
        processed: *ConnEntry,
        /// A response packet (VN, Retry, or Stateless Reset) was written to
        /// out_buf and should be sent back to the source address.
        /// Borrows `out_buf` until that buffer is overwritten or released.
        send_response: []const u8,
        /// Datagram was unroutable or invalid; no action needed.
        dropped: void,
        /// Its DCID names another server (see `steer_foreign`); nothing was
        /// processed. The QUIC-LB server id it decoded to, valid until the
        /// next call.
        foreign: []const u8,
    };

    /// Process a raw UDP datagram: route by DCID, handle version negotiation,
    /// retry tokens, stateless reset, accept new connections, and parse
    /// coalesced packets (RFC 9000 §12.2).
    ///
    /// The application should send `send_response` data back to the source.
    /// `bytes` is borrowed for this call and may be decrypted in place.
    /// Response bytes borrow `out_buf`; consume them before reusing that buffer.
    /// A dropped datagram gives no valid output prefix.
    /// `error.OutOfMemory` from index synchronization may follow committed packet
    /// processing. Do not replay the decrypted bytes; retry `syncCids` on live
    /// entries before sending newly issued CIDs. Index keys remain valid on refusal.
    /// `now` is nanoseconds in the connections' clock epoch; `ecn_val` is the
    /// received IP ECN field. Entropy is drawn only from the supplied generator.
    pub fn recvDatagram(
        self: *ConnectionManager,
        bytes: []u8,
        from: address.Address,
        local: address.Address,
        ecn_val: u2,
        out_buf: []u8,
        now: i64,
        random: std.Random,
    ) error{OutOfMemory}!RecvAction {
        return self.route(bytes, from, local, ecn_val, out_buf, now, random, self.steer_foreign);
    }

    /// `recvDatagram` for a datagram another server already reported as
    /// `foreign` and handed to us: never reported as foreign again, so a
    /// DCID nobody owns cannot bounce between servers.
    /// Has the same input borrows and allocation-failure residue as `recvDatagram`.
    pub fn recvHandedOver(
        self: *ConnectionManager,
        bytes: []u8,
        from: address.Address,
        local: address.Address,
        ecn_val: u2,
        out_buf: []u8,
        now: i64,
        random: std.Random,
    ) error{OutOfMemory}!RecvAction {
        return self.route(bytes, from, local, ecn_val, out_buf, now, random, false);
    }

    fn route(
        self: *ConnectionManager,
        bytes: []u8,
        from: address.Address,
        local: address.Address,
        ecn_val: u2,
        out_buf: []u8,
        now: i64,
        random: std.Random,
        steer: bool,
    ) error{OutOfMemory}!RecvAction {
        var fbs = io.fixedBufferStream(bytes);
        var current_entry: ?*ConnEntry = null;
        // Out here: the new connection's transport parameters point into it
        // until recv() below has answered the ClientHello.
        var retry_token: ?packet.ValidatedToken = null;

        while (fbs.seek < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            if (bytes[fbs.seek] & 0x40 == 0) break;

            const pkt_start = fbs.seek;
            var header = packet.Header.parse(&fbs, self.local_cid_len) catch break;

            // Version negotiation (RFC 9000 §6). Only for a datagram as large
            // as a real Initial, so it cannot amplify a spoofed small one.
            if (header.version != 0 and !protocol.isSupportedVersion(header.version)) {
                if (bytes.len < MIN_INITIAL_DATAGRAM) return .{ .dropped = {} };
                if (!self.reply_limits.version_negotiation.allow(now)) return .{ .dropped = {} };
                var vn_fbs = io.fixedBufferStream(out_buf);
                packet.negotiateVersion(header, &vn_fbs, random) catch return .{ .dropped = {} };
                return .{ .send_response = vn_fbs.buffered() };
            }
            // Read after the Version Negotiation branch, because that is the
            // one packet type with no Length field: a packet length this loop
            // steps by has to come from the packet.
            const full_size = fbs.seek - pkt_start + header.remainder_len;

            // Route to existing connection by DCID
            var entry = current_entry orelse self.findByDcid(header.dcid);

            if (entry == null and current_entry == null and header.packet_type == .one_rtt) {
                if (self.findByResetToken(bytes)) |e| {
                    _ = e.conn.handleStatelessReset(bytes, now);
                    return .{ .processed = e };
                }
            }

            if (entry == null) {
                // Initials open a connection wherever they land, and 0-RTT
                // carries the client's own DCID, which encodes nothing.
                if (steer and current_entry == null and
                    (header.packet_type == .one_rtt or header.packet_type == .handshake))
                {
                    if (self.foreignServerId(header.dcid)) |id| return .{ .foreign = id };
                }
                if (header.packet_type != .initial) {
                    // Short-header for unknown CID: stateless reset (RFC 9000 §10.3)
                    if (header.packet_type == .one_rtt and full_size >= MIN_RESET_TRIGGER and
                        self.reply_limits.stateless_reset.allow(now))
                    {
                        // RFC 9000 §10.3.3: response SHOULD be smaller than the trigger
                        // packet to prevent loops (a reset responding to a reset).
                        // Also MUST NOT be 3x or more larger (amplification limit).
                        const sr_max = @min(full_size -| 1, out_buf.len);
                        const sr_len = stateless_reset.generatePacket(out_buf, sr_max, self.static_reset_key, header.dcid, random);
                        if (sr_len > 0) {
                            return .{ .send_response = out_buf[0..sr_len] };
                        }
                    }
                    return .{ .dropped = {} };
                }

                // RFC 9000 14.1, 7.2: a connection opens only from a full-size
                // datagram with an unpredictable DCID. Anything less is dropped
                // before it costs a connection's state.
                if (bytes.len < MIN_INITIAL_DATAGRAM or header.dcid.len < MIN_INITIAL_DCID_LEN) {
                    return .{ .dropped = {} };
                }

                if (self.refuse_new or self.entries.items.len >= self.max_connections) {
                    return self.refuse(header, out_buf, now);
                }

                // A token is honoured whether or not Retry is required now:
                // load may have dropped since we sent the Retry, and its
                // client will insist on seeing retry_source_connection_id.
                const token = header.token orelse &[_]u8{};
                const need_retry = self.require_retry or
                    (if (self.retry_threshold) |n| self.entries.items.len >= n else false);
                if (token.len > 0) {
                    retry_token = packet.validateRetryToken(token, from, self.retry_token_key, now) catch null;
                    if (retry_token) |*vt| {
                        entry = self.acceptConnection(
                            header,
                            local,
                            from,
                            vt.getOdcid(),
                            vt.getRetryScid(),
                            now,
                            random,
                        ) catch return .{ .dropped = {} };
                    } else if (packet.validateNewToken(token, from, self.retry_token_key, now)) {
                        // Valid NEW_TOKEN — the address is proven already
                        entry = self.acceptConnection(
                            header,
                            local,
                            from,
                            header.dcid,
                            null,
                            now,
                            random,
                        ) catch return .{ .dropped = {} };
                    } else if (need_retry) {
                        return .{ .dropped = {} };
                    }
                } else if (need_retry) {
                    var retry_scid: [8]u8 = undefined;
                    random.bytes(&retry_scid);

                    var token_buf: [packet.TOKEN_MAX_LEN]u8 = undefined;
                    const token_len = packet.generateRetryToken(
                        &token_buf,
                        header.dcid,
                        &retry_scid,
                        from,
                        self.retry_token_key,
                        now,
                        random,
                    ) catch return .{ .dropped = {} };

                    var retry_fbs = io.fixedBufferStream(out_buf);
                    packet.retry(header, &retry_scid, token_buf[0..token_len], &retry_fbs) catch
                        return .{ .dropped = {} };
                    return .{ .send_response = retry_fbs.buffered() };
                }
                if (entry == null) {
                    entry = self.acceptConnection(
                        header,
                        local,
                        from,
                        null,
                        null,
                        now,
                        random,
                    ) catch return .{ .dropped = {} };
                }
            }

            // ReleaseSmall has no safety checks, so `entry.?` on a null
            // optional is a wild dereference rather than a panic. Every branch
            // above assigns or returns; drop the datagram if that ever changes.
            const e = entry orelse return .{ .dropped = {} };
            // Only count datagram_size for the first packet in a coalesced datagram
            // to avoid double-counting in amplification limit calculations.
            const dg_size: u64 = if (current_entry == null) bytes.len else 0;
            current_entry = e;
            const recv_info: connection.RecvInfo = .{ .to = local, .from = from, .ecn = ecn_val, .datagram_size = dg_size };
            e.conn.recv(&header, &fbs, recv_info, now, random) catch |err| {
                if (err == error.UndecryptablePacket and pkt_start == 0) {
                    _ = e.conn.handleStatelessReset(bytes, now);
                }
                break;
            };
            try self.syncCids(e);

            const next_pos = pkt_start + full_size;
            if (fbs.seek < next_pos) fbs.seek = next_pos;
        }

        if (current_entry) |e| {
            return .{ .processed = e };
        }
        return .{ .dropped = {} };
    }

    /// The server id `dcid` encodes, if it is another server's under our
    /// QUIC-LB config.
    fn foreignServerId(self: *ConnectionManager, dcid: []const u8) ?[]const u8 {
        const lb = &(self.conn_config.quic_lb orelse return null);
        if (dcid.len != quic_lb.cidLength(lb)) return null;
        if (quic_lb.extractConfigId(dcid[0]) != lb.config_id) return null;
        const n: usize = lb.server_id_len;
        if (!quic_lb.extractServerId(lb, dcid, &self.foreign_id)) return null;
        if (std.mem.eql(u8, self.foreign_id[0..n], lb.server_id[0..n])) return null;
        return self.foreign_id[0..n];
    }

    /// Answer an Initial we will not serve with CONNECTION_REFUSED (RFC 9000
    /// 5.2.2), sealed with the Initial keys its own DCID derives, so the
    /// client fails fast instead of retransmitting into silence.
    fn refuse(self: *ConnectionManager, header: packet.Header, out_buf: []u8, now: i64) RecvAction {
        if (!self.reply_limits.refusal.allow(now)) return .{ .dropped = {} };
        const len = writeRefusal(header, out_buf) catch return .{ .dropped = {} };
        return .{ .send_response = out_buf[0..len] };
    }

    /// Process timeouts and remove a closed connection.
    /// Call this per-entry after the owner's own polling pass.
    /// Returns true if the connection is still alive, false if it was removed
    /// (caller should `continue` without incrementing the index).
    pub fn tickEntry(self: *ConnectionManager, entry: *ConnEntry, now: i64, random: std.Random) bool {
        entry.conn.onTimeout(now, random) catch |err| {
            std.log.warn("onTimeout error: {}", .{err});
        };
        if (entry.conn.isClosed()) {
            self.removeConnection(entry);
            return false;
        }
        return true;
    }

    /// Return the number of active connections.
    pub fn connectionCount(self: *const ConnectionManager) usize {
        return self.entries.items.len;
    }
};

/// Write an Initial packet carrying CONNECTION_CLOSE(CONNECTION_REFUSED) in
/// reply to the client Initial `header`. Returns its length.
pub fn writeRefusal(header: packet.Header, out: []u8) !usize {
    const seal = (try crypto.deriveInitialKeyMaterial(header.dcid, header.version, true))[1];

    var fbs = io.fixedBufferStream(out);
    const w = &fbs;
    const pn_len = 1;
    try w.writeByte(packet.encodeLongHeaderTypeBits(.initial, header.version) | (pn_len - 1));
    try w.writeInt(u32, header.version, .big);
    try w.writeByte(@intCast(header.scid.len));
    try w.writeAll(header.scid);
    try w.writeByte(@intCast(header.dcid.len));
    try w.writeAll(header.dcid);
    try w.writeByte(0); // token length

    // CONNECTION_CLOSE (0x1c), CONNECTION_REFUSED, frame type 0, no reason.
    const payload = [_]u8{ 0x1c, @intFromEnum(frame_mod.TransportError.connection_refused), 0x00, 0x00 };
    const tag_len = 16;
    const length = pn_len + payload.len + tag_len;
    try packet.writeVarInt(w, length);
    const pn_offset = fbs.seek;
    try w.writeByte(0); // packet number 0

    const header_len = fbs.seek;
    if (out.len < header_len + payload.len + tag_len) return error.NoSpaceLeft;
    const sealed = seal.encryptPayload(0, out[0..header_len], &payload, out[header_len..]);
    const total = header_len + sealed;
    seal.applyHeaderProtection(out[0..total], pn_offset, pn_len);
    return total;
}

// Tests

/// A fixed instant. Nothing in these tests reads a clock any more, so the
/// value only has to be a plausible monotonic nanosecond count.
const test_now: i64 = 1_000 * std.time.ns_per_s;

/// Seeded entropy, so a test that draws a Retry SCID or a lookup key draws
/// the same bytes on every run. `std.Random` is an interface over a pointer
/// to its engine, so the engine outlives every value handed out here.
const TestRandom = std.Random.DefaultPrng;

test "CidKey roundtrip" {
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const key = CidKey.fromSlice(&cid);
    try std.testing.expectEqual(@as(u8, 8), key.len);
    try std.testing.expectEqualSlices(u8, &cid, key.getSlice());
}

test "CidKey equality" {
    const a = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const b = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const c = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x04 });

    try std.testing.expect(CidKeyContext.eql(.{}, a, b));
    try std.testing.expect(!CidKeyContext.eql(.{}, a, c));
}

test "CidKey different lengths" {
    const a = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const b = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    try std.testing.expect(!CidKeyContext.eql(.{}, a, b));
}

test "max_connections is configurable past 256, and every removed entry is freed" {
    const alloc = std.testing.allocator;
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = ConnectionManager.init(alloc, tls_config, .{}, .{0} ** 16, .{0} ** 16, random);
    defer mgr.deinit();
    mgr.max_connections = 300;

    const local: address.Address = .unset;
    var dcids: [301][8]u8 = undefined;
    const scid = [_]u8{0xaa} ** 8;
    for (&dcids, 0..) |*d, i| {
        std.mem.writeInt(u64, d, i + 1, .big);
        const header: packet.Header = .{
            .version = protocol.SUPPORTED_VERSIONS[0],
            .packet_type = .initial,
            .dcid = d,
            .scid = &scid,
        };
        const accepted = mgr.acceptConnection(header, local, local, null, null, now, random);
        if (i < 300) {
            const e = try accepted;
            try std.testing.expect(e.id != 0);
        } else {
            try std.testing.expectError(error.TooManyConnections, accepted);
        }
    }
    try std.testing.expectEqual(@as(usize, 300), mgr.connectionCount());

    // All at once, in one cycle: more than a fixed 256-slot queue would hold.
    while (mgr.entries.items.len > 0) mgr.removeConnection(mgr.entries.items[0]);
    try std.testing.expectEqual(@as(usize, 300), mgr.dead_entries.items.len);
    mgr.freeDeadEntries();
}

test "connections coming and going leave the CID map free slots to stop a lookup at" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();

    const local: address.Address = .unset;
    const scid = [_]u8{0xaa} ** 8;
    var dcid: [8]u8 = undefined;
    for (0..3000) |i| {
        std.mem.writeInt(u64, &dcid, i + 1, .big);
        const header: packet.Header = .{
            .version = protocol.SUPPORTED_VERSIONS[0],
            .packet_type = .initial,
            .dcid = &dcid,
            .scid = &scid,
        };
        _ = try mgr.acceptConnection(header, local, local, null, null, now, random);
        if (mgr.entries.items.len > 4) mgr.removeConnection(mgr.entries.items[0]);
        mgr.freeDeadEntries();
    }
    const m = &mgr.cid_map.unmanaged;
    var free: usize = 0;
    for (m.metadata.?[0..m.capacity()]) |md| free += @intFromBool(md.isFree());
    // Tombstones never give their slot back on their own: without the
    // rehash, a map this churned has none free.
    try std.testing.expect(free >= m.capacity() - m.count() - m.capacity() / 4);
}

fn testManager(alloc: Allocator, random: std.Random) ConnectionManager {
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    return ConnectionManager.init(alloc, tls_config, .{}, .{0} ** 16, .{0} ** 16, random);
}

fn testAcceptedEntry(manager: *ConnectionManager, random: std.Random) !*ConnEntry {
    return manager.acceptConnection(.{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = &([_]u8{0xbb} ** 8),
        .scid = &([_]u8{0xaa} ** 8),
    }, .unset, .unset, null, null, test_now, random);
}

/// A real client's first datagram, padded to 1200 bytes as RFC 9000 14.1 asks.
fn clientInitial(
    alloc: Allocator,
    out: []u8,
    now: i64,
    random: std.Random,
) !struct { conn: *connection.Connection, len: usize } {
    const conn = try alloc.create(connection.Connection);
    errdefer alloc.destroy(conn);
    try connection.connectInto(conn, alloc, "example.com", .{}, null, null, now, random);
    const len = try conn.sendAt(out, now, random);
    return .{ .conn = conn, .len = len };
}

/// Hand-built long header: enough for routing, never decrypted.
fn fakeLongHeader(buf: []u8, version: u32, dcid: []const u8) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = &fbs;
    w.writeByte(0xc0) catch unreachable;
    w.writeInt(u32, version, .big) catch unreachable;
    w.writeByte(@intCast(dcid.len)) catch unreachable;
    w.writeAll(dcid) catch unreachable;
    w.writeByte(0) catch unreachable; // scid
    w.writeByte(0) catch unreachable; // token
    packet.writeVarInt(w, 40) catch unreachable;
    return fbs.seek + 40;
}

test "an Initial in a datagram under 1200 bytes opens no connection" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    const addr: address.Address = .unset;

    var buf = [_]u8{0} ** 1500;
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &([_]u8{0x11} ** 8));
    const action = try mgr.recvDatagram(buf[0..n], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "an Initial with a DCID under 8 bytes opens no connection" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    const addr: address.Address = .unset;

    var buf = [_]u8{0} ** 1200;
    var out: [1500]u8 = undefined;
    _ = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &([_]u8{0x11} ** 7));
    const action = try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "Version Negotiation only answers full-size datagrams, and is rate limited" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    mgr.reply_limits = .init(1);
    const addr: address.Address = .unset;
    const unknown: u32 = 0x1a2a3a4a;

    var buf = [_]u8{0} ** 1200;
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, unknown, &([_]u8{0x11} ** 8));
    var action = try mgr.recvDatagram(buf[0..n], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
    action = try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);
    // The bucket is spent; the refill needs a second to pass.
    action = try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
}

test "stateless reset answers only packets long enough not to be one" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    const addr: address.Address = .unset;

    var buf = [_]u8{0x41} ++ [_]u8{0x22} ** 99;
    var out: [1500]u8 = undefined;
    const short = buf[0 .. MIN_RESET_TRIGGER - 1];
    var action = try mgr.recvDatagram(short, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
    switch (try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random)) {
        .send_response => |r| try std.testing.expect(r.len < buf.len),
        else => return error.TestUnexpectedResult,
    }

    mgr.reply_limits = .init(0);
    action = try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);
}

test "ReplyLimiter refills at its rate and caps the burst" {
    var l: ReplyLimiter = .{ .per_second = 10, .tokens = 10 };
    const t0: i64 = 5 * std.time.ns_per_s;
    var granted: usize = 0;
    while (l.allow(t0)) granted += 1;
    try std.testing.expectEqual(@as(usize, 10), granted);
    // 100 ms buys one more; ten seconds buys no more than the burst.
    try std.testing.expect(l.allow(t0 + 100 * std.time.ns_per_ms));
    try std.testing.expect(!l.allow(t0 + 100 * std.time.ns_per_ms));
    granted = 0;
    while (l.allow(t0 + 10 * std.time.ns_per_s)) granted += 1;
    try std.testing.expectEqual(@as(usize, 10), granted);
}

test "spoofed reset triggers do not spend the CONNECTION_REFUSED budget" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    mgr.reply_limits = .init(1);
    mgr.max_connections = 0;
    const addr: address.Address = .unset;
    var out: [1500]u8 = undefined;

    var junk = [_]u8{0x41} ++ [_]u8{0x22} ** 99;
    var action = try mgr.recvDatagram(&junk, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);
    action = try mgr.recvDatagram(&junk, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .dropped);

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf, now, random);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    action = try mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);
}

test "a server at capacity refuses a new client with CONNECTION_REFUSED" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    mgr.max_connections = 0;
    const addr: address.Address = .unset;

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf, now, random);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    try std.testing.expect(client.len >= MIN_INITIAL_DATAGRAM);

    var out: [1500]u8 = undefined;
    const reply = switch (try mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out, now, random)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
    // Small, so a spoofed Initial cannot be turned into an amplifier.
    try std.testing.expect(reply.len < 100);

    // The client can read it: the Initial keys are its own.
    const reply_info: connection.RecvInfo = .{
        .to = addr,
        .from = addr,
        .datagram_size = reply.len,
    };
    client.conn.handleDatagram(@constCast(reply), reply_info, now, random);
    try std.testing.expect(client.conn.isDraining());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(frame_mod.TransportError.connection_refused)),
        client.conn.local_err.?.code,
    );
}

test "refuse_new turns away new connections while existing ones keep routing" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    mgr.refuse_new = true;
    const addr: address.Address = .unset;

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf, now, random);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    var out: [1500]u8 = undefined;
    const action = try mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

fn lbConfig(server_id: u8) quic_lb.Config {
    var cfg: quic_lb.Config = .{ .config_id = 0, .server_id_len = 1, .nonce_len = 6 };
    cfg.server_id[0] = server_id;
    return cfg;
}

fn steeringManager(alloc: Allocator, server_id: u8, random: std.Random) ConnectionManager {
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    const config: connection.ConnectionConfig = .{ .quic_lb = lbConfig(server_id) };
    var mgr = ConnectionManager.init(alloc, tls_config, config, .{0} ** 16, .{0} ** 16, random);
    mgr.steer_foreign = true;
    return mgr;
}

/// A 1-RTT packet to `dcid`, long enough to earn a stateless reset.
fn shortPacket(buf: []u8, dcid: []const u8) []u8 {
    buf[0] = 0x41;
    @memcpy(buf[1 .. 1 + dcid.len], dcid);
    @memset(buf[1 + dcid.len .. 60], 0x22);
    return buf[0..60];
}

test "a 1-RTT packet for another QUIC-LB server id is reported, not reset" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = steeringManager(alloc, 1, random);
    defer mgr.deinit();
    const addr: address.Address = .unset;
    var out: [1500]u8 = undefined;
    var buf: [64]u8 = undefined;

    var cid: [8]u8 = undefined;
    quic_lb.generateCid(&lbConfig(2), &cid, random);
    switch (try mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out, now, random)) {
        .foreign => |id| try std.testing.expectEqualSlices(u8, &.{2}, id),
        else => return error.TestUnexpectedResult,
    }

    // Handed over and still unknown: reset, never passed on again.
    var action = try mgr.recvHandedOver(shortPacket(&buf, &cid), addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);

    // Our own id with no connection behind it is simply gone.
    quic_lb.generateCid(&lbConfig(1), &cid, random);
    action = try mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);

    mgr.steer_foreign = false;
    quic_lb.generateCid(&lbConfig(2), &cid, random);
    action = try mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .send_response);
}

test "an Initial is accepted locally even when its DCID decodes to another server" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = steeringManager(alloc, 1, random);
    defer mgr.deinit();
    const addr: address.Address = .unset;
    var out: [1500]u8 = undefined;

    var cid: [8]u8 = undefined;
    quic_lb.generateCid(&lbConfig(2), &cid, random);
    var buf = [_]u8{0} ** 1200;
    _ = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &cid);
    const action = try mgr.recvDatagram(&buf, addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .processed);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    // And the connection's own CID carries our id.
    const scid = mgr.entries.items[0].conn.scid[0..8];
    var id: [1]u8 = undefined;
    try std.testing.expect(quic_lb.extractServerId(&lbConfig(1), scid, &id));
    try std.testing.expectEqual(@as(u8, 1), id[0]);
}

test "past retry_threshold a new client gets Retry, and is served once it echoes the token" {
    const alloc = std.testing.allocator;
    const now = test_now;
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    mgr.retry_threshold = 1;
    const addr: address.Address = .unset;
    var out: [1500]u8 = undefined;

    // Under the threshold: served straight away.
    var buf: [1500]u8 = undefined;
    const first = try clientInitial(alloc, &buf, now, random);
    defer {
        first.conn.deinit();
        alloc.destroy(first.conn);
    }
    var action = try mgr.recvDatagram(buf[0..first.len], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .processed);

    // At it: Retry, and no state kept.
    const second = try clientInitial(alloc, &buf, now, random);
    defer {
        second.conn.deinit();
        alloc.destroy(second.conn);
    }
    const retry = switch (try mgr.recvDatagram(buf[0..second.len], addr, addr, 0, &out, now, random)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    const reply_info: connection.RecvInfo = .{
        .to = addr,
        .from = addr,
        .datagram_size = retry.len,
    };
    second.conn.handleDatagram(@constCast(retry), reply_info, now, random);
    try std.testing.expect(second.conn.retry_received);

    // Load drops before the client comes back; its token still counts, so
    // the connection is set up as a retried one.
    mgr.removeConnection(mgr.entries.items[0]);
    const n = try second.conn.sendAt(&buf, now, random);
    action = try mgr.recvDatagram(buf[0..n], addr, addr, 0, &out, now, random);
    try std.testing.expect(action == .processed);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    try std.testing.expect(mgr.entries.items[0].conn.paths[0].is_validated);
}

test "an accept that runs out of memory leaves no connection and no entry behind" {
    const local: address.Address = .unset;
    const scid = [_]u8{0xaa} ** 8;
    const dcid = [_]u8{0xbb} ** 8;
    const header: packet.Header = .{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = &dcid,
        .scid = &scid,
    };
    var entropy = TestRandom.init(7);

    // Every allocation an accept makes, one at a time, so the refusal lands
    // at each step in turn: the two reservations, the connection, and the
    // handshake and queues built inside it.
    var fail_at: usize = 0;
    while (fail_at < 8) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at });
        var mgr = testManager(failing.allocator(), entropy.random());
        defer mgr.deinit();

        if (mgr.acceptConnection(header, local, local, null, null, test_now, entropy.random())) |entry| {
            // This step fitted: drop the connection the way a server does
            // and let the next refusal be measured on a clean table.
            mgr.removeConnection(entry);
            mgr.freeDeadEntries();
            continue;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            // A refused accept is not a connection: nothing in the table to
            // remove, nothing in the routing map to route to, and nothing the
            // testing allocator still holds an account of.
            try std.testing.expectEqual(@as(usize, 0), mgr.entries.items.len);
            try std.testing.expectEqual(@as(usize, 0), mgr.cid_map.count());
            try std.testing.expectEqual(@as(usize, 0), mgr.dead_entries.items.len);
        }
    }
}

test "CID index allocation refusal leaves registration pending for retry" {
    const alloc = std.testing.allocator;
    var entropy = TestRandom.init(17);
    const random = entropy.random();
    var failing = std.testing.FailingAllocator.init(alloc, .{});
    var mgr = testManager(failing.allocator(), random);
    defer mgr.deinit();
    const entry = try testAcceptedEntry(&mgr, random);
    const previous_count = entry.registered_cid_count;
    const previous_key = entry.registered_cids[0];
    var key: CidKey = undefined;
    for (0..7) |index| {
        const issued = entry.conn.local_cid_pool.issueNewCid(8, null, random) orelse
            return error.TestUnexpectedResult;
        if (index == 0) key = CidKey.fromSlice(issued.getCid());
    }
    failing.fail_index = failing.alloc_index;

    try std.testing.expectError(error.OutOfMemory, mgr.syncCids(entry));
    try std.testing.expectEqual(previous_count, entry.registered_cid_count);
    try std.testing.expect(mgr.findByDcid(previous_key.getSlice()) == entry);
    try std.testing.expect(mgr.findByDcid(key.getSlice()) == null);

    failing.fail_index = std.math.maxInt(usize);
    try mgr.syncCids(entry);
    try std.testing.expect(mgr.findByDcid(key.getSlice()) == entry);
    try std.testing.expectEqual(@as(u8, 9), entry.registered_cid_count);
}

test "CID slot reuse removes retired routes and preserves Initial routing" {
    const alloc = std.testing.allocator;
    var entropy = TestRandom.init(19);
    const random = entropy.random();
    var mgr = testManager(alloc, random);
    defer mgr.deinit();
    const initial_dcid = [_]u8{0xbb} ** 8;
    const client_scid = [_]u8{0xaa} ** 8;
    const header: packet.Header = .{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = &initial_dcid,
        .scid = &client_scid,
    };
    const entry = try mgr.acceptConnection(
        header,
        .unset,
        .unset,
        null,
        null,
        test_now,
        random,
    );
    try mgr.syncCids(entry);

    for (0..12) |_| {
        const previous = CidKey.fromSlice(entry.conn.local_cid_pool.entries[0].getCid());
        entry.conn.local_cid_pool.retireBySeq(entry.conn.local_cid_pool.entries[0].seq_num);
        const next = entry.conn.local_cid_pool.issueNewCid(8, null, random) orelse
            return error.TestUnexpectedResult;
        const current = CidKey.fromSlice(next.getCid());
        try mgr.syncCids(entry);
        try std.testing.expect(mgr.findByDcid(previous.getSlice()) == null);
        try std.testing.expect(mgr.findByDcid(current.getSlice()) == entry);
        try std.testing.expect(mgr.findByDcid(&initial_dcid) == entry);
        try std.testing.expectEqual(@as(u8, 2), entry.registered_cid_count);
    }

    mgr.removeConnection(entry);
    mgr.freeDeadEntries();
    try std.testing.expectEqual(@as(u32, 0), mgr.cid_map.count());
}

test "reset index allocation refusal preserves old tokens and retries the new generation" {
    const alloc = std.testing.allocator;
    var entropy = TestRandom.init(23);
    const random = entropy.random();
    var failing = std.testing.FailingAllocator.init(alloc, .{});
    var mgr = testManager(failing.allocator(), random);
    defer mgr.deinit();
    const entry = try testAcceptedEntry(&mgr, random);
    const old_token: [16]u8 = @splat(0xe0);
    entry.conn.peer_cid_pool.addPeerCid(0, &.{0xe0}, old_token);
    try mgr.syncCids(entry);
    const previous_generation = entry.reset_pool_gens;
    var reset: [stateless_reset.MIN_PACKET_LEN]u8 = @splat(0x41);
    @memcpy(reset[reset.len - old_token.len ..], &old_token);
    try std.testing.expect(mgr.findByResetToken(&reset) == entry);

    entry.conn.peer_cid_pool.removeBySeq(0);
    for (1..9) |i| {
        const byte: u8 = @intCast(i);
        entry.conn.peer_cid_pool.addPeerCid(i, &.{byte}, @splat(byte));
    }
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, mgr.syncCids(entry));
    try std.testing.expectEqual(previous_generation, entry.reset_pool_gens);
    try std.testing.expect(mgr.findByResetToken(&reset) == entry);

    failing.fail_index = std.math.maxInt(usize);
    try mgr.syncCids(entry);
    try std.testing.expect(mgr.findByResetToken(&reset) == null);
    for (1..9) |i| {
        @memset(reset[reset.len - 16 ..], @intCast(i));
        try std.testing.expect(mgr.findByResetToken(&reset) == entry);
    }
    try std.testing.expectEqual(
        entry.conn.peer_cid_pool.generation,
        entry.reset_pool_gens.?[0],
    );
}

test "path one CID routes share entry identity and retire within bounded route storage" {
    var entropy = TestRandom.init(29);
    const random = entropy.random();
    var mgr = testManager(std.testing.allocator, random);
    defer mgr.deinit();
    const entry = try testAcceptedEntry(&mgr, random);
    const id = entry.id;
    const initial = entry.initial_dcid.?;
    const path_zero = CidKey.fromSlice(entry.conn.local_cid_pool.entries[0].getCid());

    // Reuse one path-one slot repeatedly: manager routes bytes, not path-local sequence IDs.
    for (0..24) |_| {
        const issued = entry.conn.local_cid_pool.issueNewCid(8, null, random) orelse
            return error.TestUnexpectedResult;
        const key = CidKey.fromSlice(issued.getCid());
        issued.path_id = 1;
        try mgr.syncCids(entry);
        try std.testing.expect(mgr.findByDcid(key.getSlice()) == entry);
        try std.testing.expect(mgr.findByDcid(path_zero.getSlice()) == entry);
        try std.testing.expectEqual(id, mgr.findByDcid(key.getSlice()).?.id);
        try std.testing.expectEqual(@as(u8, 3), entry.registered_cid_count);
        try std.testing.expectEqual(@as(u32, 3), mgr.cid_map.count());
        issued.occupied = false;
        issued.retired = true;
        try mgr.syncCids(entry);
        try std.testing.expect(mgr.findByDcid(key.getSlice()) == null);
        try std.testing.expect(mgr.findByDcid(initial.getSlice()) == entry);
        try std.testing.expectEqual(@as(u8, 2), entry.registered_cid_count);
    }

    mgr.removeConnection(entry);
    try std.testing.expectEqual(id, entry.id);
    try std.testing.expectEqual(@as(usize, 1), mgr.dead_entries.items.len);
    try std.testing.expectEqual(@as(u32, 0), mgr.cid_map.count());
    mgr.freeDeadEntries();
}

test "path one reset generation replacement is atomic on index refusal" {
    var entropy = TestRandom.init(31);
    const random = entropy.random();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var mgr = testManager(failing.allocator(), random);
    defer mgr.deinit();
    const entry = try testAcceptedEntry(&mgr, random);
    const transport = try mgr.allocator.create(connection.Connection.PathTransport);
    transport.* = .{
        .handler = @import("ack_handler.zig").PacketHandler.init(mgr.allocator),
    };
    entry.conn.path1_transport = transport;
    const old_token: [16]u8 = @splat(0xf0);
    const old_local = entry.conn.local_cid_pool.issueNewCid(8, null, random) orelse
        return error.TestUnexpectedResult;
    old_local.path_id = 1;
    const old_route = CidKey.fromSlice(old_local.getCid());
    transport.peer_cids.addPeerCid(0, &.{0xf0}, old_token);
    try mgr.syncCids(entry);
    const previous_generations = entry.reset_pool_gens;
    const path_zero_generation = entry.conn.peer_cid_pool.generation;
    var reset: [stateless_reset.MIN_PACKET_LEN]u8 = @splat(0x41);
    @memcpy(reset[reset.len - old_token.len ..], &old_token);
    try std.testing.expect(mgr.findByResetToken(&reset) == entry);

    old_local.occupied = false;
    old_local.retired = true;
    const new_local = entry.conn.local_cid_pool.issueNewCid(8, null, random) orelse
        return error.TestUnexpectedResult;
    new_local.path_id = 1;
    const new_route = CidKey.fromSlice(new_local.getCid());
    transport.peer_cids.removeBySeq(0);
    for (0..8) |i| {
        const byte: u8 = @intCast(i + 1);
        entry.conn.peer_cid_pool.addPeerCid(i, &.{byte}, @splat(byte));
        transport.peer_cids.addPeerCid(i + 1, &.{byte + 8}, @splat(byte + 8));
    }
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, mgr.syncCids(entry));
    try std.testing.expectEqual(previous_generations, entry.reset_pool_gens);
    try std.testing.expectEqual(@as(u8, 1), entry.reset_key_count);
    try std.testing.expect(mgr.findByResetToken(&reset) == entry);
    try std.testing.expect(mgr.findByDcid(old_route.getSlice()) == entry);
    try std.testing.expect(mgr.findByDcid(new_route.getSlice()) == null);
    try std.testing.expectEqual(@as(u8, 3), entry.registered_cid_count);
    failing.fail_index = std.math.maxInt(usize);
    try mgr.syncCids(entry);
    try std.testing.expect(mgr.findByResetToken(&reset) == null);
    try std.testing.expect(mgr.findByDcid(old_route.getSlice()) == null);
    try std.testing.expect(mgr.findByDcid(new_route.getSlice()) == entry);
    try std.testing.expectEqual(@as(u8, 16), entry.reset_key_count);
    try std.testing.expectEqual(@as(u32, 16), mgr.reset_token_map.count());
    for (1..17) |i| {
        @memset(reset[reset.len - 16 ..], @intCast(i));
        try std.testing.expect(mgr.findByResetToken(&reset) == entry);
    }

    // Change only path one: its independent generation must trigger reconciliation.
    const synchronized_zero = entry.reset_pool_gens.?[0];
    try std.testing.expect(synchronized_zero != path_zero_generation);
    transport.peer_cids.removeBySeq(1);
    try mgr.syncCids(entry);
    try std.testing.expectEqual(synchronized_zero, entry.reset_pool_gens.?[0]);
    try std.testing.expectEqual(transport.peer_cids.generation, entry.reset_pool_gens.?[1]);
    @memset(reset[reset.len - 16 ..], 9);
    try std.testing.expect(mgr.findByResetToken(&reset) == null);
    transport.peer_cids.addPeerCid(99, &.{0xfe}, @splat(1));
    try mgr.syncCids(entry);
    try std.testing.expectEqual(@as(u8, 15), entry.reset_key_count);
    try std.testing.expectEqual(@as(u32, 15), mgr.reset_token_map.count());
    @memset(reset[reset.len - 16 ..], 1);
    try std.testing.expect(mgr.findByResetToken(&reset) == entry);
    const allocations = failing.alloc_index;
    try mgr.syncCids(entry);
    try std.testing.expectEqual(allocations, failing.alloc_index);

    const id = entry.id;
    mgr.removeConnection(entry);
    try std.testing.expectEqual(id, entry.id);
    try std.testing.expectEqual(@as(u32, 0), mgr.reset_token_map.count());
    try std.testing.expectEqual(@as(usize, 1), mgr.dead_entries.items.len);
    mgr.freeDeadEntries();
}
