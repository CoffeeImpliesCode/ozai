//! Owns the vendored QUIC manager, stable identity storage, ALPN offers,
//! and pre-accept Retry replay gate. Connection operations live in quic_conn.
//!
//! Time and randomness are caller inputs. Only creation uses caller-supplied
//! std.Io to draw transport keys; this module owns no socket or clock.
//! Certificates, client-auth settings, and ALPN slices borrow the bridge's
//! heap-stable storage. ALPN bytes remain borrowed from the caller.

const std = @import("std");
const quic = @import("quic");

// Named for the layer, not the file: `key`, `addr` and `ula` are this
// module's own vocabulary as declarations and a parameter may not shadow one.
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const batch = @import("batch.zig");

const conn_mod = @import("quic_conn.zig");
const config_mod = @import("quic_config.zig");
const error_mod = @import("quic_error.zig");
const stream_mod = @import("quic_stream.zig");
const datagram_mod = @import("quic_datagram.zig");
const retry = @import("retry.zig");

/// The name a withdrawal leaves in every slot it empties.
///
/// **It has to be a name the core cannot select, and what makes it one is a
/// skip rather than a comparison.** A server walks its own list and passes
/// over any entry longer than the buffer it holds the selection in
/// (`vendor/quic/src/quic/tls13.zig:3099`), so an entry this long is matched
/// by nothing a peer can name and it cannot end the walk either. See
/// `withdrawAlpn` for why the slots cannot simply be left behind.
///
/// An empty name would do neither, and for two reasons that are this core's
/// rather than the wire's: RFC 7301's `ProtocolName` is 1..255 bytes, so a
/// conforming peer cannot send one, but the walk compares entries byte for
/// byte and the decoder lets a zero-length one through
/// (`tls13.zig:3101-3107`), so it would end a walk with nothing selected; and
/// `negotiatedAlpn` answers `config.alpn[0]` before anything is selected
/// (`tls13.zig:2042`), so an empty name in the first slot is what a handshake
/// that has not chosen yet would report.
const retired_alpn: []const u8 = "ozai/withdrawn-this-name-is-longer-than-the-selection";
comptime {
    // The property is this name being longer than the core's selection
    // buffer; `config_mod.max_alpn_name_len` reads that buffer's own type.
    std.debug.assert(retired_alpn.len > config_mod.max_alpn_name_len);
}

/// One datagram as it arrived, in this project's vocabulary.
///
/// The read side's own shape is `batch.Recv`, which may be a coalesced
/// buffer holding several datagrams. This is one of them: `recv` takes a
/// single datagram because the core's reply borrows the buffer it was
/// written into, and two datagrams sharing one buffer would have two
/// answers pointing at the same bytes. A caller reading a coalesced read
/// asks it for one datagram at a time, with `batch.Recv.datagram`.
pub const Datagram = struct {
    /// The bytes, one datagram and no more.
    bytes: []const u8,
    /// Where it came from.
    from: base_addr.SocketAddr,
    /// Where it was sent to.
    local: base_addr.SocketAddr,
    /// The codepoint it carried, or null for not-ECT.
    ecn: ?batch.Ecn,
};

/// Where a received datagram came from, in this project's terms.
pub const Source = struct {
    /// The address itself.
    socket: base_addr.SocketAddr,
    /// What `base/ula.zig`'s `classify` made of it: one of the three
    /// synthetic subnets, or a direct path. Note that this looks at eight
    /// octets and ignores the port — see the module doc.
    classification: base_ula.Classification,
    /// The key that owns the address in `addr_map`, or null when this node's
    /// map never handed it out: a direct path, or a synthetic address that
    /// belongs to somebody else's map. Null is not a failure — it is the
    /// answer for every packet on a direct path.
    owner: ?addr_map.Key,
};

/// What the core did with a received datagram.
pub const Outcome = union(enum) {
    /// The core owns the datagram now and has a connection for it.
    processed: conn_mod.Conn,
    /// The core wrote a stateless reply — Version Negotiation, Retry, or a
    /// stateless reset — and it goes back to `Ingress.source.socket` through
    /// the same send seam an egress uses, because it is a send. It borrows
    /// the caller's `scratch` and is good until the next `recv`.
    reply: batch.Send,
    /// Unroutable or invalid. Nothing to do and nothing to report.
    dropped: void,
    /// The DCID named another server under the same QUIC-LB config id, and
    /// this is its server id. It borrows the core's own scratch and is good
    /// until the next `recv`.
    ///
    /// A bridge built from `Config` never returns it: the core only reports
    /// a foreign DCID when `ConnectionManager.steer_foreign` is set
    /// (`connection_manager.zig:301`, default false) and `Config` has no QUIC
    /// load-balancing field to set it with. The arm is here because `recv`
    /// forwards what the core says rather than dropping an arm it does not
    /// expect, and a caller adding QUIC-LB to `Config` gets it without
    /// coming back here.
    foreign: []const u8,
};

/// One datagram through the core and back out as an answer.
pub const Ingress = struct {
    source: Source,
    outcome: Outcome,
};

/// What one pass of the timers did to a connection.
pub const Tick = enum {
    /// Still live. Keep draining it.
    live,
    /// The core has finished with it and taken it out of its table. The
    /// memory stands until `Bridge.sweep`, so a drain after this still reads
    /// a closed connection rather than freed memory.
    finished,
};

/// One vendored `ConnectionManager` and the identity it presents.
///
/// It owns no `std.Io`, no clock and no generator: `Instant` and `std.Random`
/// are parameters of every call below, which is what lets the same bridge be
/// driven twice at two different instants and get two different answers. It
/// does keep the allocator it was created with, because the core's
/// connections are freed through it and a caller that has to be asked for an
/// allocator on `destroy` has to be trusted to answer.
///
/// Heap-allocated by `create`, not returned by value: the core's
/// `TlsConfig` points at this struct's own `spki` and `alpn_list`, and a
/// returned struct is moved into the caller's frame.
///
/// Keep the allocated address stable and call `destroy` exactly once.
/// Copies share resources and cannot be separately released. Serialize access,
/// including access through connection and stream handles. `gpa` and every
/// ALPN in `config.alpns` must stay alive until `destroy`.
pub const Bridge = struct {
    gpa: std.mem.Allocator,
    /// The core. Public because a caller reads connection state off it, not
    /// because poking it is safe.
    manager: quic.connection_manager.ConnectionManager,
    node_id: base_key.NodeId,
    /// The 32 bytes of seed the presented certificate is built from.
    seed: [base_key.SecretKey.seed_length]u8,
    /// The certificate: an SPKI over `node_id`, and nothing behind it.
    spki: [config_mod.spki_length]u8,
    /// The one-element chain the core's config points at. It points into
    /// `spki`, which is why this struct lives on the heap.
    cert_chain: [1][]const u8,
    /// The protocols this bridge offers, copied into this struct for the same
    /// reason, and the first `alpn_count` of them. Bounded by `max_alpns` and
    /// `create` refuses a longer offer by name rather than truncating it. The
    /// slots past `alpn_count` are the ones a withdrawal emptied, and they hold
    /// `retired_alpn`: a connection accepted before that withdrawal still reads
    /// them, under the length it was accepted with. See `withdrawAlpn`.
    alpn_list: [config_mod.max_alpns][]const u8,
    /// How many of `alpn_list` are this bridge's, which is what the core is
    /// pointed at. Never more than `max_alpns`, and zero only on a bridge that
    /// `create` refused.
    alpn_count: usize,
    /// The peer pin a server actually enforces. It points into this struct
    /// for the same reason.
    client_auth: quic.tls13.ClientAuth,
    /// The secret Retry tokens and NEW_TOKENs are sealed under, kept beside the
    /// manager's copy of it.
    ///
    /// **Two copies of one secret and one reason.** The manager needs the key
    /// to validate what a client presents; `checkRetryToken` and
    /// `issueRetryToken` need it to seal and to recognise without asking the
    /// manager, and the core exposes no door to either. The manager holds its
    /// copy by value and takes it by value, so there is no way to have one and
    /// borrow it — and `destroy` zeroes this copy with the seed, in that order,
    /// because a secret left in freed memory is a secret this node still has.
    retry_token_key: [retry.key_length]u8,
    /// The Retry tokens this node has sealed or answered, and the filter that
    /// reads them. `recv` consults it before the core is asked, so a replayed
    /// Initial costs no cipher open and no second Retry.
    retry_gate: retry.Gate,

    /// A bridge presenting `config.secret`'s node, with a `ConnectionManager`
    /// built from it.
    ///
    /// `random` seeds the core's SipHash key and draws the connection ids it
    /// hands out; `io` is used only where `config` left a transport key
    /// null, and for that it is `std.Io.randomSecure` rather than a process
    /// CSPRNG — a global RNG is what `AGENTS.md` §2 forbids, and an `std.Io`
    /// the caller was handed is not a global.
    ///
    /// The returned pointer is owned by `gpa` and freed by `destroy`.
    /// Each ALPN in `config.alpns` is borrowed and must remain alive and
    /// unchanged; the list itself is copied and need not.
    /// A malformed offer — no protocol at all, an empty name, a name past
    /// `max_alpn_name_len`, or more than `max_alpns` of them — is refused as a
    /// `config_mod.AlpnError` before the bridge allocates or draws a key.
    /// On error no bridge or owned allocation remains. Entropy and random
    /// draws already made are not restored. `error.Canceled` is forwarded.
    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        config: config_mod.Config,
        random: std.Random,
    ) config_mod.CreateError!*Bridge {
        // The list is checked before the bridge exists, so a refusal leaves no
        // allocation to release and no truncated offer for the core to see.
        try config_mod.validateAlpns(config.alpns);
        const self = try gpa.create(Bridge);
        errdefer gpa.destroy(self);
        const retry_key = try config_mod.drawKey(io, config.retry_token_key);
        const reset_key = try config_mod.drawKey(io, config.static_reset_key);
        self.* = .{
            .gpa = gpa,
            .manager = undefined,
            .node_id = config.secret.nodeId(),
            .seed = config.secret.toBytes()[0..base_key.SecretKey.seed_length].*,
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .alpn_count = config.alpns.len,
            .client_auth = .{
                .expect_node_id = if (config.expect_peer) |peer| peer.toBytes() else null,
                // A pin implies a certificate, so the two fields are read
                // through one decision rather than two: see
                // `demandsPeerCertificate`.
                .mode = if (config_mod.demandsPeerCertificate(config)) .required else .optional,
            },
            .retry_token_key = retry_key,
            .retry_gate = .{},
        };
        self.manager = quic.connection_manager.ConnectionManager.init(
            gpa,
            self.buildTlsConfig(config),
            config_mod.connectionConfig(config, retry_key),
            retry_key,
            reset_key,
            random,
        );
        // The two Retry fields are set after `init` rather than through it
        // because the core's constructor takes no policy and its struct
        // defaults are "never retry". That default is why nothing under
        // `src/` had pre-accept Retry before `Config` grew these two: the
        // fields have been here since the tree was vendored and no caller had
        // a way to reach them.
        self.manager.require_retry = config.require_retry;
        self.manager.retry_threshold = config.retry_threshold;
        return self;
    }

    /// Free every connection the core holds and then the bridge.
    ///
    /// The secret seed and the Retry token key are zeroed after the
    /// connections are released, in that order: a connection's handshake may
    /// still be pointing at either, which is why they are zeroed after
    /// `deinit` and not before it. This invalidates every connection, stream
    /// and TLS view from the bridge. Do not call through this pointer again or
    /// destroy an owner copy.
    pub fn destroy(self: *Bridge) void {
        self.manager.deinit();
        std.crypto.secureZero(u8, self.seed[0..]);
        std.crypto.secureZero(u8, self.retry_token_key[0..]);
        self.gpa.destroy(self);
    }

    /// The node id this bridge presents as a bare `SubjectPublicKeyInfo`.
    pub fn nodeId(self: *const Bridge) base_key.NodeId {
        return self.node_id;
    }

    /// The TLS configuration the core is running.
    ///
    /// Exposed because it is the translation, and a translation nobody can
    /// read is a translation nobody can check.
    ///
    /// The result borrows this bridge's identity and ALPN storage.
    /// Keep the bridge and its borrowed ALPN alive while using the result.
    /// Import the registered `quic` module to name the result type.
    pub fn tlsConfig(self: *const Bridge) quic.tls13.TlsConfig {
        return self.manager.tls_config;
    }

    /// Withdraw `alpn` from what this bridge offers, and say whether it was
    /// being offered at all.
    ///
    /// **One array, three views over it, and the withdrawal has to reach all
    /// three.** `create` copied the offered names into `alpn_list` and pointed
    /// the core's `TlsConfig.alpn` at `alpn_list[0..alpn_count]`; that slice was
    /// frozen then (`buildTlsConfig`), so shortening this bridge's own count
    /// alone would leave every protocol on offer exactly as it was. And every
    /// connection the core accepts is handed `self.tls_config` *by value*
    /// (`connection_manager.zig:450`), which copies the slice header rather
    /// than the names behind it: a handshake accepted before this call reads
    /// this array under the length it was accepted with, and reads whatever is
    /// in the slots up to that length.
    ///
    /// **Which is why the slots the count stops covering are overwritten rather
    /// than abandoned.** They hold `retired_alpn`, a name the core cannot select
    /// at all, so a handshake accepted before this call and still waiting for
    /// the rest of its ClientHello chooses among the protocols still on offer,
    /// in the order this bridge now offers them, and is refused with
    /// `no_application_protocol` when it named none of them — rather than
    /// settling on a protocol this node has closed. The window is a ClientHello
    /// spanning more than one Initial packet: the core accepts the connection on
    /// the first and reads the protocol when the rest arrives, which is a later
    /// round, and rounds are where a retirement happens.
    ///
    /// **A connection that has already chosen keeps it.** The choice is the
    /// handshake's own `selected_alpn` (`tls13.zig:1967`), written when the
    /// ClientHello was read and never re-read from this array, so nothing here
    /// touches it: what is live finishes on the protocol it negotiated, which is
    /// what a retiring protocol wants.
    ///
    /// Order is kept, because order is preference: the server takes the first
    /// entry of this list the peer also named (`tls13.zig:3075`), so the
    /// survivors move up rather than swap. Nothing is allocated, freed, or
    /// copied out — `alpn_list` holds borrowed pointers and this rewrites them
    /// in place, and the bytes behind them are the caller's until `destroy`.
    ///
    /// A name this bridge never offered answers false and changes nothing.
    /// With no protocols left, new handshakes are refused with
    /// `no_application_protocol`. Already selected ALPNs remain unchanged.
    ///
    /// Serialize with `recv` and with anything else reaching `manager`: the
    /// core reads this array while it is parsing a handshake, so withdraw
    /// between rounds rather than inside one.
    pub fn withdrawAlpn(self: *Bridge, retiring_alpn: []const u8) bool {
        var kept: usize = 0;
        var removed = false;
        for (self.alpn_list[0..self.alpn_count]) |offered| {
            if (std.mem.eql(u8, offered, retiring_alpn)) {
                removed = true;
                continue;
            }
            // `kept` never runs ahead of the element being read, so this never
            // overwrites an entry the walk has not reached.
            self.alpn_list[kept] = offered;
            kept += 1;
        }
        if (!removed) return false;
        // The slots the walk just emptied still belong to handshakes accepted
        // before this call: each was handed this array's header with the length
        // it had then, so a name the core cannot select is what stops them
        // naming what was withdrawn. See `retired_alpn`.
        @memset(self.alpn_list[kept..self.alpn_count], retired_alpn);
        self.alpn_count = kept;
        // The slice the core is pointed at, so the next handshake negotiates
        // against the survivors rather than against this bridge's own count.
        self.manager.tls_config.alpn = self.alpn_list[0..kept];
        return true;
    }

    /// The core's TLS configuration for this identity.
    ///
    /// The two vocabularies differ because the core was written for a TLS
    /// stack that had an X.509 chain and a host name to check, and a node
    /// has neither: it is 32 bytes of ed25519 public key presented as a
    /// `SubjectPublicKeyInfo`, and the peer is named by the key rather than
    /// by a name in a certificate. So the translation is one-way and total —
    /// a node id in, an SPKI and a pin out — and it happens here once, rather
    /// than at each of the call sites that would otherwise have to know both
    /// spellings.
    ///
    /// `expect_peer_node_id` is deliberately left null. It is read only by
    /// `clientProcessCertificate` and a `ConnectionManager` never runs a
    /// client handshake, so setting it would read as a second pin and enforce
    /// nothing; the pin a server enforces is `client_auth.expect_node_id`,
    /// set above.
    ///
    /// The block is handed over whenever a peer is pinned, not only when a
    /// certificate is demanded: it is where the pin lives, so withholding it
    /// withholds the pin — see `demandsPeerCertificate`, which is also what
    /// `Config.require_peer_certificate` no longer decides on its own.
    fn buildTlsConfig(self: *Bridge, config: config_mod.Config) quic.tls13.TlsConfig {
        self.spki = quic.tls13.ed25519Spki(&self.node_id.toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = undefined;
        @memcpy(self.alpn_list[0..config.alpns.len], config.alpns);
        return .{
            .cert_chain_der = &self.cert_chain,
            .private_key_bytes = self.seed[0..],
            .private_key_algorithm = .ed25519,
            // The slice, not the array: the core negotiates against exactly
            // the protocols this bridge was configured with, and offering the
            // unused tail would offer protocols nobody chose.
            .alpn = self.alpn_list[0..self.alpn_count],
            .client_auth = if (config_mod.demandsPeerCertificate(config)) &self.client_auth else null,
        };
    }

    /// One datagram through the core.
    ///
    /// `map` is the caller's address map and is borrowed for this call only.
    /// It answers who owns the address a datagram arrived from, which is the
    /// question a departing path is asked.
    ///
    /// `scratch` is the core's buffer: the datagram is copied into its front
    /// and any stateless reply is written behind it, so one buffer serves both
    /// and the reply borrows it until the next call. The core takes its input
    /// as `[]u8` because it decrypts in place; the copy is the price of that,
    /// and it is paid once per datagram rather than once per packet.
    ///
    /// `at` is the caller's instant and `random` the caller's generator, for
    /// the reason the module doc gives.
    ///
    /// `scratch` must not overlap `datagram.bytes`. Replies borrow `scratch`
    /// until it is reused or released. The source key is an independent copy.
    /// `error.NoRoom` before processing leaves connection state unchanged.
    /// `error.OutOfMemory` may follow committed packet processing, but preserves
    /// routing keys. Do not replay the input; synchronize live entries through
    /// `manager.syncCids` before draining newly issued CIDs, or close the owner.
    ///
    /// **A token this node has already answered is refused before the core is
    /// asked at all — but only when no connection of this bridge's owns the
    /// destination id it arrived on.** That exception is the whole shape of
    /// the filter, and it is the difference between *admission* and *a
    /// connection's own traffic*: RFC 9000 §17.2.5 has a client present one
    /// Retry token in every Initial that carries the rest of its ClientHello,
    /// so a ClientHello longer than one datagram arrives as several packets
    /// that all carry it, and a filter that dropped the second would strand
    /// the handshake it had already admitted. What is left to refuse is a
    /// datagram naming no connection this node holds: a replay of a captured
    /// Initial, which costs no AEAD open here and none in the manager either,
    /// and gets no second Retry — which is what RFC 9000 §17.2.5 asks a
    /// client to expect and what a loaded node actually pays for.
    ///
    /// The destination id is read out of the same header walk as the token
    /// (`retry.initialHeader`), and an id over RFC 9000 §17.2.2's twenty bytes
    /// is refused rather than looked up: the core's routing key truncates one
    /// (`connection_manager.zig:38-41`), so asking it about an over-long id
    /// would answer for whichever connection holds the same twenty bytes. A
    /// NEW_TOKEN is *not* dropped either: it is reusable by design, and
    /// `retry.Gate` records only what `validateRetryToken` opened. Everything
    /// else — no token, an unknown one, one this node did not mint — goes to
    /// the manager, which is the authority on whether a token opens.
    pub fn recv(
        self: *Bridge,
        map: *const addr_map.MappedAddrs,
        datagram: Datagram,
        scratch: []u8,
        at: conn_mod.Instant,
        random: std.Random,
    ) error_mod.Error!Ingress {
        if (datagram.bytes.len > scratch.len) return error.NoRoom;
        const classification = base_ula.classify(datagram.from);
        const owner: ?addr_map.Key = switch (classification) {
            // Only a synthetic address can be owned; a direct path needs no
            // map and keeps its real port, which is why `classify` carries it
            // through whole rather than reducing it to a `Ula`.
            .any_path, .relay, .custom => |octets| map.lookup(octets),
            .ip => null,
        };
        const source: Source = .{
            .socket = datagram.from,
            .classification = classification,
            .owner = owner,
        };

        // The pre-accept filter, ahead of the copy and ahead of the manager: a
        // spent token is free to recognise, and this is the only place in the
        // file that reads a header rather than a payload. Both of the facts it
        // needs come out of one walk, because the manager would look the
        // destination id up on every datagram it routes anyway.
        if (retry.initialHeader(datagram.bytes)) |header| {
            if (header.token) |token| {
                switch (self.checkRetryToken(token, datagram.from, at)) {
                    .spent => {
                        // Spent, and belonging to nobody here. The lookup is
                        // the core's own routing table, asked with the very id
                        // the core would route this datagram by
                        // (`connection_manager.zig:683`), so a datagram it
                        // would have handed to a connection is exactly the one
                        // that is not a replay. Over RFC 9000 §17.2.2's cap the
                        // id names no connection by definition, and asking
                        // anyway would answer from a truncated key.
                        const owned = header.dcid.len <= retry.max_connection_id and
                            self.manager.findByDcid(header.dcid) != null;
                        if (!owned) return .{ .source = source, .outcome = .dropped };
                    },
                    .unknown, .recorded, .invalid => {},
                }
            }
        }

        @memcpy(scratch[0..datagram.bytes.len], datagram.bytes);
        const action = try self.manager.recvDatagram(
            scratch[0..datagram.bytes.len],
            conn_mod.toCoreAddress(datagram.from),
            conn_mod.toCoreAddress(datagram.local),
            ecnBits(datagram.ecn),
            scratch[datagram.bytes.len..],
            at,
            random,
        );
        return .{
            .source = source,
            .outcome = switch (action) {
                .processed => |entry| .{ .processed = .{ .entry = entry } },
                // A stateless reply is a send, and it carries the codepoint
                // the request arrived with. A Retry is the first packet a peer
                // hears from this node, and it is usually the answer to a
                // datagram the peer marked ECT: dropping the codepoint here
                // would have that peer's loss reported against a path it never
                // chose, which is the one mistake this seam exists to make
                // impossible. `batch.Report` is where the socket would have
                // said so, and a stateless reply has no caller to read it.
                .send_response => |bytes| .{ .reply = batch.Send.single(bytes, datagram.ecn) },
                .dropped => .dropped,
                .foreign => |server_id| .{ .foreign = server_id },
            },
        };
    }

    /// What `token` is, for a datagram that arrived from `from` at `at`.
    ///
    /// `RetryVerdict.spent` is the gate's answer: this node already validated
    /// those exact bytes for that exact address, and the cipher's answer cannot
    /// have changed. `recorded` means it opened just now and will answer `spent`
    /// next time; `unknown` means it is a NEW_TOKEN, which is reusable and is
    /// never recorded; `invalid` means it is not one of ours. All four are
    /// datagrams the core should see, `spent` included whenever the datagram
    /// names a connection this bridge owns — a question about the destination
    /// id and not about the token, which is why it is `recv` and not this
    /// function that asks it.
    pub fn checkRetryToken(
        self: *Bridge,
        token: []const u8,
        from: base_addr.SocketAddr,
        at: conn_mod.Instant,
    ) retry.Verdict {
        return self.retry_gate.check(
            self.retry_token_key,
            token,
            conn_mod.toCoreAddress(from),
            at,
        );
    }

    /// Whether `token` was already answered for `from`, read without the
    /// cipher and without changing what the gate holds.
    ///
    /// A token this bridge sealed and has not seen echoed yet answers false:
    /// the window between issuing one and the client coming back with it is the
    /// one moment a matching record must not read as spent.
    pub fn checkRetryTokenIsSpent(
        self: *const Bridge,
        token: []const u8,
        from: base_addr.SocketAddr,
        at: conn_mod.Instant,
    ) bool {
        return self.retry_gate.spent(token, conn_mod.toCoreAddress(from), at);
    }

    /// Seal a Retry token for a datagram that arrived from `from`, bound to
    /// `odcid` and `retry_scid`.
    ///
    /// **The key is this bridge's, not the caller's**, because a token sealed
    /// under any other key is one `recv` would refuse, and the whole point is
    /// that the client comes back with it. `at` and `random` are the caller's
    /// for the module doc's reason, and `random` must be a real CSPRNG: the
    /// nonce is drawn from it.
    ///
    /// The token is recorded as unspent, so the echo that follows is recognised
    /// without a cipher open and a second echo is dropped.
    pub fn issueRetryToken(
        self: *Bridge,
        odcid: []const u8,
        retry_scid: []const u8,
        from: base_addr.SocketAddr,
        at: conn_mod.Instant,
        random: std.Random,
    ) retry.Error!retry.RetryToken {
        return self.retry_gate.issue(
            self.retry_token_key,
            odcid,
            retry_scid,
            conn_mod.toCoreAddress(from),
            at,
            random,
        );
    }

    /// How many Retry tokens this bridge is holding, of `retry.max_tracked`. A
    /// caller watching the bound reads it here.
    pub fn retryTokensTracked(self: *const Bridge) usize {
        return self.retry_gate.tracked();
    }

    /// One pass of the core's timers for `conn`, at the caller's instant.
    ///
    /// A finished connection leaves the core's table here and its memory
    /// stands until `sweep`, which is what lets a caller drain the close it
    /// just produced before the memory goes.
    pub fn tick(
        self: *Bridge,
        conn: conn_mod.Conn,
        at: conn_mod.Instant,
        random: std.Random,
    ) Tick {
        if (self.manager.tickEntry(conn.entry, at, random)) return .live;
        return .finished;
    }

    /// The i-th connection the core holds, or null when there is no i-th.
    ///
    /// A borrowed handle, and no more than `tick` says a connection is live:
    /// after `sweep` it points at freed bytes. Walking this by index rather
    /// than taking a slice keeps the conversion allocation-free, which is the
    /// only reason it is not a slice of `Conn`.
    pub fn connectionAt(self: *const Bridge, index: usize) ?conn_mod.Conn {
        if (index >= self.manager.entries.items.len) return null;
        return .{ .entry = self.manager.entries.items[index] };
    }

    /// Free the connections `tick` took out of the table.
    ///
    /// After all processing for the cycle, and never in the middle of it: a
    /// caller still holding a handle must read a closed connection rather
    /// than freed memory.
    pub fn sweep(self: *Bridge) void {
        self.manager.freeDeadEntries();
    }
};

/// The two bits the core reads off an `IP_TOS` or `IPV6_TCLASS`, or zero.
///
/// Zero is `IP_TOS_NOT_ECT`, so "no codepoint" and "not-ECT" are the same
/// value on this side too, which is what `batch.Recv.ecnFromBits` says from
/// the other end.
fn ecnBits(codepoint: ?batch.Ecn) u2 {
    return if (codepoint) |set| @truncate(set.toBits()) else 0;
}

const t = std.testing;

/// A client's own synthetic address, in the subnet a node is reached on
/// before a path is chosen.
const client_host: base_ula.HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
/// The server's, in the relay subnet — a relay path is the case
/// `docs/PLAN.md`'s mapping exists for, so it is the one these tests drive.
const server_host: base_ula.HostBits = .{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

/// How the client and the server each see the other, as this project
/// addresses it. Both are synthetic: the core never sees a real IP here.
const client_addr: base_addr.SocketAddr = base_ula.socketAddrFor(.any_path, client_host);
const server_addr: base_addr.SocketAddr = base_ula.socketAddrFor(.relay, server_host);

/// Fixed seeds, so a run draws the same connection ids and the same nonces
/// every time. `generateDeterministic` fails only on a degenerate seed,
/// which a constant byte pattern is not.
const server_seed: [base_key.SecretKey.seed_length]u8 = @splat(0x53);
const client_seed: [base_key.SecretKey.seed_length]u8 = @splat(0xc1);

/// The one ALPN both ends speak.
const alpn = "ozai";

/// The name the client asks for. Nothing resolves it and nothing checks it:
/// there is no certificate to match a name against, only a key to compare.
const server_name = "ozai.invalid";

/// How many protocol names the test client can offer, and the size of its
/// storage for them.
///
/// More than one because a client never serves a protocol, so `max_alpns` has
/// nothing to say here: what needs the room is a ClientHello too long for one
/// Initial packet, and length comes from the names. See `pad_alpn`.
const client_alpns_max: usize = 10;

/// 224 bytes of protocol name: under the 255 RFC 7301's length byte encodes,
/// and far over the 32 a selection can hold, so the core carries it in a
/// client's offer and can never answer with it. Its job is to make the offer
/// long enough that the server's accept of a connection and its reading of
/// that connection's protocol land in different rounds, which is the window
/// `withdrawAlpn` has to reach. A build sending a post-quantum key share gets
/// the same window without any of this.
const pad_alpn: []const u8 = "ozai-withdrawal-test-padding" ** 8;
comptime {
    std.debug.assert(pad_alpn.len <= 255);
}

/// Where virtual time starts: a second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
const start: conn_mod.Instant = 1_000 * std.time.ns_per_s;

/// Seeded engine kept stable while calls use its `std.Random` interface.
const Prng = std.Random.DefaultPrng;

/// Fixture datagram capacity, matching the core packer's 1500-byte ceiling.
const max_datagram = 1500;

/// The core's floor for a datagram, re-exported rather than written down: a
/// test that pads to its own idea of 1200 would keep passing if the core's
/// floor moved. The same value `Conn.drain` refuses a short buffer against.
const min_initial = conn_mod.min_datagram;

/// How many socket writes one `drain` hands back. A connection's whole flight
/// fits; a caller that wants fewer gets a short answer rather than a refusal
/// — see `Conn.drain` — and asks again for the rest.
const max_egress = 32;

/// How many datagrams `exchange` moves before it decides the two ends have
/// nothing left for each other.
const max_rounds = 8;

/// A long header for a version the core does not speak, padded to the size
/// RFC 9000 §14.1 requires before a server will spend anything on it.
///
/// This is the cheapest thing the core consults a timer for: it reaches its
/// Version Negotiation reply limiter and nothing else, and no connection is
/// created, so a test can drive `recv` without a handshake.
fn unsupportedVersionProbe() [min_initial]u8 {
    var bytes = [_]u8{0} ** min_initial;
    // Long header (0x80), fixed bit (0x40), packet type 0b00.
    bytes[0] = 0xc0;
    std.mem.writeInt(u32, bytes[1..5], 0x0a0a0a0a, .big);
    bytes[5] = 8; // destination connection id length
    @memset(bytes[6..14], 0x5a);
    bytes[14] = 8; // source connection id length
    @memset(bytes[15..23], 0x3c);
    // A zero token length and a zero payload length. The rest stays zero, so
    // the next byte the routing loop looks at has the fixed bit clear and it
    // stops there — one packet in the datagram, which is what it claims to be.
    return bytes;
}

/// A client connection, standing in for the peer's half of a relay path.
///
/// `quic.ConnectionManager` only ever runs a server — there is no client arm
/// of it — so the other half of a handshake is built the way
/// `vendor/quic/src/quic/lossy_link_test.zig` builds it: a `Connection` and a
/// `TlsConfig` the caller's node id is pinned into. That is not a gap in this
/// file, it is the core's shape.
///
/// Built in place rather than returned by value because its config points at
/// its own `spki`: a returned struct is moved into the caller's frame and the
/// pointer would dangle.
const Client = struct {
    conn: *quic.connection.Connection,
    engine: Prng,
    /// The certificate this client presents, and the seed behind it, kept
    /// here for as long as the config points at them.
    spki: [config_mod.spki_length]u8,
    cert_chain: [1][]const u8,
    /// The protocols this client offers, and the storage the handshake's config
    /// points at — the core keeps that config by value, so the names are copied
    /// here for the same reason the bridge's own list is.
    alpn_list: [client_alpns_max][]const u8,
    seed: [base_key.SecretKey.seed_length]u8,
    /// The send-side scratch, and the core's mutable read buffer beside it so
    /// a datagram going each way never shares bytes.
    buffer: [max_datagram]u8 = undefined,
    inbound: [max_datagram]u8 = undefined,

    /// `alpns` is what this client offers: most tests the one protocol both
    /// ends speak, and the withdrawal test a list long enough that the server
    /// accepts the connection in one round and reads its protocol in another.
    ///
    /// `datagram_frame_size` and `max_uni_streams` are what this client
    /// advertises, and null means the core's own default: a null datagram size
    /// is no DATAGRAM support at all, which is what most of these tests want
    /// and what the two that do want it have to ask for.
    fn init(
        self: *Client,
        secret: base_key.SecretKey,
        expect: ?base_key.NodeId,
        alpns: []const []const u8,
        engine_seed: u64,
        at: conn_mod.Instant,
        datagram_frame_size: ?u64,
        max_uni_streams: ?u64,
    ) !void {
        std.debug.assert(alpns.len > 0);
        std.debug.assert(alpns.len <= client_alpns_max);
        self.* = .{
            .conn = undefined,
            .engine = Prng.init(engine_seed),
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .seed = secret.toBytes()[0..base_key.SecretKey.seed_length].*,
        };
        self.spki = quic.tls13.ed25519Spki(&secret.nodeId().toBytes());
        self.cert_chain = .{self.spki[0..]};
        @memcpy(self.alpn_list[0..alpns.len], alpns);
        self.conn = try t.allocator.create(quic.connection.Connection);
        errdefer t.allocator.destroy(self.conn);
        try quic.connection.connectInto(
            self.conn,
            t.allocator,
            server_name,
            .{
                .max_datagram_frame_size = datagram_frame_size,
                // The core's own default is 100 (`connection.zig:926`) and a
                // default is not a declaration this file can name.
                .initial_max_streams_uni = max_uni_streams orelse 100,
            },
            .{
                .cert_chain_der = &.{},
                .private_key_bytes = &.{},
                // The offered slice, not the whole array: the rest is storage
                // this client never fills.
                .alpn = self.alpn_list[0..alpns.len],
                .server_name = server_name,
                // The client's own pin on the server — the one field of the
                // core's config a client actually reads. The bridge sets the
                // mirror image of it on the server side; see `buildTlsConfig`.
                .expect_peer_node_id = if (expect) |peer| peer.toBytes() else null,
                .client_certificate = .{
                    .cert_chain_der = &self.cert_chain,
                    .private_key_bytes = self.seed[0..],
                    .private_key_algorithm = .ed25519,
                },
            },
            null,
            at,
            self.random(),
        );
        self.conn.paths[0].peer_addr = conn_mod.toCoreAddress(server_addr);
        self.conn.paths[0].local_addr = conn_mod.toCoreAddress(client_addr);
    }

    fn deinit(self: *Client) void {
        self.conn.deinit();
        t.allocator.destroy(self.conn);

        // The connection is freed, and nothing else in here outlives it: the
        // handshake's config points at `spki` and `alpn_list`, which is why
        // this struct was built in place rather than returned. Left standing,
        // a second `deinit` or a read after the `defer` would walk a connection
        // that is already back in the testing allocator.
        self.* = undefined;
    }

    fn random(self: *Client) std.Random {
        return self.engine.random();
    }

    /// Hand one datagram to the client, as a socket would. Everything the
    /// client ever receives comes from the server, so there is one address.
    ///
    /// The core takes its input as `[]u8` because it decrypts in place, so
    /// the datagram is copied in from the send seam's slice. It is the same
    /// copy `Bridge.recv` makes and for the same reason: the read buffer
    /// belongs to whoever owns it, and the core does not get to keep a
    /// pointer into somebody else's.
    fn receive(self: *Client, bytes: []const u8, at: conn_mod.Instant) void {
        std.debug.assert(bytes.len <= self.inbound.len);
        @memcpy(self.inbound[0..bytes.len], bytes);
        self.conn.handleDatagram(self.inbound[0..bytes.len], .{
            .to = conn_mod.toCoreAddress(client_addr),
            .from = conn_mod.toCoreAddress(server_addr),
            .datagram_size = bytes.len,
        }, at, self.random());
    }
};

/// Drain a connection and hand every datagram it produced to the client.
///
/// The runs go through `batch.Runs` on the way, at a capability that cannot
/// segment: a test that wanted to prove the batching would pass
/// `Capability.linux_full` and count the runs, and `batch.zig` has tests of
/// its own for that. What this proves is that what the bridge hands over is
/// something the send seam can consume at all.
fn deliver(
    conn: conn_mod.Conn,
    client: *Client,
    egress: []conn_mod.Egress,
    out: []u8,
    at: conn_mod.Instant,
) !bool {
    const sends = try conn.drain(egress, out, at, client.random());
    for (sends) |send| {
        var runs = try batch.Runs.init(send.send, batch.Capability.none);
        while (runs.next()) |run| client.receive(run.contents, at);
    }
    return sends.len != 0;
}

/// Move datagrams between the client and the bridge until neither has more.
///
/// Time never advances here: `at` is the instant every single call is made
/// at. That is the point of the whole design — a handshake driven entirely in
/// one instant is a handshake a test fully controls, and the only way to get
/// one is that nothing underneath reads a clock.
fn exchange(
    client: *Client,
    bridge: *Bridge,
    map: *const addr_map.MappedAddrs,
    at: conn_mod.Instant,
) !void {
    var scratch: [2 * max_datagram]u8 = undefined;
    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        var moved = false;
        while (true) {
            const len = client.conn.sendAt(&client.buffer, at, client.random()) catch break;
            if (len == 0) break;
            const ingress = try bridge.recv(map, .{
                .bytes = client.buffer[0..len],
                .from = client_addr,
                .local = server_addr,
                .ecn = null,
            }, scratch[0..], at, client.random());
            switch (ingress.outcome) {
                .processed => |conn| {
                    if (try deliver(conn, client, egress[0..], out[0..], at)) moved = true;
                },
                .reply => |reply| {
                    client.receive(reply.contents, at);
                    moved = true;
                },
                // Nothing to move and nothing to answer.
                .dropped, .foreign => {},
            }
        }
        if (!moved) break;
    }
    bridge.sweep();
}

test "a node's identity reaches the core as a bare SPKI and the handshake finishes" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(1);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();

    // The translation, read back rather than assumed. One certificate, 44
    // bytes, wrapping this node's own id, the peer pinned in the one field
    // a server actually enforces, and nothing set in the field that only a
    // client reads.
    const tls = bridge.tlsConfig();
    try t.expectEqual(@as(usize, 1), tls.cert_chain_der.len);
    try t.expectEqual(@as(usize, config_mod.spki_length), tls.cert_chain_der[0].len);
    try t.expectEqualSlices(
        u8,
        &quic.tls13.ed25519Spki(&server_secret.nodeId().toBytes()),
        tls.cert_chain_der[0],
    );
    try t.expectEqual(quic.tls13.PrivateKeyAlgorithm.ed25519, tls.private_key_algorithm);
    try t.expectEqual(@as(usize, 1), tls.alpn.len);
    try t.expectEqualStrings(alpn, tls.alpn[0]);
    try t.expectEqual(@as(?[32]u8, null), tls.expect_peer_node_id);
    try t.expectEqual(client_secret.nodeId().toBytes(), tls.client_auth.?.expect_node_id.?);
    try t.expectEqual(quic.tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // The consequence of the translation above: a handshake completes, and
    // it completes over two synthetic addresses with no socket anywhere.
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 2, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    try t.expectEqual(@as(usize, 1), bridge.manager.connectionCount());
    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());

    // The answer to the question `docs/PLAN.md`'s mapping raises: the core
    // does not validate a peer's address, so an RFC 4193 ULA is a peer
    // address like any other. It round-trips through the core's own address
    // type unchanged, and `classify` still recognises it.
    try t.expectEqual(client_addr, conn.peer().?);
    try t.expectEqual(server_addr, conn.local().?);
    try t.expectEqual(
        base_ula.Classification{ .any_path = base_ula.ulaFor(.any_path, client_host) },
        base_ula.classify(conn.peer().?),
    );

    // The peer identity this connection runs on came out of the certificate
    // the client presented and from nothing else. The whole certificate is
    // that client's 44 bytes, the policy that accepted it is the one this
    // bridge built, and the ALPN both ends settled on is the one string the
    // caller named — three fields of the translation, read back off a
    // connection that used them.
    try t.expectEqualSlices(
        u8,
        &quic.tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(alpn, conn.entry.conn.negotiatedAlpn());
}

test "a bridge that pins no node still learns which node it is talking to" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // One field changed from the test above and nothing else: no expected
    // peer. The certificate request is still made, so the connection is
    // still identified — the peer has proved possession of the id it
    // presented rather than being the node the caller asked for.
    var engine = Prng.init(3);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqual(@as(?[32]u8, null), bridge.tlsConfig().client_auth.?.expect_node_id);

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 4, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    try t.expectEqualSlices(
        u8,
        &quic.tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(@as(?[32]u8, null), conn.entry.conn.clientAuth().?.expect_node_id);
}

test "egress is the batcher's value, and a burst of one size is one send" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(5);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 6, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());

    // Enough payload for several datagrams, which is what makes the batching
    // observable at all: one datagram is one send whatever the code does.
    const payload = "ozai" ** 4096;
    const stream = try conn.entry.conn.openStream();
    try stream.send.writeData(payload);
    stream.send.close();

    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var segmented: usize = 0;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        const sends = try conn.drain(egress[0..], out[0..], start, client.random());
        if (sends.len == 0) break;
        for (sends) |send| {
            // Every send is addressed to the peer address the core holds,
            // which is a synthetic address and survives the round trip.
            try t.expectEqual(client_addr, send.to);
            // And every send is a value the batcher can cut into socket
            // writes whose payload comes back whole.
            var runs = try batch.Runs.init(send.send, batch.Capability.linux_full);
            var rejoined: usize = 0;
            while (runs.next()) |run| rejoined += run.contents.len;
            try t.expectEqual(send.send.contents.len, rejoined);
            var cmsgs: [batch.max_cmsg]batch.Cmsg = undefined;
            const written = batch.cmsg(send.send, .v6, &cmsgs);
            try t.expectEqual(
                @as(usize, if (send.send.isSegmented()) batch.max_cmsg else 1),
                written.len,
            );
            if (send.send.isSegmented()) segmented += 1;
            var runs2 = try batch.Runs.init(send.send, batch.Capability.none);
            while (runs2.next()) |run| client.receive(run.contents, start);
        }
    }

    // The finding in its strongest form: a core datagram fits
    // `batch.Send` exactly, so a burst of equally sized QUIC packets comes
    // out of the bridge as one `UDP_SEGMENT` send rather than N.
    try t.expect(segmented > 0);
}

test "a caller's instant reaches the core byte for byte" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(7);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const probe = unsupportedVersionProbe();
    // An instant nothing on this host would produce: a monotonic clock that
    // started at an odd offset and has a sub-millisecond remainder on it.
    const at: conn_mod.Instant = 7 * std.time.ns_per_s + 123_456_789;
    var scratch: [2 * max_datagram]u8 = undefined;
    const ingress = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], at, engine.random());

    // Version Negotiation is the one reply the core writes without a
    // connection, and reaching it costs the reply limiter a refill whose only
    // input is the instant.
    try t.expect(ingress.outcome == .reply);
    try t.expect(ingress.outcome.reply.contents.len > 0);
    try t.expectEqual(at, bridge.manager.reply_limits.version_negotiation.last_refill_ns);
}

test "the same call at two instants gives two answers" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(11);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 12, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    const stream = try conn.entry.conn.openStream();
    try stream.send.writeData("a datagram to send");
    stream.send.close();

    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;

    // At the instant the connection was accepted, the same two calls say
    // there is a flight to send and the connection is alive.
    const before = try conn.drain(egress[0..], out[0..], start, client.random());
    try t.expect(before.len > 0);
    try t.expectEqual(Tick.live, bridge.tick(conn, start, client.random()));

    // At an instant past the idle timeout, the same two calls say the
    // connection is over and there is nothing left to send. Nothing in this
    // file read a clock to get there: the answers differ because the
    // arguments did, which is the property `docs/DECISIONS/0002` is about and
    // the only way a test can tell a threaded clock from a stored one.
    const later = start + 60 * std.time.ns_per_s;
    try t.expectEqual(Tick.finished, bridge.tick(conn, later, client.random()));
    try t.expectEqual(
        @as(usize, 0),
        (try conn.drain(egress[0..], out[0..], later, client.random())).len,
    );

    bridge.sweep();
}

test "an address that arrived off the wire is the path it stands for" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(13);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var map_engine = Prng.init(14);
    const relay = try base_relay_url.RelayUrl.parse("https://relay.example.com");
    const owned: addr_map.Key = .{ .relay = .{ .relay = relay, .node = server_secret.nodeId() } };
    const allocated = try map.get(t.allocator, owned, map_engine.random());

    const probe = unsupportedVersionProbe();
    var scratch: [2 * max_datagram]u8 = undefined;
    const from_relay: base_addr.SocketAddr = .{ .ip = .{ .v6 = allocated }, .port = base_ula.mapped_port };
    const ingress = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = from_relay,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, engine.random());

    // `classify` says which path the address stands for; the map says whose
    // it is. A datagram on a relay path names the relay and the peer, and the
    // two answers are separate lookups on purpose.
    try t.expectEqual(
        base_ula.Classification{ .relay = allocated },
        ingress.source.classification,
    );
    try t.expectEqual(from_relay, ingress.source.socket);
    try t.expectEqual(owned, ingress.source.owner.?);

    // An address this node's map never handed out has no owner, and says so
    // rather than guessing. `client_addr` is in the `any_path` subnet and was
    // never allocated here.
    const unallocated = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, engine.random());
    try t.expectEqual(
        base_ula.Classification{ .any_path = base_ula.ulaFor(.any_path, client_host) },
        unallocated.source.classification,
    );
    try t.expectEqual(@as(?addr_map.Key, null), unallocated.source.owner);
}

test "a transport key the caller supplied is used, and one it did not is drawn from its Io" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var engine = Prng.init(17);

    const supplied: [retry.key_length]u8 = @splat(0x77);
    const given = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
        .retry_token_key = supplied,
    }, engine.random());
    defer given.destroy();
    try t.expectEqualSlices(u8, &supplied, &given.manager.retry_token_key);

    // Two bridges over one identity, drawn from one `std.Io`, are two
    // different bridges. A constant the bridge defaulted to would make these
    // equal; so would storing the generator.
    const drawn_a = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer drawn_a.destroy();
    const drawn_b = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer drawn_b.destroy();

    try t.expect(!std.mem.eql(
        u8,
        &drawn_a.manager.retry_token_key,
        &drawn_b.manager.retry_token_key,
    ));
    try t.expect(!std.mem.eql(
        u8,
        &drawn_a.manager.static_reset_key,
        &drawn_b.manager.static_reset_key,
    ));
    // And a different key from the supplied one, or the two draws above
    // would only be proving that `retry_token_key` is not read.
    try t.expect(!std.mem.eql(u8, &supplied, &drawn_a.manager.retry_token_key));
}

/// The identity storage a live bridge's TLS configuration points at, checked
/// as ownership and not as contents alone.
///
/// `create` put the bridge on the heap precisely so that these pointers would
/// not move, and `tlsConfig` hands the caller a view over them. A bridge whose
/// configuration pointed at a block a refused `create` had left behind, or at
/// one it had freed, would still answer with the right bytes here for exactly
/// as long as nothing reused that memory — so the aliasing is the invariant,
/// and the bytes only say which identity is being presented.
fn expectBridgeOwnsItsTlsConfig(bridge: *const Bridge, node: base_key.NodeId, pin: base_key.NodeId) !void {
    const tls = bridge.tlsConfig();
    try t.expectEqual(@as(usize, 1), tls.cert_chain_der.len);
    try t.expectEqual(@as(usize, 1), tls.alpn.len);
    try t.expectEqual(@intFromPtr(&bridge.cert_chain), @intFromPtr(tls.cert_chain_der.ptr));
    try t.expectEqual(@intFromPtr(&bridge.alpn_list), @intFromPtr(tls.alpn.ptr));
    try t.expectEqualSlices(u8, bridge.spki[0..], tls.cert_chain_der[0]);
    try t.expectEqualSlices(u8, &quic.tls13.ed25519Spki(&node.toBytes()), tls.cert_chain_der[0]);
    try t.expectEqualStrings(alpn, tls.alpn[0]);
    try t.expectEqual(
        @intFromPtr(bridge.seed[0..].ptr),
        @intFromPtr(tls.private_key_bytes.ptr),
    );
    // The peer pin lives in the bridge too and is the block the core reads, so
    // a dangling one is a pin that verifies nothing at all.
    const auth = tls.client_auth orelse return error.TestUnexpectedResult;
    try t.expectEqual(@intFromPtr(&bridge.client_auth), @intFromPtr(auth));
    try t.expectEqual(pin.toBytes(), auth.expect_node_id.?);
    try t.expectEqual(quic.tls13.ClientAuth.Mode.required, auth.mode);
    // One node id, presented and pinned, read off the bridge rather than
    // restated from the config the caller handed in.
    try t.expectEqual(node.toBytes(), bridge.nodeId().toBytes());
}

test "a refused bridge leaves no identity storage behind it" {
    // One allocation and no other, which is the claim this test exists for:
    // `create` allocates the bridge, `drawKey` draws through the caller's
    // `std.Io` rather than through the allocator, and `ConnectionManager.init`
    // documents that it "performs no allocation or I/O"
    // (`connection_manager.zig:313`). Refusing the one boundary there is, and
    // finding no second one to refuse, is what turns the claim into an
    // observation.
    var server_key = try base_key.SecretKey.fromSeed(server_seed);
    defer server_key.deinit();
    var peer_key = try base_key.SecretKey.fromSeed(client_seed);
    defer peer_key.deinit();
    var engine = Prng.init(29);

    // A fixed backing array is what makes "nothing was kept" exact: its end
    // index counts every byte handed out, so zero is zero rather than "no leak
    // was noticed once the run was over".
    var backing: [@sizeOf(Bridge)]u8 align(@alignOf(Bridge)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);

    var refusing = t.FailingAllocator.init(fixed.allocator(), .{ .fail_index = 0 });
    try t.expectError(
        error.OutOfMemory,
        Bridge.create(refusing.allocator(), t.io, .{
            .secret = server_key,
            .expect_peer = peer_key.nodeId(),
            .alpns = &.{alpn},
        }, engine.random()),
    );
    try t.expect(refusing.has_induced_failure);
    // Not a balance at the end of a run: not one byte was ever handed out, so
    // the block a bridge would have occupied is still the caller's to give to
    // the next one. A `create` that allocated and then failed could not give
    // an end index back.
    try t.expectEqual(@as(usize, 0), fixed.end_index);

    // And the same allocator answers a whole bridge, at the first byte of that
    // same array, whose configuration borrows the bridge's own storage. A
    // refusal that had kept identity storage would have left something behind
    // for this one to sit behind, and one that had freed storage a
    // configuration still pointed at would answer with reused bytes.
    const bridge = try Bridge.create(fixed.allocator(), t.io, .{
        .secret = server_key,
        .expect_peer = peer_key.nodeId(),
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqual(@sizeOf(Bridge), fixed.end_index);
    const block: []u8 = @as([*]u8, @ptrCast(bridge))[0..@sizeOf(Bridge)];
    try t.expect(fixed.isLastAllocation(block));
    try expectBridgeOwnsItsTlsConfig(bridge, server_key.nodeId(), peer_key.nodeId());
}

test "an allocator that refuses the sink leaves every byte pending for the next pass" {
    // A stream is the one thing in this file a test can drive without a
    // peer: the core hands out a receive half, and a STREAM frame is all it
    // takes to fill it.
    const message = "the relay frame this pass must not lose";
    var core = quic.stream.Stream.init(t.allocator, 0);
    defer core.deinit();
    try core.recv.handleStreamFrame(0, message, false);
    var stream: stream_mod.Stream = .{ .entry = &core };

    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);

    // The sink's first allocation is the refusal: the run the peer sent is
    // already buffered and untouched, because the room is taken before the
    // read that would hand it over.
    var refusing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, stream.drain(refusing.allocator(), &sink));
    try t.expectEqual(@as(usize, 0), sink.items.len);

    // The retry yields the bytes the refusal interrupted at, once, in order.
    try t.expect(try stream.drain(t.allocator, &sink));
    try t.expectEqualStrings(message, sink.items);
    try t.expect(!try stream.drain(t.allocator, &sink));
}

/// The largest contiguous run the core hands back from a single read
/// (`FrameSorter.MAX_COALESCED`, `stream.zig:105`), which it does not export.
///
/// Two whole runs of this size are what give a drain two allocating
/// boundaries rather than one: the frame behind a full run cannot coalesce
/// onto it (`stream.zig:256`), so the two stand as separate runs and the sink
/// is asked for room twice. One run's worth is not enough on its own, because
/// `ArrayList` over-allocates by half and a second run half the size of the
/// first fits in what the first ask already left.
const run_ceiling = 64 * 1024;

/// A stream carrying `head` and `tail` as two separate runs, built in place
/// because the caller holds a borrow of it for the whole pass.
fn queueTwoRuns(core: *quic.stream.Stream, head: []const u8, tail: []const u8) !void {
    errdefer core.deinit();
    core.* = quic.stream.Stream.init(t.allocator, 0);
    try core.recv.handleStreamFrame(0, head, false);
    try core.recv.handleStreamFrame(head.len, tail, false);
}

/// What a completed drain has to leave in the sink: the peer's two runs, in
/// order, once each.
fn expectWholePayload(sink: *const std.ArrayList(u8), head: []const u8, tail: []const u8) !void {
    try t.expectEqual(head.len + tail.len, sink.items.len);
    try t.expectEqualSlices(u8, head, sink.items[0..head.len]);
    try t.expectEqualSlices(u8, tail, sink.items[head.len..]);
}

/// What a refusal has to leave: a prefix of the peer's bytes and nothing
/// else, so the retry carries the rest of them and none of them twice. A drain
/// that had consumed a run before the reserve refused would leave a gap here
/// instead, and one that had taken the run twice would leave a repeat.
fn expectPayloadPrefix(sink: *const std.ArrayList(u8), head: []const u8, tail: []const u8) !void {
    try t.expect(sink.items.len <= head.len + tail.len);
    const head_part = @min(sink.items.len, head.len);
    try t.expectEqualSlices(u8, head[0..head_part], sink.items[0..head_part]);
    if (sink.items.len > head.len) {
        const tail_part = sink.items.len - head.len;
        try t.expectEqualSlices(u8, tail[0..tail_part], sink.items[head.len..]);
    }
}

/// Refuse every allocating boundary a drain of two queued runs makes, one at a
/// time, from the first to the run nothing is refused on.
///
/// `t.checkAllAllocationFailures` counts `alloc` and not `resize`, and this
/// path makes both: `ArrayList.ensureTotalCapacity` asks the allocator to grow
/// the sink in place and allocates only where it will not
/// (`std/array_list.zig`), so a sweep over the allocation counter alone would
/// cover whichever half the allocator happened to take and would report a
/// pass over boundaries it never reached. This walks the two counters
/// together.
///
/// A refused resize is not a refusal at all: the same function falls back to a
/// fresh allocation, which succeeds, and the drain completes. Those passes
/// are kept because a relocation has to deliver exactly the bytes a growth in
/// place would, and because they are the passes that exercise the free-and-
/// copy path rather than the in-place one.
fn sweepStreamDrain(head: []const u8, tail: []const u8) !void {
    // What a full drain asks for, counted rather than guessed.
    var counting = t.FailingAllocator.init(t.allocator, .{});
    var count_core: quic.stream.Stream = undefined;
    try queueTwoRuns(&count_core, head, tail);
    defer count_core.deinit();
    var count_sink: std.ArrayList(u8) = .empty;
    defer count_sink.deinit(t.allocator);
    var counted: stream_mod.Stream = .{ .entry = &count_core };
    try t.expect(try counted.drain(counting.allocator(), &count_sink));
    try expectWholePayload(&count_sink, head, tail);
    const allocs = counting.alloc_index;
    const resizes = counting.resize_index;
    // Every pass below refuses one boundary; a drain that asked for nothing
    // would pass all of them without having tried anything.
    try t.expect(allocs + resizes > 0);

    var boundary: usize = 0;
    while (boundary < allocs + resizes) : (boundary += 1) {
        const config: t.FailingAllocator.Config = if (boundary < allocs)
            .{ .fail_index = boundary }
        else
            .{ .resize_fail_index = boundary - allocs };
        var refusing = t.FailingAllocator.init(t.allocator, config);

        var core: quic.stream.Stream = undefined;
        try queueTwoRuns(&core, head, tail);
        defer core.deinit();
        var sink: std.ArrayList(u8) = .empty;
        defer sink.deinit(t.allocator);
        var stream: stream_mod.Stream = .{ .entry = &core };

        var refused = false;
        if (stream.drain(refusing.allocator(), &sink)) |moved| {
            try t.expect(moved);
            try expectWholePayload(&sink, head, tail);
        } else |err| {
            try t.expectEqual(error.OutOfMemory, err);
            // This pass's own allocator refused, and it refused on the
            // boundary rather than somewhere in the setup above it.
            try t.expect(refusing.has_induced_failure);
            refused = true;
            try expectPayloadPrefix(&sink, head, tail);
        }
        // Cumulative bytes, in the one direction a refusal can move them:
        // every byte *this pass* was handed went back with it. A run the peer
        // will never retransmit — because it was received — is not sitting in
        // a chunk this pass dropped on the floor.
        try t.expect(refusing.freed_bytes >= sink.items.len);
        // And whatever the refusal did not take is still queued, in order: the
        // retry carries the rest of it and the drain after that says there is
        // nothing left.
        if (refused) {
            try t.expect(try stream.drain(t.allocator, &sink));
            try expectWholePayload(&sink, head, tail);
        }
        try t.expect(!try stream.drain(t.allocator, &sink));
    }
}

test "every allocation a drain of two queued runs makes can be refused on its own" {
    // Two whole runs of peer bytes in two fills no other pair of runs in this
    // file shares, so a sink holding either of them twice, or the wrong one
    // first, cannot pass for a sink holding both once.
    const head = try t.allocator.alloc(u8, run_ceiling);
    defer t.allocator.free(head);
    @memset(head, 0xa5);
    const tail = try t.allocator.alloc(u8, run_ceiling);
    defer t.allocator.free(tail);
    @memset(tail, 0x5a);

    try sweepStreamDrain(head, tail);
}

test "no egress room leaves the flight unsent, and the retry after it emits the flight" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(19);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 20, start, null, null);
    defer client.deinit();

    // The client's first Initial, accepted. The connection therefore holds a
    // whole flight that nothing has sent yet.
    var scratch: [2 * max_datagram]u8 = undefined;
    const len = try client.conn.sendAt(&client.buffer, start, client.random());
    const ingress = try bridge.recv(&map, .{
        .bytes = client.buffer[0..len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, client.random());
    const conn = switch (ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var no_slot: [0]conn_mod.Egress = undefined;
    var too_short: [conn_mod.min_datagram - 1]u8 = undefined;

    // Both refusals come before the core is asked for anything.
    try t.expectError(error.NoRoom, conn.drain(no_slot[0..], out[0..], start, client.random()));
    try t.expectError(error.NoRoom, conn.drain(egress[0..], too_short[0..], start, client.random()));

    // And the flight is still there: the datagram both refusals declined to
    // produce is the one this call gets.
    const sends = try conn.drain(egress[0..], out[0..], start, client.random());
    try t.expect(sends.len > 0);
    try t.expect(sends[0].send.contents.len > 0);
}

test "an egress array that fills up is a short answer, and asking again finishes the flight" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(21);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 22, start, null, null);
    defer client.deinit();

    var scratch: [2 * max_datagram]u8 = undefined;
    const len = try client.conn.sendAt(&client.buffer, start, client.random());
    const ingress = try bridge.recv(&map, .{
        .bytes = client.buffer[0..len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, client.random());
    const conn = switch (ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    // One slot at a time, as a caller with a small array would. Every call
    // answers with what it could carry, the first is not empty because there
    // is a flight waiting, and the calls end rather than repeating a
    // refusal: nothing the core produced was dropped on the way.
    var one: [1]conn_mod.Egress = undefined;
    var out: [max_datagram]u8 = undefined;
    var passes: usize = 0;
    while (passes < max_rounds) : (passes += 1) {
        const sends = try conn.drain(one[0..], out[0..], start, client.random());
        if (sends.len == 0) break;
        try t.expectEqual(one.len, sends.len);
        try t.expect(sends[0].send.contents.len > 0);
    }
    try t.expect(passes < max_rounds);
    try t.expectEqual(
        @as(usize, 0),
        (try conn.drain(one[0..], out[0..], start, client.random())).len,
    );
}

/// An `std.Io` that is `std.Io.failing` in every way but one: its entropy
/// source answers the caller's own cancellation instead of refusing.
///
/// The vtable is a file-scope constant rather than a copy made per call: a
/// `std.Io` holds a pointer to its vtable, so returning one built on the stack
/// hands the caller a pointer to a frame that has already returned. Debug
/// happened to keep that address readable; ReleaseSafe did not.
const cancelled_vtable: std.Io.VTable = blk: {
    var vtable = std.Io.failing.vtable.*;
    vtable.randomSecure = struct {
        fn draw(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.Canceled;
        }
    }.draw;
    break :blk vtable;
};

fn cancelledIo() std.Io {
    return .{ .userdata = null, .vtable = &cancelled_vtable };
}

test "an entropy draw that was cancelled is not reported as a broken entropy source" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var engine = Prng.init(23);

    // `std.Io.failing` is the std-supplied `std.Io` with no entropy at all,
    // which is the other of the two answers.
    try t.expectError(
        error.EntropyUnavailable,
        Bridge.create(t.allocator, std.Io.failing, .{
            .secret = server_secret,
            .alpns = &.{alpn},
        }, engine.random()),
    );
    try t.expectError(
        error.Canceled,
        Bridge.create(t.allocator, cancelledIo(), .{
            .secret = server_secret,
            .alpns = &.{alpn},
        }, engine.random()),
    );

    // A supplied key is never drawn, so the same two `std.Io`s build a bridge
    // without either refusal.
    const supplied: [retry.key_length]u8 = @splat(0x55);
    const bridge = try Bridge.create(t.allocator, cancelledIo(), .{
        .secret = server_secret,
        .alpns = &.{alpn},
        .retry_token_key = supplied,
        .static_reset_key = supplied,
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqualSlices(u8, &supplied, &bridge.manager.retry_token_key);
}

test "a peer pin is enforced whatever the caller said about certificates" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var engine = Prng.init(25);

    // The pin, with the certificate requirement explicitly cleared. The core
    // reads the pin out of the block that requirement decides on, so this is
    // the configuration in which an unenforced pin was possible.
    const pinned = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .require_peer_certificate = false,
        .alpns = &.{alpn},
    }, engine.random());
    defer pinned.destroy();
    const tls = pinned.tlsConfig();
    try t.expect(tls.client_auth != null);
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        tls.client_auth.?.expect_node_id.?,
    );
    try t.expectEqual(quic.tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // Naming no peer and asking for no certificate is the one configuration
    // that accepts an anonymous peer, and it still asks for one by default.
    const anonymous = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .require_peer_certificate = false,
        .alpns = &.{alpn},
    }, engine.random());
    defer anonymous.destroy();
    try t.expectEqual(@as(?*const quic.tls13.ClientAuth, null), anonymous.tlsConfig().client_auth);

    const defaulted = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, engine.random());
    defer defaulted.destroy();
    const default_tls = defaulted.tlsConfig();
    try t.expect(default_tls.client_auth != null);
    try t.expectEqual(quic.tls13.ClientAuth.Mode.required, default_tls.client_auth.?.mode);
    try t.expectEqual(@as(?[32]u8, null), default_tls.client_auth.?.expect_node_id);
}

test "one egress slot at a time sends as much as the whole array sends" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // Two bridges and two clients over one identity and one seed, so both
    // sides hold the same flight and either drain is free to produce it. One
    // is drained into the whole array, the other one slot at a time; the bytes
    // that come out have to be the same, or a caller with a small array loses
    // what a caller with a big one sends — which is the whole cost of a
    // commit boundary that is checked one datagram too late.
    var wide_engine = Prng.init(31);
    const wide = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, wide_engine.random());
    defer wide.destroy();
    var narrow_engine = Prng.init(31);
    const narrow = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
    }, narrow_engine.random());
    defer narrow.destroy();
    var map: addr_map.MappedAddrs = .init();
    defer map.deinit(t.allocator);
    // A second mapping table, so the address the first accept allocated is not
    // still in the one the second accept reads: both sides then hold the same
    // state and any difference in the bytes is the drain's.
    var narrow_map: addr_map.MappedAddrs = .init();
    defer narrow_map.deinit(t.allocator);
    var scratch: [2 * max_datagram]u8 = undefined;

    var wide_client: Client = undefined;
    try wide_client.init(client_secret, server_secret.nodeId(), &.{alpn}, 32, start, null, null);
    defer wide_client.deinit();
    const wide_len = try wide_client.conn.sendAt(&wide_client.buffer, start, wide_client.random());
    const wide_ingress = try wide.recv(&map, .{
        .bytes = wide_client.buffer[0..wide_len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, wide_client.random());
    const wide_conn = switch (wide_ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var narrow_client: Client = undefined;
    try narrow_client.init(client_secret, server_secret.nodeId(), &.{alpn}, 32, start, null, null);
    defer narrow_client.deinit();
    const narrow_len = try narrow_client.conn.sendAt(&narrow_client.buffer, start, narrow_client.random());
    const narrow_ingress = try narrow.recv(&narrow_map, .{
        .bytes = narrow_client.buffer[0..narrow_len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, narrow_client.random());
    const narrow_conn = switch (narrow_ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var wide_bytes: std.ArrayList(u8) = .empty;
    defer wide_bytes.deinit(t.allocator);
    for (try wide_conn.drain(egress[0..], out[0..], start, wide_client.random())) |send| {
        try wide_bytes.appendSlice(t.allocator, send.send.contents);
    }

    var one: [1]conn_mod.Egress = undefined;
    var narrow_out: [max_datagram]u8 = undefined;
    var narrow_bytes: std.ArrayList(u8) = .empty;
    defer narrow_bytes.deinit(t.allocator);
    var passes: usize = 0;
    while (passes < max_rounds) : (passes += 1) {
        const sends = try narrow_conn.drain(one[0..], narrow_out[0..], start, narrow_client.random());
        if (sends.len == 0) break;
        for (sends) |send| try narrow_bytes.appendSlice(t.allocator, send.send.contents);
    }

    // The consumer-visible claim is that a caller with a one-slot array loses
    // nothing, so the totals must match. The bytes of two separately built
    // connections are not the same bytes — connection ids and the transcript
    // that covers them differ — and nothing in the core's contract says they
    // should be, so asserting that would assert a property this test's own
    // premise cannot deliver.
    try t.expect(wide_bytes.items.len > 0);
    try t.expectEqual(wide_bytes.items.len, narrow_bytes.items.len);
    try t.expect(passes > 0);
}
// Retry admission.

/// One flight from the client, held so a test can hand the same bytes to the
/// bridge twice — which is the only way to ask whether a second copy of an
/// Initial costs anything at all.
const Flight = struct {
    bytes: [max_datagram]u8 = undefined,
    length: usize = 0,

    fn take(client: *Client, at: conn_mod.Instant) !Flight {
        const len = try client.conn.sendAt(&client.buffer, at, client.random());
        if (len == 0) return error.TestUnexpectedResult;
        var held: Flight = .{ .length = len };
        @memcpy(held.bytes[0..len], client.buffer[0..len]);
        return held;
    }

    fn slice(self: *const Flight) []const u8 {
        return self.bytes[0..self.length];
    }
};

/// Offer one held flight to `bridge`, from the client's address and marked
/// ECT(1) so that the answer's codepoint can be read back.
///
/// `at` is the instant of this datagram and not always `start`: the same
/// bytes offered twice are two arrivals, and one offered after the idle
/// timeout is asked about at the instant it arrived.
fn offer(
    bridge: *Bridge,
    map: *const addr_map.MappedAddrs,
    flight: Flight,
    scratch: []u8,
    at: conn_mod.Instant,
    random: std.Random,
) !Ingress {
    return bridge.recv(map, .{
        .bytes = flight.slice(),
        .from = client_addr,
        .local = server_addr,
        .ecn = .ect1,
    }, scratch, at, random);
}

test "an Initial with no token is answered with a Retry, and its echo is answered once" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(41);
    // `require_retry` is the whole of pre-accept Retry in ozai. Without it the
    // core accepts the first Initial and the token below never exists, which is
    // the state `src/` was in before `Config` grew the field.
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
        .retry_token_key = @splat(0x5a),
        .require_retry = true,
    }, engine.random());
    defer bridge.destroy();
    try t.expect(bridge.manager.require_retry);

    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 42, start, null, null);
    defer client.deinit();
    var scratch: [2 * max_datagram]u8 = undefined;
    var peer = Prng.init(43);

    // The first flight asks for nothing and is answered with a Retry.
    const first = try Flight.take(&client, start);
    try t.expect(retry.initialHeader(first.slice()).?.token == null);
    const retry_packet = switch ((try offer(bridge, &map, first, scratch[0..], start, peer.random())).outcome) {
        .reply => |bytes| bytes,
        else => return error.TestUnexpectedResult,
    };
    // **The reply carries the request's codepoint.** A Retry is usually the
    // answer to a datagram the peer marked ECT, and a stateless reply that
    // dropped the codepoint would have its loss reported against a path the
    // peer never chose — with no caller to read a `batch.Report` about it.
    try t.expectEqual(@as(?batch.Ecn, .ect1), retry_packet.ecn);

    client.receive(retry_packet.contents, start);
    try t.expect(client.conn.retry_received);

    // The echo is a fresh Initial carrying the token, and it is accepted —
    // which is what records the token, so the next copy of these bytes is free
    // to recognise.
    const echo = try Flight.take(&client, start);
    const token = retry.initialHeader(echo.slice()).?.token orelse return error.TestUnexpectedResult;
    try t.expect(token.len > 0);
    const conn = switch ((try offer(bridge, &map, echo, scratch[0..], start, peer.random())).outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 1), bridge.manager.entries.items.len);
    try t.expectEqual(retry.Verdict.spent, bridge.checkRetryToken(token, client_addr, start));

    // **And the same bytes again is this connection's business, not the
    // gate's.** It is addressed to a connection this bridge owns, so it goes
    // to the core, which drops the duplicate packet number inside it (RFC
    // 9000 §13.1) rather than acting on the ClientHello twice. The gate stands
    // in front of *admission*, and this datagram is not being admitted to
    // anything.
    const again = switch ((try offer(bridge, &map, echo, scratch[0..], start, peer.random())).outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(conn.id(), again.id());
    try t.expectEqual(@as(usize, 1), bridge.manager.entries.items.len);
    // The gate learned nothing new from it: the record that answered is the
    // one it already held, and a datagram it does not admit writes none.
    try t.expectEqual(@as(usize, 1), bridge.retryTokensTracked());
    try t.expectEqual(retry.Verdict.spent, bridge.checkRetryToken(token, client_addr, start));

    // **Which is the datagram the filter is for: the same one once nothing of
    // this bridge's owns its destination id any more.** Reaped at an instant
    // past the idle timeout and well inside the token's own age, so the
    // record answers `spent` and the drop below is this filter's rather than
    // the age's.
    const reap = start + 45 * std.time.ns_per_s;
    try t.expectEqual(Tick.finished, bridge.tick(again, reap, peer.random()));
    bridge.sweep();
    try t.expectEqual(@as(usize, 0), bridge.manager.connectionCount());
    switch ((try offer(bridge, &map, echo, scratch[0..], reap, peer.random())).outcome) {
        .dropped => {},
        else => return error.TestUnexpectedResult,
    }
    // No second connection, and no record written for the refusal: this is
    // the path that costs no AEAD open.
    try t.expectEqual(@as(usize, 0), bridge.manager.connectionCount());
    try t.expectEqual(@as(usize, 1), bridge.retryTokensTracked());
}

test "a ClientHello split across Initial packets after a Retry reaches the connection the first one opened" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(81);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
        .retry_token_key = @splat(0x5a),
        .require_retry = true,
    }, engine.random());
    defer bridge.destroy();

    // **A ClientHello too long for one Initial packet.** Every datagram of
    // this client's first flight then carries the one Retry token, because the
    // packer holds it until the ClientHello is out (`packet_packer.zig:656`)
    // — so the token is presented again by the second packet, in bytes this
    // node has never seen, for a connection this node has already opened.
    // That is not a replay: RFC 9000 §17.2.5 has the client present the token
    // in every Initial it sends until its ClientHello is complete, and the
    // second Retry it forbids is the answer to a *second Initial*, not to a
    // second packet of the first. The padding names are what make it long;
    // see `pad_alpn`.
    var offers: [client_alpns_max][]const u8 = undefined;
    offers[0] = alpn;
    @memset(offers[1..], pad_alpn);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &offers, 82, start, null, null);
    defer client.deinit();
    var scratch: [2 * max_datagram]u8 = undefined;
    var peer = Prng.init(83);

    // The first flight asks for nothing and is answered with a Retry, which
    // is the same first step as the test above and the reason that one's
    // echo fit in one packet.
    const first = try Flight.take(&client, start);
    try t.expect(retry.initialHeader(first.slice()).?.token == null);
    const retry_packet = switch ((try offer(bridge, &map, first, scratch[0..], start, peer.random())).outcome) {
        .reply => |bytes| bytes,
        else => return error.TestUnexpectedResult,
    };
    client.receive(retry_packet.contents, start);
    try t.expect(client.conn.retry_received);

    // The first packet of the echo opens the connection, and the token in it
    // is what this bridge records.
    const head = try Flight.take(&client, start);
    const token = retry.initialHeader(head.slice()).?.token orelse return error.TestUnexpectedResult;
    const conn = switch ((try offer(bridge, &map, head, scratch[0..], start, peer.random())).outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 1), bridge.manager.entries.items.len);

    // **The rest of the same ClientHello.** Distinct bytes carrying the same
    // token — so not the retransmission of the packet above, and not a second
    // use of the token by any new connection, because none is being opened:
    // it belongs to the connection the packet above opened, and the core
    // routes it there by destination id before it looks at any token
    // (`connection_manager.zig:683`).
    const tail = try Flight.take(&client, start);
    try t.expect(!std.mem.eql(u8, head.slice(), tail.slice()));
    try t.expectEqualSlices(u8, token, retry.initialHeader(tail.slice()).?.token.?);
    // **And the same destination id**, which is the whole of what makes this
    // packet that connection's and not a new attempt: the rest of one
    // ClientHello is addressed to the connection the first of its packets
    // opened, and RFC 9000 §17.2.5 puts the Retry's source id there for
    // exactly that reason.
    try t.expectEqualSlices(
        u8,
        retry.initialHeader(head.slice()).?.dcid,
        retry.initialHeader(tail.slice()).?.dcid,
    );
    const continued = switch ((try offer(bridge, &map, tail, scratch[0..], start, peer.random())).outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(conn.id(), continued.id());
    try t.expectEqual(@as(usize, 1), bridge.manager.entries.items.len);
    // One echo, one record: the second packet learned nothing from the gate,
    // because there was nothing left for it to learn.
    try t.expectEqual(@as(usize, 1), bridge.retryTokensTracked());

    // **And the handshake it was carrying on completes.** This is the whole of
    // the claim and a counter is not it: a server holding a connection whose
    // ClientHello is still in pieces is holding half a handshake.
    try exchange(&client, bridge, &map, start);
    const settled = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(settled.established());
    try t.expectEqual(conn.id(), settled.id());
    try t.expectEqualStrings(alpn, settled.entry.conn.negotiatedAlpn());

    // **And application bytes cross it**, which is what a session is: a
    // unidirectional stream the peer never opens a send half for, written
    // after the handshake and read at the far end.
    const message = "bytes after a Retry split the ClientHello";
    var uni = try stream_mod.openUni(client.conn);
    try t.expectEqual(message.len, try uni.write(message));
    uni.close();
    try exchange(&client, bridge, &map, start);
    var incoming = settled.acceptUni(0) orelse return error.TestUnexpectedResult;
    try t.expectEqual(uni.id(), incoming.id());
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    try t.expect(try incoming.drain(t.allocator, &sink));
    try t.expectEqualStrings(message, sink.items);
    try t.expect(incoming.finished());
}

test "a token this bridge did not seal is validated, and one it did is not asked twice" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(44);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpns = &.{alpn},
        .retry_token_key = @splat(0x5a),
    }, engine.random());
    defer bridge.destroy();

    const token = try bridge.issueRetryToken(
        "original-dcid",
        "retry-scid-01",
        client_addr,
        start,
        engine.random(),
    );
    // Issued, not yet echoed: a client that has not had its token back has not
    // been answered, so this is not spendable.
    try t.expect(!bridge.checkRetryTokenIsSpent(token.slice(), client_addr, start));
    try t.expectEqual(
        retry.Verdict.recorded,
        bridge.checkRetryToken(token.slice(), client_addr, start),
    );
    try t.expectEqual(
        retry.Verdict.spent,
        bridge.checkRetryToken(token.slice(), client_addr, start),
    );
    // The same bytes from another host are a different token: the seal binds
    // the address, and skipping the seal means comparing it by hand.
    try t.expect(!bridge.checkRetryTokenIsSpent(token.slice(), server_addr, start));
}

// Unidirectional streams.

test "a unidirectional stream is bounded by the credit the peer granted" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(45);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
        // Both bounds here are the *peer's* to grant, and this bridge is the
        // peer of the client below: the core installs the stream count and the
        // per-stream window a connection may use from the parameters the peer
        // advertised (`connection.zig:3370-3378`), so what bounds the client's
        // opens and writes is what this server states. Setting them on the
        // client fixture instead bounds what the *server* may open and leaves
        // the core's own default of 100 in force for the client — which is
        // why the refusal this test ends on could not fire.
        .initial_max_streams_uni = 1,
        .initial_max_stream_data_uni = 8,
    }, engine.random());
    defer bridge.destroy();

    // One unidirectional stream, and eight bytes on it: both bounds small
    // enough to be driven, and both of them granted above rather than asked
    // for here.
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 46, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    var uni = try stream_mod.openUni(client.conn);
    const first_id = uni.id();
    try t.expectEqual(@as(u64, 8), uni.credit());
    try t.expectEqual(@as(usize, 5), try uni.write("hello"));
    // **A write past the credit is refused rather than queued** for a window
    // the peer may never open. Three bytes are left and four were asked for.
    try t.expectError(error.NoSendCredit, uni.write("1234"));
    try t.expectEqual(@as(usize, 5), uni.buffered());
    // No FIN has reached the peer yet, so its one-stream grant is still spent.
    // Closing and exchanging first would let its MAX_STREAMS replenish it.
    try t.expectError(error.NoStreamRoom, stream_mod.openUni(client.conn));
    uni.close();
    try exchange(&client, bridge, &map, start);

    // The other end sees the receive half it actually is, on the id the sender
    // numbered. `var`, not `const`, because `drain` takes the handle mutably:
    // what it moves is the core receive stream's read cursor, reached through
    // the pointer the handle holds, and that cursor is what a second `drain`
    // finds already advanced.
    const server_conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    var incoming = server_conn.acceptUni(0) orelse return error.TestUnexpectedResult;
    try t.expectEqual(first_id, incoming.id());
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    try t.expect(try incoming.drain(t.allocator, &sink));
    try t.expectEqualStrings("hello", sink.items);
    try t.expect(incoming.finished());
    // Nothing after it: `acceptUni` answers the smallest id above the one the
    // caller took, and the peer opened one.
    try t.expect(server_conn.acceptUni(incoming.id()) == null);

    // The FIN earned a fresh grant on the wire, not a lifetime cap of one.
    // The refused open consumed no id, and the next stream has its own window.
    var next = try stream_mod.openUni(client.conn);
    const next_id = next.id();
    try t.expectEqual(first_id + 4, next_id);
    try t.expectEqual(@as(u64, 8), next.credit());
    try t.expectEqual(@as(usize, 8), try next.write("12345678"));
    try t.expectError(error.NoSendCredit, next.write("9"));
    try t.expectError(error.NoStreamRoom, stream_mod.openUni(client.conn));
    next.close();
    try exchange(&client, bridge, &map, start);

    var following = server_conn.acceptUni(first_id) orelse return error.TestUnexpectedResult;
    try t.expectEqual(next_id, following.id());
    sink.clearRetainingCapacity();
    try t.expect(try following.drain(t.allocator, &sink));
    try t.expectEqualStrings("12345678", sink.items);
    try t.expect(following.finished());
    try t.expect(!try following.drain(t.allocator, &sink));
    try t.expect(server_conn.acceptUni(next_id) == null);
}

test "a datagram crosses the connection, and one over the bound is refused" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(47);
    // **Both ends advertise**, which is the only way the extension comes up
    // (`connection.zig:3382`): one advertisement is not "unlimited", it is "no
    // DATAGRAM at all".
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
        .max_datagram_frame_size = 65_536,
    }, engine.random());
    defer bridge.destroy();
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 48, start, 65_536, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const server_conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(server_conn.established());
    try t.expect(client.conn.isEstablished());
    try t.expect(datagram_mod.enabled(client.conn));
    try t.expect(server_conn.datagramsEnabled());

    // Flush handshake/control ACKs through the real wire before queuing a
    // ceiling-sized frame, which needs a packet's otherwise unused budget.
    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    _ = try deliver(server_conn, &client, egress[0..], out[0..], start);
    try exchange(&client, bridge, &map, start);

    const limit = server_conn.datagramMaxPayload() orelse return error.TestUnexpectedResult;
    try t.expect(limit > 0);
    try t.expectEqual(@as(usize, 0), server_conn.datagramQueued());

    // The ceiling includes the peer's frame bound, path packet budget, short
    // header and AEAD tag. The extra byte needs storage of its own even when
    // that ceiling fills the format's largest payload buffer.
    try t.expect(limit <= datagram_mod.max_payload);
    var payload: [datagram_mod.max_payload]u8 = undefined;
    for (payload[0..limit], 0..) |*byte, index| byte.* = @truncate(index);
    try server_conn.sendDatagram(payload[0..limit], start);
    try t.expectEqual(@as(usize, 1), server_conn.datagramQueued());
    // One byte over what the peer allows is refused before the core is asked,
    // so nothing was queued for it.
    const oversized: [datagram_mod.max_payload + 1]u8 = @splat(0);
    try t.expectError(
        error.DatagramTooLarge,
        server_conn.sendDatagram(oversized[0 .. limit + 1], start),
    );
    try t.expectEqual(@as(usize, 1), server_conn.datagramQueued());

    // exchange is client-driven. Drain server egress explicitly; Conn.drain
    // can flush a preceding ACK packet and then pack the queued maximum.
    _ = try deliver(server_conn, &client, egress[0..], out[0..], start);

    try exchange(&client, bridge, &map, start);

    // And it arrives at the far end, copied into the caller's buffer and owned
    // by nothing else: a second read finds an empty queue, not the same
    // datagram.
    var buffer: [datagram_mod.max_payload]u8 = undefined;
    try t.expectEqualStrings(
        payload[0..limit],
        datagram_mod.recv(client.conn, &buffer, start) orelse
            return error.TestUnexpectedResult,
    );
    try t.expect(datagram_mod.recv(client.conn, &buffer, start) == null);

    // A buffer too short leaves the datagram where it was and answers null,
    // which is the second thing null means.
    try server_conn.sendDatagram("short", start);
    _ = try deliver(server_conn, &client, egress[0..], out[0..], start);
    try exchange(&client, bridge, &map, start);
    var narrow: [2]u8 = undefined;
    try t.expect(datagram_mod.recv(client.conn, &narrow, start) == null);
    try t.expectEqualStrings(
        "short",
        datagram_mod.recv(client.conn, &buffer, start) orelse
            return error.TestUnexpectedResult,
    );
    try t.expect(datagram_mod.recv(client.conn, &buffer, start) == null);
}

test "a connection with no DATAGRAM on it says so rather than carrying one" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var engine = Prng.init(49);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{alpn},
    }, engine.random());
    defer bridge.destroy();
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), &.{alpn}, 50, start, null, null);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    // Null is not "unlimited": with neither end advertising, the core never
    // turns the extension on and every send is refused by name.
    const server_conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(!server_conn.datagramsEnabled());
    try t.expect(server_conn.datagramMaxPayload() == null);
    try t.expectError(error.DatagramsNotEnabled, server_conn.sendDatagram("hello", start));
    try t.expectEqual(@as(usize, 0), server_conn.datagramQueued());
}

test "an ALPN list longer than the bound is refused by name, and an empty one too" {
    var secret = try base_key.SecretKey.fromSeed(server_seed);
    defer secret.deinit();
    var engine = Prng.init(51);

    // Invalid offers must not allocate or ask the caller for secure entropy.
    var backing: [@sizeOf(Bridge)]u8 align(@alignOf(Bridge)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    var refusing = t.FailingAllocator.init(fixed.allocator(), .{ .fail_index = 0 });

    const too_many = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h", "i" };
    try t.expect(config_mod.max_alpns < too_many.len);
    try t.expectError(error.TooManyAlpns, Bridge.create(refusing.allocator(), std.Io.failing, .{
        .secret = secret,
        .alpns = &too_many,
    }, engine.random()));
    try t.expect(!refusing.has_induced_failure);
    try t.expectEqual(@as(usize, 0), fixed.end_index);
    // An empty offer is a node that speaks nothing, and a handshake that
    // negotiates nothing is not one this bridge can serve.
    try t.expectError(error.NoAlpn, Bridge.create(refusing.allocator(), std.Io.failing, .{
        .secret = secret,
        .alpns = &.{},
    }, engine.random()));
    try t.expect(!refusing.has_induced_failure);
    try t.expectEqual(@as(usize, 0), fixed.end_index);

    try t.expectError(error.NoAlpn, Bridge.create(refusing.allocator(), std.Io.failing, .{
        .secret = secret,
        .alpns = &.{ alpn, "" },
    }, engine.random()));
    try t.expect(!refusing.has_induced_failure);
    try t.expectEqual(@as(usize, 0), fixed.end_index);

    const too_long: [config_mod.max_alpn_name_len + 1]u8 = @splat('n');
    try t.expectError(
        error.AlpnNameTooLong,
        Bridge.create(refusing.allocator(), std.Io.failing, .{
            .secret = secret,
            .alpns = &.{&too_long},
        }, engine.random()),
    );
    try t.expect(!refusing.has_induced_failure);
    try t.expectEqual(@as(usize, 0), fixed.end_index);

    // One entry and the exact name-length boundary remain usable offers.
    const at_name_bound: [config_mod.max_alpn_name_len]u8 = @splat('n');
    for ([_][]const u8{ alpn, &at_name_bound }) |name| {
        const single = try Bridge.create(t.allocator, t.io, .{
            .secret = secret,
            .alpns = &.{name},
        }, engine.random());
        defer single.destroy();
        try t.expectEqual(@as(usize, 1), single.tlsConfig().alpn.len);
        try t.expectEqualStrings(name, single.tlsConfig().alpn[0]);
    }

    // And at the bound itself the bridge exists and offers every one of them.
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = secret,
        .alpns = too_many[0..config_mod.max_alpns],
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqual(config_mod.max_alpns, bridge.tlsConfig().alpn.len);
    for (too_many[0..config_mod.max_alpns], bridge.tlsConfig().alpn) |want, got| {
        try t.expectEqualStrings(want, got);
    }
}

test "a withdrawn protocol leaves the offers, in order, and an unoffered one changes nothing" {
    var secret = try base_key.SecretKey.fromSeed(server_seed);
    defer secret.deinit();
    var engine = Prng.init(53);

    const offers = [_][]const u8{ "/ozai/blobs", "/ozai/gossip", "/ozai/relay" };
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = secret,
        .alpns = &offers,
    }, engine.random());
    defer bridge.destroy();

    // **What is asserted is the core's own slice, not this bridge's count.**
    // The count is bookkeeping; `tlsConfig().alpn` is the list the next
    // handshake is negotiated against, and a withdrawal that shortened only
    // the count would leave the protocol on the wire with every assertion
    // above it still true.
    try t.expectEqual(offers.len, bridge.tlsConfig().alpn.len);

    // The other view a withdrawal has to reach: this is the header a
    // connection accepted right now would be handed, and it is what a
    // connection already accepted still holds. The core copies the slice, not
    // the names (`connection_manager.zig:450`), so whatever this length can
    // still address is what such a handshake negotiates against.
    const stale = bridge.alpn_list[0..offers.len];

    // The middle one goes, and the two survivors keep their order: the server
    // takes the first entry of this list the peer also named
    // (`tls13.zig:3075`), so compaction that swapped them would silently
    // change which protocol wins a handshake both ends offer.
    try t.expect(bridge.withdrawAlpn("/ozai/gossip"));
    const left = bridge.tlsConfig().alpn;
    try t.expectEqual(@as(usize, 2), left.len);
    try t.expectEqualStrings("/ozai/blobs", left[0]);
    try t.expectEqualStrings("/ozai/relay", left[1]);

    // So nothing in it names the protocol that went, and the slot the
    // compaction emptied holds a name no peer can select: a handshake reading
    // through this header now chooses between the two survivors, or is refused
    // if it named neither.
    for (stale) |entry| try t.expect(!std.mem.eql(u8, entry, "/ozai/gossip"));
    try t.expectEqualStrings(retired_alpn, stale[2]);

    // A protocol this bridge never offered is not an error and moves nothing,
    // including the core's slice: withdrawing one that is already gone must
    // not rebuild the list out of a compacted count.
    try t.expect(!bridge.withdrawAlpn("/ozai/none"));
    try t.expect(!bridge.withdrawAlpn("/ozai/relay/1"));
    try t.expectEqual(@as(usize, 2), bridge.tlsConfig().alpn.len);

    // And the last ones, because the empty list is a bridge that has withdrawn
    // everything rather than one that has stopped answering: the core is
    // handed an empty list, and `destroy` still frees what it owns. Every slot
    // a handshake accepted before that last withdrawal holds the name that
    // cannot be selected, so such a handshake is refused rather than settled on
    // something this node has withdrawn — which is the length-bounded reason
    // `retired_alpn` is longer than a selection.
    try t.expect(bridge.withdrawAlpn("/ozai/blobs"));
    try t.expect(bridge.withdrawAlpn("/ozai/relay"));
    try t.expectEqual(@as(usize, 0), bridge.tlsConfig().alpn.len);
    for (stale) |entry| try t.expectEqualStrings(retired_alpn, entry);
    try t.expect(!bridge.withdrawAlpn("/ozai/blobs"));
}

/// Prove that the first produced datagram cannot contain the complete hello.
///
/// TLS waits for the length declared in the ClientHello header before selecting
/// ALPN. Read that header from the actual queued CRYPTO bytes, not a calculated
/// fixture size. QUIC does not compress them, so they cannot fit in a shorter
/// datagram. An ACK-only server flight does not prove this selection boundary.
fn expectHelloOutlivesItsFirstPacket(
    client: *const Client,
    first: *const Flight,
) !void {
    const hello = client.conn.crypto_streams.initial.send_buffer.items;
    try t.expect(hello.len > 4);
    // RFC 8446 §4: HandshakeType(1) || length(3) || body.
    try t.expectEqual(@as(u8, 1), hello[0]); // client_hello
    const body: usize = std.mem.readInt(u24, hello[1..4], .big);
    try t.expectEqual(hello.len, body + 4);
    try t.expect(hello.len > first.slice().len);
}

test "a handshake accepted before a withdrawal cannot still choose the withdrawn protocol" {
    var server_secret = try base_key.SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try base_key.SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // Three offers, and the first is the one that goes: the server takes the
    // first entry of its own list the peer also named (`tls13.zig:3075`), so a
    // handshake nothing had interrupted would have settled on this one.
    const gossip = "/ozai/gossip";
    const blobs = "/ozai/blobs";
    const relay = "/ozai/relay";

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var scratch: [2 * max_datagram]u8 = undefined;
    // The receive path's own copy of the datagram it was handed, borrowed
    // once here rather than spelled at every call below.
    const room = scratch[0..];
    var egress: [max_egress]conn_mod.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;

    // RFC 9001 encodes TLS no_application_protocol (120) as CRYPTO_ERROR 0x178.
    const refused_code = quic.frame.TransportError.cryptoError(120);

    var engine = Prng.init(61);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{ gossip, blobs, relay },
    }, engine.random());
    defer bridge.destroy();

    // A connection that chose before anything was withdrawn: one protocol and
    // a short hello, so it settles inside this first exchange. It is here
    // because the withdrawal is not meant to reach it, and the one way to show
    // that is to let it keep carrying bytes afterwards.
    var chosen: Client = undefined;
    try chosen.init(client_secret, server_secret.nodeId(), &.{gossip}, 63, start, null, null);
    defer chosen.deinit();
    const chosen_flight = try Flight.take(&chosen, start);
    const chosen_ingress = try offer(bridge, &map, chosen_flight, room, start, chosen.random());
    const selected = switch (chosen_ingress.outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    _ = try deliver(selected, &chosen, egress[0..], out[0..], start);
    try exchange(&chosen, bridge, &map, start);
    try t.expect(selected.established());
    try t.expectEqualStrings(gossip, selected.entry.conn.negotiatedAlpn());

    // **The window itself.** A ClientHello too long for one Initial packet, so
    // the server accepts the connection on the first and reads its protocol on
    // the rest. The padding names are what make it long; see `pad_alpn`. This
    // client's own order is the one that loses: it names `relay` before
    // `blobs`, so a selection that walked the client's list would settle on
    // the wrong protocol, and only this node's order settles on `blobs`.
    var offers: [client_alpns_max][]const u8 = undefined;
    offers[0] = gossip;
    offers[1] = relay;
    offers[2] = blobs;
    @memset(offers[3..], pad_alpn);
    var inflight: Client = undefined;
    try inflight.init(client_secret, server_secret.nodeId(), &offers, 62, start, null, null);
    defer inflight.deinit();

    const head = try Flight.take(&inflight, start);
    try expectHelloOutlivesItsFirstPacket(&inflight, &head);
    const head_ingress = try offer(bridge, &map, head, room, start, inflight.random());
    const opened = switch (head_ingress.outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };

    // The accepted connection holds only part of its hello. Its first packet
    // can earn an ACK without selecting ALPN, so no send-count oracle applies.
    try t.expect(bridge.withdrawAlpn(gossip));

    // The rest of the ClientHello, which is where the protocol is chosen.
    const tail = try Flight.take(&inflight, start);
    try t.expect(!std.mem.eql(u8, head.slice(), tail.slice()));
    const tail_ingress = try offer(bridge, &map, tail, room, start, inflight.random());
    const continued = switch (tail_ingress.outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(opened.id(), continued.id());
    _ = try deliver(continued, &inflight, egress[0..], out[0..], start);
    try exchange(&inflight, bridge, &map, start);

    // The frozen slice length still covers the original three slots. Selection
    // must use the surviving server preference order, not the client's order.
    try t.expect(continued.established());
    try t.expectEqualStrings(blobs, continued.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(blobs, inflight.conn.negotiatedAlpn());

    // **And the session it settled on carries application bytes**, which is
    // what a caller asked for: a unidirectional stream, the exact payload, and
    // the FIN that says there is no more of it.
    const message = "settled on the protocol that survived";
    var uni = try continued.openUni();
    try t.expectEqual(message.len, try uni.write(message));
    const stream_id = uni.id();
    uni.close();
    _ = try deliver(continued, &inflight, egress[0..], out[0..], start);
    try exchange(&inflight, bridge, &map, start);
    var arrival = stream_mod.acceptUni(inflight.conn, 0) orelse return error.TestUnexpectedResult;
    try t.expectEqual(stream_id, arrival.id());
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    try t.expect(try arrival.drain(t.allocator, &sink));
    try t.expectEqualStrings(message, sink.items);
    try t.expect(arrival.finished());

    // **And the choice already made is untouched.** The withdrawal rewrote the
    // slots a handshake accepted before it reads; this one read its protocol
    // long ago and copied the name out of them (`tls13.zig:3108`), so retiring
    // `gossip` cannot reach a session already on it. It still answers on that
    // protocol, with its own bytes.
    try t.expectEqualStrings(gossip, selected.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(gossip, chosen.conn.negotiatedAlpn());
    const carried = "still on the protocol it negotiated";
    var kept = try selected.openUni();
    try t.expectEqual(carried.len, try kept.write(carried));
    const carried_id = kept.id();
    kept.close();
    _ = try deliver(selected, &chosen, egress[0..], out[0..], start);
    try exchange(&chosen, bridge, &map, start);
    var carried_in = stream_mod.acceptUni(chosen.conn, 0) orelse return error.TestUnexpectedResult;
    try t.expectEqual(carried_id, carried_in.id());
    var carried_sink: std.ArrayList(u8) = .empty;
    defer carried_sink.deinit(t.allocator);
    try t.expect(try carried_in.drain(t.allocator, &carried_sink));
    try t.expectEqualStrings(carried, carried_sink.items);
    try t.expect(carried_in.finished());

    // **The same window, refused.** A second bridge, because a withdrawal is
    // one event and this one has to land in a window of its own: this
    // handshake names one protocol and no alternative at all, so what it can
    // settle on after the withdrawal is nothing.
    var refusal_engine = Prng.init(64);
    const refusals = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpns = &.{ gossip, blobs, relay },
    }, refusal_engine.random());
    defer refusals.destroy();

    var stale_offers: [client_alpns_max][]const u8 = undefined;
    stale_offers[0] = gossip;
    @memset(stale_offers[1..], pad_alpn);
    var stale: Client = undefined;
    try stale.init(client_secret, server_secret.nodeId(), &stale_offers, 65, start, null, null);
    defer stale.deinit();

    // Accepted on a partial ClientHello naming only what is about to be
    // withdrawn, exactly as the session above was.
    const stale_head = try Flight.take(&stale, start);
    try expectHelloOutlivesItsFirstPacket(&stale, &stale_head);
    const stale_ingress = try offer(refusals, &map, stale_head, room, start, stale.random());
    const stale_opened = switch (stale_ingress.outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expect(refusals.withdrawAlpn(gossip));

    const stale_tail = try Flight.take(&stale, start);
    const stale_tail_ingress = try offer(refusals, &map, stale_tail, room, start, stale.random());
    const stale_answered = switch (stale_tail_ingress.outcome) {
        .processed => |held| held,
        else => return error.TestUnexpectedResult,
    };
    try t.expectEqual(stale_opened.id(), stale_answered.id());
    _ = try deliver(stale_answered, &stale, egress[0..], out[0..], start);
    try exchange(&stale, refusals, &map, start);

    // Read the refusal from the peer's received transport close, not from the
    // server's local error or a server handle that its owner can reap.
    try t.expect(!stale.conn.isEstablished());
    const refusal = stale.conn.local_err orelse return error.TestUnexpectedResult;
    try t.expect(!refusal.is_app);
    try t.expectEqual(refused_code, refusal.code);

    // **And a handshake that starts after the withdrawal is refused the same
    // way**, so the retirement is not something a connection only has to be
    // caught inside of. One protocol, named, and nothing left to serve it
    // with: the same wire answer, from a hello that fitted in one packet and
    // never had a window at all.
    var later: Client = undefined;
    try later.init(client_secret, server_secret.nodeId(), &.{gossip}, 66, start, null, null);
    defer later.deinit();
    try exchange(&later, refusals, &map, start);
    try t.expect(!later.conn.isEstablished());
    const later_refusal = later.conn.local_err orelse return error.TestUnexpectedResult;
    try t.expect(!later_refusal.is_app);
    try t.expectEqual(refused_code, later_refusal.code);
}
