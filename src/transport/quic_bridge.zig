//! The seam between the vendored QUIC core and this project's transport.
//!
//! `docs/DECISIONS/0001-transport-substrate.md`, M8 step 5, says the vendored
//! core is "consumed by `ozai.transport`". Until this file existed nothing
//! under `src/` named it: the module was declared in `build.zig`, compiled by
//! `zig build quic-test`, and otherwise unreachable from the project. This is
//! that consumer.
//!
//! What the core is: `vendor/quic/src/`, sans-IO, patched so its clock and
//! its randomness are parameters and its peer certificate is a bare 44-byte
//! Ed25519 `SubjectPublicKeyInfo`. See `vendor/quic/VENDORED.md`. What it is
//! not: anything that owns a socket. It has no syscall seam left to own one
//! with.
//!
//! # The three things that reach the core
//!
//! The core takes `now: i64` and `random: std.Random` on every ingress,
//! every egress and every timer pass. This project threads `io: std.Io`
//! (`docs/DECISIONS/0002-async-substrate.md`) and keeps a clock and a
//! generator out of every struct below `ozai.transport`. Reconciling the two
//! is the whole design question of this file, and the answer is:
//
//! - **The instant is the caller's.** `Instant` is a parameter of `recv`,
//!   `drain` and `tick` — every call that moves the core forward — and
//!   nothing in this file ever reads a clock. `std.Io` can answer
//!   `Io.Clock.now(io, .monotonic)` and no function here asks it: a bridge
//!   that asked would be one refactor away from being undrivable, and
//!   `docs/DECISIONS/0002` names that property as the reason the runtime's
//!   `Io` is threaded rather than stored.
//! - **The generator is the caller's**, by value, on the same lines as
//!   `transport/addr_map.zig`'s `MappedAddrs.get`. `std.Random` is an
//!   interface over a pointer to an engine, so the caller keeps the engine
//!   next to every value it hands out; nothing here draws entropy.
//! - **`std.Io` reaches the core nowhere**, and that is a finding rather than
//!   an omission: the vendored tree's only surviving `std.Io` is
//!   `tls13.P256Cert.init` (`vendor/quic/src/quic/tls13.zig:4580`), the X.509
//!   certificate helper, which the ed25519 SPKI path never reaches. So `io`
//!   appears on `create` and nowhere else, and it is used for the one job
//!   left for it — the two transport secrets a caller did not supply.
//!
//! # What the core does not know about addresses
//!
//! Four things, all of them found by reading the vendored tree rather than
//! assumed, and all of them load-bearing for `base/ula.zig`:
//!
//! 1. **Nothing validates a synthetic address.** The core never asks whether
//!    a peer's address is routable, private, or even well formed. The only
//!    address-sensitive policy in the tree is `NetworkPath.canSend`
//!    (`connection.zig:127`), the server-side 3× anti-amplification limit,
//!    and the two comparisons `Address.eql` and `Address.sameIp`
//!    (`vendor/quic/src/address.zig`). An RFC 4193 ULA is therefore
//!    accepted as a peer address without complaint, which is the answer to
//!    the question `docs/PLAN.md`'s mapping raises, and the test
//!    "the core takes a synthetic address for a peer's address" is that
//!    answer demonstrated rather than asserted.
//!
//! 2. **One active path, not N.** `Connection` holds exactly two
//!    `NetworkPath`s and indexes one as active (`connection.zig:626`). A
//!    datagram from an address that is not the active path's peer address
//!    goes to `handleMigration` (`connection.zig:1542`), which makes the
//!    second address a *candidate*, challenges it, and promotes it. So the
//!    core models one path plus one migration in flight. `ula.Path.any_path`
//!    models the opposite: one address every candidate path is reached
//!    through, with each datagram duplicated onto each path. `addr_map`'s
//!    three subnets therefore name three addresses, and a connection handed
//!    all three is a connection the core will read as a migration. This is
//!    the largest gap between the two models and it is not fixable in this
//!    file.
//!
//! 3. **The core's path identity includes the port; `ula`'s does not.**
//!    `Address.eql` compares family, address, port and scope
//!    (`vendor/quic/src/address.zig`); `ula.classify` compares eight octets and
//!    ignores the port entirely. Every synthetic address carries
//!    `ula.mapped_port`, so the two agree today by construction — but a
//!    caller that reached the same /64 on a second port would be invisible
//!    to `classify` while the core would see a different path.
//!
//! 4. **`TlsConfig.expect_peer_node_id` is client-only.** It is read in
//!    `clientProcessCertificate` (`tls13.zig:1465`) and nowhere else, and a
//!    `ConnectionManager` only ever accepts server connections. The peer pin
//!    a server actually enforces is `ClientAuth.expect_node_id`. The
//!    translation below sets the one that bites and says so, rather than
//!    setting the field that looks like a pin and enforces nothing.
//!
//! # Why the send side is `transport/batch.zig` and not a second path
//!
//! The core's egress is `Connection.sendAt(out_buf, now, random)`: it writes
//! one datagram into a caller buffer and the caller sends it. `batch.zig`
//! already models what a socket is to be asked for — bytes, a segment size,
//! a codepoint, and what the socket refused. A core datagram fits that shape
//! exactly: it is a contiguous slice of a buffer. The one thing a QUIC burst
//! does that the batcher does not want is vary its datagram size inside a
//! run, so a run closes at the first datagram that differs from the one
//! before it and the rest go out as singles. That is the batcher's own
//! fallback (`batch.Send.isSegmented`, `batch.Runs`), not a new one, and it
//! is where a burst of equal-sized packets becomes a `UDP_SEGMENT` send.

const std = @import("std");
const quic = @import("quic");

// Named for the layer, not the file: `key`, `addr` and `ula` are this
// module's own vocabulary as declarations and a parameter may not shadow one.
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const batch = @import("batch.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;

const Manager = quic.connection_manager.ConnectionManager;
const Entry = quic.connection_manager.ConnEntry;
const quic_stream = quic.stream;
const tls13 = quic.tls13;
const ClientAuth = tls13.ClientAuth;

/// The size of a peer certificate, in bytes: a DER `SubjectPublicKeyInfo`
/// wrapping 32 bytes of ed25519 public key and nothing else. There is no
/// chain behind it and there is no host name in it, which is the whole of
/// the identity model — see `vendor/quic/VENDORED.md`.
pub const spki_length = tls13.ed25519_spki_len;

/// The 32 bytes of a secret key that are the actual entropy source; what the
/// core wants as `private_key_bytes` for `.ed25519`.
const seed_length = SecretKey.seed_length;

/// The instant the core is driven at: nanoseconds on a monotonic clock.
///
/// The core takes `now: i64` on every ingress, every egress and every timer
/// pass and reads no clock of its own, so this is the parameter it already
/// has. It is named here because "nanoseconds since whatever the caller's
/// clock started at" is the whole contract: the core only ever takes
/// differences against another value stamped from the same clock, so a test
/// may start at any instant it likes, and two runs started at different
/// instants are two different runs.
pub const Instant = i64;

/// What this bridge refuses.
///
/// `batch.Error` is included rather than restated: the batcher's refusals are
/// this path's refusals, and a second copy of the list is a list that goes
/// stale when `batch.zig` grows an arm.
pub const Error = batch.Error || error{
    /// The caller's `out` array or `scratch`/`buffer` had no room for what
    /// the core produced.
    ///
    /// **Named for the ways that can happen, not for a mid-flight one.**
    /// `Conn.drain` raises this before the core has built anything, because
    /// the core consumes what it packs: room running out between datagrams is
    /// not a refusal but a short answer, with the flight behind it untouched.
    /// `Bridge.recv` raises it for a datagram larger than `scratch`, which
    /// costs nothing either. A caller that grows the room and calls again
    /// gets the work it was refused.
    NoRoom,
    /// The core had no stream id for this end to open: the peer's transport
    /// parameters have not been applied yet, or it has granted no more streams
    /// than this end has already used.
    ///
    /// **A recoverable refusal, and named apart from `CoreRefused` for that
    /// reason.** `StreamsMap.setMaxStreams` runs only where
    /// `hs.peer_transport_params` is set (`connection.zig:2650`), so a
    /// connection whose peer has not been read yet has a limit of zero and
    /// refuses every open; `MAX_STREAMS` raises the same limit later
    /// (`connection.zig:2146`), so an exhausted limit looks identical. Both are
    /// facts about *now* rather than faults, a later pass gets a different
    /// answer, and a caller that treats this as fatal stops serving over a
    /// refusal the protocol itself makes temporary. What is left in
    /// `CoreRefused` is everything else the core can refuse with — an
    /// allocator that will not make the send ledger above all — and that is
    /// what a caller must still fail on.
    NoStreamRoom,
    /// The active path has no address. Every address the core holds went
    /// through `toCoreAddress` or came out of a peer's `preferred_address`,
    /// and the one value neither produced is the `unset` a `NetworkPath`
    /// starts as — so this is a connection whose path has not been named yet,
    /// which a client is until its dialer writes one onto it.
    NoPathAddress,
    /// The core refused to build a packet. Its own error set is `anyerror` —
    /// `Connection.sendAt` (`connection.zig:3139`) carries no named set —
    /// so a bridge that propagated it would put `anyerror` in its public API,
    /// which `AGENTS.md` forbids. What it was is logged before the refusal
    /// is named, so nothing is dropped on the floor.
    CoreRefused,
};

/// What `create` refuses.
pub const CreateError = error{
    /// The caller's allocator refused the bridge.
    OutOfMemory,
    /// The `std.Io` handed to `create` had no secure entropy source and the
    /// caller did not supply the two transport keys itself.
    EntropyUnavailable,
    /// The `std.Io` was told to stop while `create` was drawing one of those
    /// two keys: `std.Io.Cancelable` arriving through `randomSecure`.
    ///
    /// **Its own answer, not `EntropyUnavailable`'s.** They are facts about
    /// different layers. This one is the caller's own cancellation, which the
    /// caller retries when it chooses and which says nothing at all about the
    /// entropy source; the other is an `std.Io` that cannot key this bridge
    /// and never will. Reporting the first as the second told a cancelling
    /// caller that its entropy was broken.
    Canceled,
};

/// The room one datagram of egress needs, in bytes: RFC 9000 §14.1's padded
/// Initial, taken from the core that pads to it rather than written down
/// here, so a change to the core's floor moves this with it.
///
/// It is a floor and not a ceiling because of how the core builds a datagram:
/// it pads an Initial up to this size and does that arithmetic against the
/// buffer it was handed, so a shorter buffer is one where a packet has
/// already consumed the frames it packed and has nowhere to put them.
const min_datagram = quic.connection_manager.MIN_INITIAL_DATAGRAM;

/// The configuration a caller supplies, in this project's vocabulary.
///
/// Nothing here is named after a field in the vendored tree. A bridge whose
/// configuration is a bag of upstream field names is a wrapper, and a
/// wrapper has to be updated whenever the thing it wraps is renamed; this one
/// is a node id, two keys and an ALPN, and the translation to the core's
/// spelling happens once, in `Bridge.create`.
pub const Config = struct {
    /// This node's identity: the seed the presented certificate is built
    /// from, and the node id a peer compares the certificate against.
    secret: SecretKey,
    /// The node on the other end, when the caller knows it before the
    /// handshake. The connection opens and stays open only for a peer whose
    /// certificate carries these 32 bytes.
    ///
    /// Null is not "any peer". `require_peer_certificate` still holds and the
    /// peer has proved possession of whatever id it presented, which is a
    /// weaker answer than the one this field asks for.
    ///
    /// **A pin here demands a certificate whatever `require_peer_certificate`
    /// says**, and that is the whole precedence between the two fields: the
    /// core reads the pin out of the client-auth block, and
    /// `require_peer_certificate` is what decides whether that block is asked
    /// for at all, so a caller that named a peer and turned the certificate
    /// off would have had its pin dropped without being told — a pin the
    /// field next to it can erase is not a pin. See `demandsPeerCertificate`.
    expect_peer: ?NodeId = null,
    /// Whether a connection opened here must present a certificate at all.
    ///
    /// True by default because a dial-by-node-id stack has no other way to
    /// know who is on the other end. A synthetic address names a path, not a
    /// peer, and a peer that presents no key has proved nothing at all — not
    /// even that it is the node a neighbouring path belongs to.
    ///
    /// False accepts a peer that proves nothing, and it is the only
    /// configuration in which `expect_peer` is not enforced, so it belongs to
    /// a caller that has decided identity is not this connection's business.
    /// A config that names a peer is not one of those.
    require_peer_certificate: bool = true,
    /// The one ALPN this build speaks. The core takes a list because it is a
    /// general TLS stack; a node speaks one, and a list here would be a
    /// second place for two builds to disagree.
    alpn: []const u8,
    /// How long a connection may sit idle before the core gives it up, in
    /// milliseconds. The core's unit is milliseconds and so is this one:
    /// converting at the call site would be one more unit in the project.
    idle_timeout_ms: u64 = 30_000,
    /// The secret that signs Retry tokens and NEW_TOKENs. Null draws one
    /// from the `std.Io` `create` was handed; see `create` for why that is
    /// not a global.
    retry_token_key: ?[16]u8 = null,
    /// The secret the core signs stateless resets with. Null draws one from
    /// the same `std.Io`. It must be the key every connection on this bridge
    /// advertises its reset tokens under, which is why it is one value here
    /// and two fields in the core.
    static_reset_key: ?[16]u8 = null,
};

/// Whether a connection opened on `config` must present a certificate.
///
/// A peer pin implies it, and that implication is the entire precedence
/// rule: `expect_peer` says *which* key a peer has to hold and
/// `require_peer_certificate` says *that it has one*, so a caller that set
/// the first and cleared the second had asked for the stronger of the two
/// answers. The core keeps both in one block (`buildTlsConfig`), and
/// withholding that block withholds the pin with it — a caller could name a
/// peer and get a connection that never compared a certificate against it.
/// Only a config that names no peer and asks for no certificate accepts an
/// anonymous one, and it has to say so in both fields to get there.
fn demandsPeerCertificate(config: Config) bool {
    return config.expect_peer != null or config.require_peer_certificate;
}

/// One QUIC connection the core owns, as a borrowed handle.
///
/// The core heap-allocates the connection and frees it: in `Bridge.destroy`,
/// or in `Bridge.sweep` once `Bridge.tick` has said the connection is
/// finished. Nothing in this file owns the memory, and a handle past that
/// point reads freed bytes. The vendor's own comment calls the ~185 KB
/// connection a heap allocation for the same reason.
pub const Conn = struct {
    /// The core's entry. Read connection state off it; write none.
    entry: *Entry,

    /// The core's own id for this connection, unique per bridge and never
    /// reused. What a caller logs.
    pub fn id(self: Conn) u64 {
        return self.entry.id;
    }

    /// The peer's address on the active path, in this project's address.
    ///
    /// Null when the path has no peer address yet; see
    /// `Error.NoPathAddress` for the one route there.
    pub fn peer(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.peerAddress());
    }

    /// This node's address on the active path.
    pub fn local(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.localAddress());
    }

    /// Whether the handshake is done and the connection carries stream data.
    pub fn established(self: Conn) bool {
        return self.entry.conn.isEstablished();
    }

    /// Whether the core has finished with it. A closed connection may still
    /// be drained once — `sweep` has not run.
    pub fn closed(self: Conn) bool {
        return self.entry.conn.isClosed();
    }

    /// Everything the core wants sent at `at`, as the send seam's values.
    ///
    /// `buffer` receives the datagrams back to back and `out` the socket
    /// writes they add up to; both are the caller's, so nothing here
    /// allocates. Each send borrows its bytes out of `buffer`, so a send is
    /// good until the next `drain` on this connection overwrites it.
    ///
    /// The bytes are exactly what `Connection.sendAt` wrote, in order, cut
    /// into runs at every change of datagram size. A run of more than one
    /// datagram of equal size is a `batch.Send` carrying a segment size and
    /// is what a socket with `UDP_SEGMENT` turns into one `sendmsg`; a run of
    /// one is `batch.Send.single`, which is what rule 7 of
    /// `docs/ARCHITECTURE.md` says a single datagram is. How many datagrams
    /// one run may hold is the caller's `Capability` to decide, not this
    /// function's: it hands over the payload and leaves `batch.Runs` to the
    /// caller, because only the caller knows what its socket can do.
    ///
    /// # What the room costs, and when it gets asked about
    ///
    /// `Connection.sendAt` consumes what it packs — a CRYPTO frame's bytes
    /// leave the send buffer, a packet number is spent, the packet goes into
    /// the retransmission ledger — and it does that before the caller learns
    /// anything. So the room is checked before the core is asked for a
    /// datagram, never after:
    ///
    /// - **No slot and no room for a datagram is `error.NoRoom`, or
    ///   `error.NoPathAddress` for a path with no peer address, and both are
    ///   raised with nothing built.** An empty `out`, a `buffer` under
    ///   `min_datagram` and a path no address reached are the whole of it. The
    ///   flight is exactly as it was, and the retry after a bigger buffer
    ///   emits the datagram this call refused.
    /// - **Room running out mid-flight is not a refusal.** The loop stops
    ///   between datagrams with everything it built already inside a run it is
    ///   about to hand back, so the returned slice is a prefix of what `out`
    ///   and `buffer` had room for, and the rest of the flight is still the
    ///   core's to send. Call `drain` again for the rest; an empty slice is
    ///   how a call says the connection has nothing left.
    ///
    /// A datagram the core refused to build is `Error.CoreRefused`, with the
    /// core's own answer logged before the refusal is named so nothing is
    /// dropped on the floor. It is the one failure here that is not a room
    /// question, and the one with a cost: a datagram already built in this
    /// pass is inside no returned send, because a function that returns
    /// either a refusal or a list cannot hand back both.
    pub fn drain(
        self: Conn,
        out: []Egress,
        buffer: []u8,
        at: Instant,
        random: std.Random,
    ) Error![]Egress {
        const conn = self.entry.conn;
        // The codepoint belongs on the send, and the core already answers
        // that question: `getEcnMark` is its own view of whether this path
        // has validated ECN, and `batch.Recv.ecnFromBits` is the same two
        // bits on this side of the seam. Reading its answer rather than its
        // validator's internals is the difference between a seam and a
        // second opinion — and `.ect0` is what the validator counts against
        // the peer's ACK_ECN counts, so any other value would fail the path.
        const ecn: ?batch.Ecn = batch.Recv.ecnFromBits(conn.getEcnMark());
        // The peer address, read once and before anything is built: it is the
        // same address for every send on this connection until the core
        // migrates it, and a path with no address is refused here rather than
        // halfway through a run that has to be handed back whole.
        const core_peer = conn.peerAddress().*;
        if (core_peer == .unset) return error.NoPathAddress;
        const to: SocketAddr = fromCoreAddress(core_peer);
        if (out.len == 0 or buffer.len < min_datagram) return error.NoRoom;

        var filled: usize = 0;
        var used: usize = 0;
        // The run being accumulated: `run_size` is 0 when no run is open.
        var run_start: usize = 0;
        var run_size: usize = 0;
        while (true) {
            // A free slot for this datagram, before it is built. Two while a
            // run is open: one for the close this datagram may trigger, and
            // one owed either way to the close of whatever run this datagram
            // opens. Holding that second one back is what lets the loop stop
            // at any datagram boundary — the run it leaves open still has the
            // slot its close needs.
            const slots = out.len - used;
            if (slots == 0 or (run_size != 0 and slots < 2)) break;
            if (buffer.len - filled < min_datagram) break;

            const len = conn.sendAt(buffer[filled..], at, random) catch |err| {
                std.log.warn("quic bridge: the core refused to build a packet: {t}", .{err});
                return error.CoreRefused;
            };
            if (len == 0) break;
            if (run_size == 0) {
                run_size = len;
            } else if (len != run_size) {
                // A `UDP_SEGMENT` send names one size for every datagram but
                // the last, so a change of size ends the run. Continuing
                // anyway would hand the socket a `UDP_SEGMENT` value that
                // does not describe the payload.
                used = try closeRun(out, used, buffer, run_start, filled, run_size, ecn, to);
                run_start = filled;
                run_size = len;
            }
            filled += len;
        }
        if (run_size != 0) {
            // Safe by the loop's own arithmetic rather than by hope: the slot
            // was reserved before the datagram that opened this run.
            used = try closeRun(out, used, buffer, run_start, filled, run_size, ecn, to);
        }
        return out[0..used];
    }

    /// The bidirectional stream this connection's *peer* opened, or null when
    /// it has not opened one.
    ///
    /// **A stream is read by whichever end opened it.** `Stream.drain` reads
    /// the stream it is called on and nothing else, so a protocol where both
    /// ends speak on one stream has only two shapes: this end opens one and
    /// finds the peer's, or the peer opens one and this end takes it. The
    /// relay protocol takes the second — the client opens one stream and the
    /// relay speaks on that same one — because the client is the end that
    /// dials, and the end that dials is the end that has to speak first.
    ///
    /// Null rather than a refusal: the peer simply has not got there yet, and
    /// a caller that read that as an error would fail a connection that is one
    /// round trip from working. How many peer streams a caller expects is the
    /// caller's own question and is not answered here.
    pub fn peerStream(self: Conn) ?Stream {
        var it = self.entry.conn.streams.streams.iterator();
        while (it.next()) |entry| {
            if (quic_stream.isLocal(entry.key_ptr.*, self.entry.conn.is_server)) continue;
            return .{ .entry = entry.value_ptr.* };
        }
        return null;
    }
};

/// One application stream on a connection, as a byte pipe in this project's
/// vocabulary.
///
/// **The seam for everything that runs above a datagram.** `Conn` reads state
/// and `Conn.drain` writes packets, and nothing in between was exposed: a
/// protocol carried *over* a connection — the relay protocol is the one this
/// project has — has to run on a stream, and a caller reaching into
/// `Conn.entry.conn.streams` for one would be a second opinion on the core,
/// which is the thing this file exists to prevent. So the stream is named
/// here, once, and `vendor/quic` is untouched: it opens a stream, carries
/// bytes and says when it is done, which is the whole of what a framed
/// protocol over QUIC asks of a transport.
///
/// It is not relay-specific and nothing in this file knows what rides on it.
/// A borrowed handle, so every guarantee `Conn` states about its own entry
/// holds for this: good until the connection is swept.
pub const Stream = struct {
    /// The core's own stream.
    entry: *quic_stream.Stream,

    /// Open a new bidirectional stream on `conn`.
    ///
    /// The core's error set here is `anyerror` — `Connection.openStream`
    /// (`connection.zig:3935`) carries no named set — so it is mapped onto this
    /// file's own two answers, for the reason each of those gives. A stream
    /// limit is `error.NoStreamRoom` and logs nothing, because it is the core
    /// saying "not yet" and a warning a pass later contradicted would be a log
    /// about a fact that has since changed. Anything else is
    /// `Error.CoreRefused`, with the core's own answer logged before the
    /// refusal is named, so nothing is dropped on the floor.
    pub fn open(conn: Conn) Error!Stream {
        const opened = conn.entry.conn.openStream() catch |err| switch (err) {
            error.StreamLimitError => return error.NoStreamRoom,
            else => {
                std.log.warn("quic bridge: the core refused to open a stream: {t}", .{err});
                return error.CoreRefused;
            },
        };
        return .{ .entry = opened };
    }

    /// The core's own id for this stream.
    pub fn id(self: Stream) u64 {
        return self.entry.stream_id;
    }

    /// Write bytes, after everything written before them.
    pub fn write(self: *Stream, bytes: []const u8) Error!void {
        self.entry.send.writeData(bytes) catch |err| {
            std.log.warn("quic bridge: the core refused stream bytes: {t}", .{err});
            return error.CoreRefused;
        };
    }

    /// Say nothing more on this stream. A peer reads the end as a FIN.
    pub fn close(self: *Stream) void {
        self.entry.send.close();
    }

    /// Take everything this stream has ready, appending it to `sink`.
    ///
    /// Returns whether anything was appended, so a caller can fold this into
    /// its own "did this pass move anything" answer without a second read.
    /// Nothing is ready is false rather than a refusal: a stream with nothing
    /// on it yet is a peer that has not spoken, not a fault.
    ///
    /// **The sink is the caller's and it grows, because a read has no length
    /// worth guessing.** The core hands back whatever contiguous run it holds —
    /// `FrameSorter.pop` returns a whole chunk, coalesced up to `MAX_COALESCED`
    /// (`stream.zig:72`) — so the size of a read is a function of what the peer
    /// sent and of nothing the caller can see coming. A caller that owned a
    /// fixed buffer had two answers and both were wrong: sized to a frame it
    /// refused the run *after* popping it, and the bytes were already gone
    /// (`stream.zig:390-396` hands over ownership), and sized to the ceiling it
    /// allocated the ceiling per stream for the whole life of the connection.
    /// A sink that grows pays for what actually arrived and nothing for what a
    /// peer might send.
    ///
    /// **One copy, not two.** The core hands its chunk to the application to
    /// free (`ReceiveStream.read`, `stream.zig:523`), so `gpa` is the allocator
    /// that made it — which is the bridge's own, and a caller passes the one it
    /// created the bridge with. The append is the copy, and it has to be one:
    /// a framed protocol parses a message in place and borrows into the bytes
    /// it was handed, and those bytes must outlive the message, which a borrow
    /// of the core's chunk cannot because the next read has already taken it.
    ///
    /// **The room is taken before the bytes, because the bytes are gone once
    /// the core has handed them over.** A read advances the stream's position,
    /// charges the peer for what it read, and transfers an owned allocation
    /// out; an allocator that then refuses the append has dropped a run the
    /// peer will never retransmit, because from the core's side it was
    /// delivered. So this asks the core how much the next read holds —
    /// `ReceiveStream.peekLen`, which consumes nothing — reserves exactly
    /// that, and reads afterwards.
    ///
    /// **What a refused allocation leaves.** Everything appended before the
    /// refusal stays in `sink`, which is the caller's, and every byte the sink
    /// did not take is still pending on the stream, in order. A retry with an
    /// allocator that answers appends exactly the bytes this call stopped at,
    /// and none of them twice. `false` therefore means "nothing was appended",
    /// which is also what a stream with nothing ready means; `sink.len` is
    /// what tells those two apart.
    pub fn drain(
        self: *Stream,
        gpa: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) std.mem.Allocator.Error!bool {
        var moved = false;
        while (self.entry.recv.peekLen()) |len| {
            try sink.ensureUnusedCapacity(gpa, len);
            const chunk = self.entry.recv.read() orelse break;
            sink.appendSliceAssumeCapacity(chunk);
            gpa.free(chunk);
            moved = true;
        }
        return moved;
    }

    /// Whether the peer has said everything it will say on this stream.
    pub fn finished(self: Stream) bool {
        return self.entry.recv.allReceived();
    }
};

/// One socket write: where it goes and what the batcher is to be asked for.
pub const Egress = struct {
    /// The peer address on the core's active path, in this project's
    /// address. It is the same address for every send on this connection
    /// until the core migrates it.
    to: SocketAddr,
    /// The payload. Feed it to `batch.Runs.init` with the socket's
    /// `Capability` and hand each run to `batch.cmsg`.
    send: batch.Send,
};

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
    from: SocketAddr,
    /// Where it was sent to.
    local: SocketAddr,
    /// The codepoint it carried, or null for not-ECT.
    ecn: ?batch.Ecn,
};

/// Where a received datagram came from, in this project's terms.
pub const Source = struct {
    /// The address itself.
    socket: SocketAddr,
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
    processed: Conn,
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
    /// (`connection_manager.zig:234`, default false) and `Config` has no QUIC
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
pub const Bridge = struct {
    gpa: std.mem.Allocator,
    /// The core. Public because a caller reads connection state off it, not
    /// because poking it is safe.
    manager: Manager,
    node_id: NodeId,
    /// The 32 bytes of seed the presented certificate is built from.
    seed: [seed_length]u8,
    /// The certificate: an SPKI over `node_id`, and nothing behind it.
    spki: [spki_length]u8,
    /// The one-element chain the core's config points at. It points into
    /// `spki`, which is why this struct lives on the heap.
    cert_chain: [1][]const u8,
    /// The one-element ALPN list, for the same reason.
    alpn_list: [1][]const u8,
    /// The peer pin a server actually enforces. It points into this struct
    /// for the same reason.
    client_auth: ClientAuth,

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
    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        config: Config,
        random: std.Random,
    ) CreateError!*Bridge {
        const self = try gpa.create(Bridge);
        errdefer gpa.destroy(self);
        const retry_key = try drawKey(io, config.retry_token_key);
        const reset_key = try drawKey(io, config.static_reset_key);
        self.* = .{
            .gpa = gpa,
            .manager = undefined,
            .node_id = config.secret.nodeId(),
            .seed = config.secret.toBytes()[0..seed_length].*,
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .client_auth = .{
                .expect_node_id = if (config.expect_peer) |peer| peer.toBytes() else null,
                // A pin implies a certificate, so the two fields are read
                // through one decision rather than two: see
                // `demandsPeerCertificate`.
                .mode = if (demandsPeerCertificate(config)) .required else .optional,
            },
        };
        self.manager = Manager.init(
            gpa,
            self.buildTlsConfig(config),
            connectionConfig(config, retry_key),
            retry_key,
            reset_key,
            random,
        );
        return self;
    }

    /// Free every connection the core holds and then the bridge.
    ///
    /// The secret seed is zeroed first: it is a copy of a key the caller
    /// also holds, and a heap this size is very likely to outlive the
    /// process's own key store.
    pub fn destroy(self: *Bridge) void {
        self.manager.deinit();
        std.crypto.secureZero(u8, self.seed[0..]);
        self.gpa.destroy(self);
    }

    /// The node id this bridge presents as a bare `SubjectPublicKeyInfo`.
    pub fn nodeId(self: *const Bridge) NodeId {
        return self.node_id;
    }

    /// The TLS configuration the core is running.
    ///
    /// Exposed because it is the translation, and a translation nobody can
    /// read is a translation nobody can check.
    ///
    /// The type is the core's own and is spelled in full: an alias for it here
    /// would be private, and a public signature may not name a private type.
    pub fn tlsConfig(self: *const Bridge) quic.tls13.TlsConfig {
        return self.manager.tls_config;
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
    fn buildTlsConfig(self: *Bridge, config: Config) quic.tls13.TlsConfig {
        self.spki = tls13.ed25519Spki(&self.node_id.toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = .{config.alpn};
        return .{
            .cert_chain_der = &self.cert_chain,
            .private_key_bytes = self.seed[0..],
            .private_key_algorithm = .ed25519,
            .alpn = &self.alpn_list,
            .client_auth = if (demandsPeerCertificate(config)) &self.client_auth else null,
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
    pub fn recv(
        self: *Bridge,
        map: *const addr_map.MappedAddrs,
        datagram: Datagram,
        scratch: []u8,
        at: Instant,
        random: std.Random,
    ) Error!Ingress {
        if (datagram.bytes.len > scratch.len) return error.NoRoom;
        @memcpy(scratch[0..datagram.bytes.len], datagram.bytes);
        const action = self.manager.recvDatagram(
            scratch[0..datagram.bytes.len],
            toCoreAddress(datagram.from),
            toCoreAddress(datagram.local),
            ecnBits(datagram.ecn),
            scratch[datagram.bytes.len..],
            at,
            random,
        );
        const classification = base_ula.classify(datagram.from);
        const owner: ?addr_map.Key = switch (classification) {
            // Only a synthetic address can be owned; a direct path needs no
            // map and keeps its real port, which is why `classify` carries it
            // through whole rather than reducing it to a `Ula`.
            .any_path, .relay, .custom => |octets| map.lookup(octets),
            .ip => null,
        };
        return .{
            .source = .{
                .socket = datagram.from,
                .classification = classification,
                .owner = owner,
            },
            .outcome = switch (action) {
                .processed => |entry| .{ .processed = .{ .entry = entry } },
                .send_response => |bytes| .{ .reply = try group(bytes, bytes.len, null) },
                .dropped => .dropped,
                .foreign => |server_id| .{ .foreign = server_id },
            },
        };
    }

    /// One pass of the core's timers for `conn`, at the caller's instant.
    ///
    /// A finished connection leaves the core's table here and its memory
    /// stands until `sweep`, which is what lets a caller drain the close it
    /// just produced before the memory goes.
    pub fn tick(
        self: *Bridge,
        conn: Conn,
        at: Instant,
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
    pub fn connectionAt(self: *const Bridge, index: usize) ?Conn {
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

/// The core's connection configuration for a node's config.
///
/// One field is not a rename and is the reason this function exists at all:
/// `token_key` is the same secret as the manager's `retry_token_key` and
/// nothing sets it for you. A server that leaves it null signs every
/// NEW_TOKEN with sixteen zero bytes, so a token it issued outlives the key
/// it was meant to be useless without. Two fields in the core, one value in
/// this project's vocabulary.
fn connectionConfig(config: Config, retry_token_key: [16]u8) quic.connection.ConnectionConfig {
    return .{
        .max_idle_timeout = config.idle_timeout_ms,
        .token_key = retry_token_key,
    };
}

/// The transport key the caller supplied, or one drawn from `io`.
///
/// A null here is upstream drawing from the process CSPRNG, which
/// `AGENTS.md` §2 forbids and `vendor/quic/VENDORED.md` records as one of
/// the three things the patch removed. `std.Io.randomSecure` is the caller's
/// own entropy, reached through the handle the caller was already given: no
/// global, nothing stored, and a test that wants determinism passes the key
/// instead.
///
/// Both of its answers keep their own name. They arrive together in one
/// error set (`std.Io.RandomSecureError`) and mean opposite things to
/// whatever is above: `EntropyUnavailable` is an `std.Io` that cannot key
/// this bridge and never will, and `Canceled` is the caller stopping this
/// operation, which the caller retries when it chooses. Collapsing them told
/// a cancelling caller that its entropy source was broken, and told an
/// `std.Io` with no entropy that its own cancellation should be retried.
fn drawKey(io: std.Io, supplied: ?[16]u8) CreateError![16]u8 {
    if (supplied) |key| return key;
    var drawn: [16]u8 = undefined;
    io.randomSecure(&drawn) catch |err| switch (err) {
        error.EntropyUnavailable => return error.EntropyUnavailable,
        error.Canceled => return error.Canceled,
    };
    return drawn;
}

/// The two bits the core reads off an `IP_TOS` or `IPV6_TCLASS`, or zero.
///
/// Zero is `IP_TOS_NOT_ECT`, so "no codepoint" and "not-ECT" are the same
/// value on this side too, which is what `batch.Recv.ecnFromBits` says from
/// the other end.
fn ecnBits(codepoint: ?batch.Ecn) u2 {
    const set = codepoint orelse return 0;
    return @truncate(set.toBits());
}

/// A run of equally sized datagrams, or one datagram.
///
/// The one datagram case is not a special case of the batch case: `Send` says
/// "one datagram" by carrying no segment size, and a hand-built value with a
/// segment size set and a payload no longer than it would hand a socket a
/// `UDP_SEGMENT` control message naming a single datagram. `batch.Runs.next`
/// refuses to propagate the size onto a run of one for the same reason.
fn group(contents: []const u8, size: usize, ecn: ?batch.Ecn) batch.Error!batch.Send {
    if (contents.len == size) return batch.Send.single(contents, ecn);
    return batch.Send.batch(contents, size, ecn);
}

/// Close the run that ended at `end` and start nothing.
///
/// `to` is the address `Conn.drain` resolved before it asked the core for
/// anything, so this cannot discover a path with no address after the run it
/// is closing has already been built. The `out.len` check is the slot the
/// caller counted for this close; a run of equal-size datagrams always
/// divides by its size, so `group` is not what refuses here.
fn closeRun(
    out: []Egress,
    used: usize,
    buffer: []u8,
    begin: usize,
    end: usize,
    size: usize,
    ecn: ?batch.Ecn,
    to: SocketAddr,
) Error!usize {
    if (used == out.len) return error.NoRoom;
    out[used] = .{
        .to = to,
        .send = try group(buffer[begin..end], size, ecn),
    };
    return used + 1;
}

/// This project's address as the core's own.
///
/// The core's address is a tagged union over the two families with no kernel
/// struct behind it (`vendor/quic/src/address.zig`), and this project's is a
/// tagged union with no scope, so the conversion is the bytes and the port
/// and nothing else has to be decided. This and `fromCoreAddress` are the only
/// two places the two vocabularies meet; the socket seam's own conversions
/// live in `transport/socket.zig` and never see the core's type.
fn toCoreAddress(socket: SocketAddr) quic.address.Address {
    return switch (socket.ip) {
        .v4 => |octets| quic.address.Address.initIpv4(octets, socket.port),
        // The scope is zero because `SocketAddr` carries none. A link-local
        // address would need one and this project has no name for it; the
        // synthetic ULAs are not link-local, which is why the core's scope
        // comparison can never disagree with `ula` for them.
        .v6 => |octets| quic.address.Address.initIpv6(octets, socket.port, 0),
    };
}

/// The core's address as this project's.
///
/// Null for the one value `SocketAddr` cannot spell — `unset`, a path the
/// core has not been given an address for — and null rather than a wildcard
/// for it, because a datagram sent to a path with no address reaches nobody.
fn fromCoreAddress(core: *const quic.address.Address) ?SocketAddr {
    return switch (core.*) {
        .unset => null,
        .ipv4 => |v4| .{ .ip = .{ .v4 = v4.bytes }, .port = v4.port },
        .ipv6 => |v6| .{ .ip = .{ .v6 = v6.bytes }, .port = v6.port },
    };
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
const client_addr: SocketAddr = base_ula.socketAddrFor(.any_path, client_host);
const server_addr: SocketAddr = base_ula.socketAddrFor(.relay, server_host);

/// Fixed seeds, so a run draws the same connection ids and the same nonces
/// every time. `generateDeterministic` fails only on a degenerate seed,
/// which a constant byte pattern is not.
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);

/// The one ALPN both ends speak.
const alpn = "ozai";

/// The name the client asks for. Nothing resolves it and nothing checks it:
/// there is no certificate to match a name against, only a key to compare.
const server_name = "ozai.invalid";

/// Where virtual time starts: a second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
const start: Instant = 1_000 * std.time.ns_per_s;

/// A seeded generator's engine. `std.Random` is an interface over a pointer
/// to an engine, so the engine has to outlive every value handed out from it;
/// `Client` keeps the two together for the same reason `lossy_link_test.zig`
/// does.
const Prng = std.Random.DefaultPrng;

/// The largest datagram a socket read is expected to hold. The same bound
/// `vendor/quic/src/quic/lossy_link_test.zig` uses, which is where it came
/// from: a QUIC packet is at most a path MTU and no path MTU is larger.
const max_datagram = 1500;

/// The core's floor for a datagram, re-exported rather than written down: a
/// test that pads to its own idea of 1200 would keep passing if the core's
/// floor moved. The same value `Conn.drain` refuses a short buffer against.
const min_initial = min_datagram;

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
    spki: [spki_length]u8,
    cert_chain: [1][]const u8,
    alpn_list: [1][]const u8,
    seed: [seed_length]u8,
    /// The send-side scratch, and the core's mutable read buffer beside it so
    /// a datagram going each way never shares bytes.
    buffer: [max_datagram]u8 = undefined,
    inbound: [max_datagram]u8 = undefined,

    fn init(
        self: *Client,
        secret: SecretKey,
        expect: ?NodeId,
        engine_seed: u64,
        at: Instant,
    ) !void {
        self.* = .{
            .conn = undefined,
            .engine = Prng.init(engine_seed),
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .seed = secret.toBytes()[0..seed_length].*,
        };
        self.spki = tls13.ed25519Spki(&secret.nodeId().toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = .{alpn};
        self.conn = try t.allocator.create(quic.connection.Connection);
        errdefer t.allocator.destroy(self.conn);
        try quic.connection.connectInto(
            self.conn,
            t.allocator,
            server_name,
            .{},
            .{
                .cert_chain_der = &.{},
                .private_key_bytes = &.{},
                .alpn = &self.alpn_list,
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
        self.conn.paths[0].peer_addr = toCoreAddress(server_addr);
        self.conn.paths[0].local_addr = toCoreAddress(client_addr);
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
    fn receive(self: *Client, bytes: []const u8, at: Instant) void {
        std.debug.assert(bytes.len <= self.inbound.len);
        @memcpy(self.inbound[0..bytes.len], bytes);
        self.conn.handleDatagram(self.inbound[0..bytes.len], .{
            .to = toCoreAddress(client_addr),
            .from = toCoreAddress(server_addr),
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
    conn: Conn,
    client: *Client,
    egress: []Egress,
    out: []u8,
    at: Instant,
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
    at: Instant,
) !void {
    var scratch: [2 * max_datagram]u8 = undefined;
    var egress: [max_egress]Egress = undefined;
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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(1);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();

    // The translation, read back rather than assumed. One certificate, 44
    // bytes, wrapping this node's own id, the peer pinned in the one field
    // a server actually enforces, and nothing set in the field that only a
    // client reads.
    const tls = bridge.tlsConfig();
    try t.expectEqual(@as(usize, 1), tls.cert_chain_der.len);
    try t.expectEqual(@as(usize, spki_length), tls.cert_chain_der[0].len);
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&server_secret.nodeId().toBytes()),
        tls.cert_chain_der[0],
    );
    try t.expectEqual(tls13.PrivateKeyAlgorithm.ed25519, tls.private_key_algorithm);
    try t.expectEqual(@as(usize, 1), tls.alpn.len);
    try t.expectEqualStrings(alpn, tls.alpn[0]);
    try t.expectEqual(@as(?[32]u8, null), tls.expect_peer_node_id);
    try t.expectEqual(client_secret.nodeId().toBytes(), tls.client_auth.?.expect_node_id.?);
    try t.expectEqual(tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // The consequence of the translation above: a handshake completes, and
    // it completes over two synthetic addresses with no socket anywhere.
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 2, start);
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
        &tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(alpn, conn.entry.conn.negotiatedAlpn());
}

test "a bridge that pins no node still learns which node it is talking to" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // One field changed from the test above and nothing else: no expected
    // peer. The certificate request is still made, so the connection is
    // still identified — the peer has proved possession of the id it
    // presented rather than being the node the caller asked for.
    var engine = Prng.init(3);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqual(@as(?[32]u8, null), bridge.tlsConfig().client_auth.?.expect_node_id);

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 4, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(@as(?[32]u8, null), conn.entry.conn.clientAuth().?.expect_node_id);
}

test "egress is the batcher's value, and a burst of one size is one send" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(5);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 6, start);
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

    var egress: [max_egress]Egress = undefined;
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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(7);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const probe = unsupportedVersionProbe();
    // An instant nothing on this host would produce: a monotonic clock that
    // started at an odd offset and has a sub-millisecond remainder on it.
    const at: Instant = 7 * std.time.ns_per_s + 123_456_789;
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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(11);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 12, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    const stream = try conn.entry.conn.openStream();
    try stream.send.writeData("a datagram to send");
    stream.send.close();

    var egress: [max_egress]Egress = undefined;
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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(13);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var map_engine = Prng.init(14);
    const relay = try base_addr.RelayUrl.parse("https://relay.example.com");
    const owned: addr_map.Key = .{ .relay = .{ .relay = relay, .node = server_secret.nodeId() } };
    const allocated = try map.get(t.allocator, owned, map_engine.random());

    const probe = unsupportedVersionProbe();
    var scratch: [2 * max_datagram]u8 = undefined;
    const from_relay: SocketAddr = .{ .ip = .{ .v6 = allocated }, .port = base_ula.mapped_port };
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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var engine = Prng.init(17);

    const supplied: [16]u8 = @splat(0x77);
    const given = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
        .retry_token_key = supplied,
    }, engine.random());
    defer given.destroy();
    try t.expectEqualSlices(u8, &supplied, &given.manager.retry_token_key);

    // Two bridges over one identity, drawn from one `std.Io`, are two
    // different bridges. A constant the bridge defaulted to would make these
    // equal; so would storing the generator.
    const drawn_a = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer drawn_a.destroy();
    const drawn_b = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
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

test "an allocator that refuses the sink leaves every byte pending for the next pass" {
    // A stream is the one thing in this file a test can drive without a
    // peer: the core hands out a receive half, and a STREAM frame is all it
    // takes to fill it.
    const message = "the relay frame this pass must not lose";
    var core = quic_stream.Stream.init(t.allocator, 0);
    defer core.deinit();
    try core.recv.handleStreamFrame(0, message, false);
    var stream: Stream = .{ .entry = &core };

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

test "a sink that refuses half way keeps what it took and the rest" {
    var core = quic_stream.Stream.init(t.allocator, 0);
    defer core.deinit();
    // Out of order, so the reassembler holds two runs rather than one.
    try core.recv.handleStreamFrame(64, "the second run", false);
    try core.recv.handleStreamFrame(0, "the first run", false);
    var stream: Stream = .{ .entry = &core };

    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    // Enough for one reserve and not for two: the second read has to fail,
    // after the first run is already in the sink.
    var one_run = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 1 });
    try t.expectError(error.OutOfMemory, stream.drain(one_run.allocator(), &sink));
    try t.expectEqualStrings("the first run", sink.items);

    sink.clearRetainingCapacity();
    try t.expect(try stream.drain(t.allocator, &sink));
    try t.expectEqualStrings("the first runthe second run", sink.items);
}

test "no egress room leaves the flight unsent, and the retry after it emits the flight" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(19);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 20, start);
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

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var no_slot: [0]Egress = undefined;
    var too_short: [min_datagram - 1]u8 = undefined;

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
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(21);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 22, start);
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
    var one: [1]Egress = undefined;
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
fn cancelledIo() std.Io {
    var vtable = std.Io.failing.vtable.*;
    vtable.randomSecure = struct {
        fn draw(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.Canceled;
        }
    }.draw;
    return .{ .userdata = null, .vtable = &vtable };
}

test "an entropy draw that was cancelled is not reported as a broken entropy source" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var engine = Prng.init(23);

    // `std.Io.failing` is the std-supplied `std.Io` with no entropy at all,
    // which is the other of the two answers.
    try t.expectError(
        error.EntropyUnavailable,
        Bridge.create(t.allocator, std.Io.failing, .{
            .secret = server_secret,
            .alpn = alpn,
        }, engine.random()),
    );
    try t.expectError(
        error.Canceled,
        Bridge.create(t.allocator, cancelledIo(), .{
            .secret = server_secret,
            .alpn = alpn,
        }, engine.random()),
    );

    // A supplied key is never drawn, so the same two `std.Io`s build a bridge
    // without either refusal.
    const supplied: [16]u8 = @splat(0x55);
    const bridge = try Bridge.create(t.allocator, cancelledIo(), .{
        .secret = server_secret,
        .alpn = alpn,
        .retry_token_key = supplied,
        .static_reset_key = supplied,
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqualSlices(u8, &supplied, &bridge.manager.retry_token_key);
}

test "a peer pin is enforced whatever the caller said about certificates" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var engine = Prng.init(25);

    // The pin, with the certificate requirement explicitly cleared. The core
    // reads the pin out of the block that requirement decides on, so this is
    // the configuration in which an unenforced pin was possible.
    const pinned = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .require_peer_certificate = false,
        .alpn = alpn,
    }, engine.random());
    defer pinned.destroy();
    const tls = pinned.tlsConfig();
    try t.expect(tls.client_auth != null);
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        tls.client_auth.?.expect_node_id.?,
    );
    try t.expectEqual(tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // Naming no peer and asking for no certificate is the one configuration
    // that accepts an anonymous peer, and it still asks for one by default.
    const anonymous = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .require_peer_certificate = false,
        .alpn = alpn,
    }, engine.random());
    defer anonymous.destroy();
    try t.expectEqual(@as(?*const ClientAuth, null), anonymous.tlsConfig().client_auth);

    const defaulted = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer defaulted.destroy();
    const default_tls = defaulted.tlsConfig();
    try t.expect(default_tls.client_auth != null);
    try t.expectEqual(tls13.ClientAuth.Mode.required, default_tls.client_auth.?.mode);
    try t.expectEqual(@as(?[32]u8, null), default_tls.client_auth.?.expect_node_id);
}

test "one egress slot at a time sends exactly what the whole array sends" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
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
        .alpn = alpn,
    }, wide_engine.random());
    defer wide.destroy();
    var narrow_engine = Prng.init(31);
    const narrow = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, narrow_engine.random());
    defer narrow.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var scratch: [2 * max_datagram]u8 = undefined;

    var wide_client: Client = undefined;
    try wide_client.init(client_secret, server_secret.nodeId(), 32, start);
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
    try narrow_client.init(client_secret, server_secret.nodeId(), 32, start);
    defer narrow_client.deinit();
    const narrow_len = try narrow_client.conn.sendAt(&narrow_client.buffer, start, narrow_client.random());
    const narrow_ingress = try narrow.recv(&map, .{
        .bytes = narrow_client.buffer[0..narrow_len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, narrow_client.random());
    const narrow_conn = switch (narrow_ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var wide_bytes: std.ArrayList(u8) = .empty;
    defer wide_bytes.deinit(t.allocator);
    for (try wide_conn.drain(egress[0..], out[0..], start, wide_client.random())) |send| {
        try wide_bytes.appendSlice(t.allocator, send.send.contents);
    }

    var one: [1]Egress = undefined;
    var narrow_out: [max_datagram]u8 = undefined;
    var narrow_bytes: std.ArrayList(u8) = .empty;
    defer narrow_bytes.deinit(t.allocator);
    var passes: usize = 0;
    while (passes < max_rounds) : (passes += 1) {
        const sends = try narrow_conn.drain(one[0..], narrow_out[0..], start, narrow_client.random());
        if (sends.len == 0) break;
        for (sends) |send| try narrow_bytes.appendSlice(t.allocator, send.send.contents);
    }

    try t.expect(wide_bytes.items.len > 0);
    try t.expectEqualSlices(u8, wide_bytes.items, narrow_bytes.items);
}
