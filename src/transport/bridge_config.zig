//! What a caller hands the bridge, and what the bridge does when the caller
//! hands it nothing: the node identity, the two transport secrets, the ALPN,
//! and the two refusal sets.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over this
//! and five other named modules. The boundary is drawn here because these are
//! the declarations that name nothing themselves and that every other module
//! names: `Error` is in the signature of `Conn.drain` and `Bridge.recv`,
//! `Instant` is a parameter of every call that moves the core forward, and
//! `Config` is translated exactly once, in `bridge_manager.Bridge.create`. A
//! module every other one names and that names none of them is a leaf, and that
//! is what this file is.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const batch = @import("batch.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;

const tls13 = quic.tls13;

/// The size of a peer certificate, in bytes: a DER `SubjectPublicKeyInfo`
/// wrapping 32 bytes of ed25519 public key and nothing else. There is no
/// chain behind it and there is no host name in it, which is the whole of
/// the identity model — see `vendor/quic/VENDORED.md`.
pub const spki_length = tls13.ed25519_spki_len;

/// The 32 bytes of a secret key that are the actual entropy source; what the
/// core wants as `private_key_bytes` for `.ed25519`.
pub const seed_length = SecretKey.seed_length;

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
    /// CID/reset index growth failed after the core may have processed input.
    /// Live connections remain valid; retry their manager's `syncCids` before
    /// sending newly issued CIDs, or abandon the connection.
    OutOfMemory,
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
    /// False permits an anonymous peer only when `expect_peer` is also null.
    /// A configured pin always requires and verifies the peer certificate.
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
pub fn demandsPeerCertificate(config: Config) bool {
    return config.expect_peer != null or config.require_peer_certificate;
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
pub fn drawKey(io: std.Io, supplied: ?[16]u8) CreateError![16]u8 {
    if (supplied) |key| return key;
    var drawn: [16]u8 = undefined;
    io.randomSecure(&drawn) catch |err| switch (err) {
        error.EntropyUnavailable => return error.EntropyUnavailable,
        error.Canceled => return error.Canceled,
    };
    return drawn;
}

const t = std.testing;

// The shared peer fixture, named here so the tests below stand as they were
// written: a bridge test needs one client, one seed and one ALPN.
const peer_mod = @import("bridge_peer.zig");
const server_seed = peer_mod.server_seed;
const alpn = peer_mod.alpn;
const Prng = peer_mod.Prng;

const Bridge = @import("bridge_manager.zig").Bridge;

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
