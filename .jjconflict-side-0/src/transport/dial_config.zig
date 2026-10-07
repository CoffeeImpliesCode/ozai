//! What a dial is configured with, and what a refused dial says: the identity,
//! the ALPN, the SNI, the NEW_TOKEN, the peer-pin rule, and the two refusal
//! sets.
//!
//! Split out of `transport/dial.zig`, which is now the facade over this and
//! three other named modules. The boundary is drawn here because these are the
//! declarations every other dial module names and that name none of them: the
//! pin is a parameter of `dial` rather than a field of `Dialer` precisely
//! because the config belongs to the caller rather than to the machine, and a
//! config next to the machine that copies it by value is a second answer to the
//! same question.

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("addr_map.zig");
const quic_bridge = @import("quic_bridge.zig");

const SecretKey = base_key.SecretKey;

/// The instant the core is driven at. Re-exported so a caller threading a dial
/// names one module for its identity and its clock.
pub const Instant = quic_bridge.Instant;

/// The size of a peer certificate: a DER `SubjectPublicKeyInfo` wrapping 32
/// bytes of ed25519 public key and nothing else.
pub const spki_length = quic_bridge.spki_length;

/// The 32 bytes of a secret key that are the actual entropy source; what the
/// core wants as `private_key_bytes` for `.ed25519`.
pub const seed_length = SecretKey.seed_length;

/// The SNI every dial sends unless the caller names another one. See the
/// module doc: this is a constant, not a host, and it is never verified.
pub const default_server_name = "ozai.invalid";

/// What this path refuses.
///
/// Three other vocabularies are included whole rather than restated. One set
/// covers a dialled and an accepted connection, and a second copy of
/// `quic_bridge.Error` is a list that goes stale when that file grows an arm.
/// A target can reach every arm of `base_addr.CustomAddrParseError` and of
/// `addr_map.GetError`, and a caller should not have to import two more
/// modules to handle a refused dial. Of those, `DataTooLong` is the one worth
/// a word: a key that silently cut a custom address off would send the peer
/// somewhere that is not here.
pub const Error = quic_bridge.Error || base_addr.CustomAddrParseError ||
    addr_map.GetError || error{
    /// The caller's allocator refused the dial.
    OutOfMemory,
    /// The caller required a pin and named no peer to pin. Nothing was
    /// allocated: the refusal is the first thing `dial` does.
    NoPeerPin,
    /// A relay target without a peer id has no `(relay, node)` map key.
    NoPeerId,
    /// The manager's connection table is full. A dial takes the same slot an
    /// accepted connection would, and a node that is refusing new connections
    /// is refusing both.
    TooManyConnections,
    /// The connection had more live CIDs than `ConnEntry` can record, so one
    /// could not be taken back out of the routing map. Unreachable for a
    /// connection the manager just built; named because a silent drop here
    /// would leave a routing entry pointing at freed memory.
    CidPoolFull,
};

/// What `Dialer.destroy` refuses.
pub const DestroyError = error{
    /// A connection this dialer opened is still in the manager's table. Its
    /// TLS handshake points at this dialer's seed, `cert_chain` and `alpn_list`,
    /// so freeing those now leaves the core reading freed bytes.
    DialedConnectionsLive,
};

/// The configuration a caller supplies, in this project's vocabulary.
///
/// Nothing here is named after a field in the vendored tree, for
/// `quic_bridge.zig`'s reason, and there is deliberately no pin: the pin
/// belongs to a dial, not to a dialer, because one dialer dials many peers.
pub const Config = struct {
    /// This node's identity: the seed the presented certificate is built from,
    /// and the node id a peer compares the certificate against.
    secret: SecretKey,
    /// The one ALPN this build speaks. The core takes a list because it is a
    /// general TLS stack; a node speaks one.
    alpn: []const u8,
    /// The SNI to send. A constant for every dial this project originates; see
    /// the module doc for what the field is and is not.
    server_name: []const u8 = default_server_name,
    /// How long a connection may sit idle before the core gives it up, in
    /// milliseconds. The core's unit is milliseconds and so is this one.
    idle_timeout_ms: u64 = 30_000,
    /// A NEW_TOKEN for the first Initial. Null sends no token.
    /// The dialer retains this slice for later dials. Keep it alive and
    /// unchanged until `destroy`. Each connection copies the token bytes.
    initial_token: ?[]const u8 = null,
    /// Whether a dial that names no peer is refused.
    ///
    /// True by default, and the answer to the question the core's nullable
    /// pin raises: a connection with no pin verifies nothing, so a caller that
    /// wants one has to write `false` here and say so in the same breath.
    /// Whatever it is, the pin the core was handed is readable back off
    /// `tlsConfigFor`, so no connection can be built that nobody can see is
    /// unpinned.
    require_peer_pin: bool = true,
};
