//! QUIC configuration in the transport's vocabulary and its translation to the core.
//!
//! Identity storage and ALPN withdrawal belong to the bridge. This module
//! retains no I/O handle, clock, random generator, or identity storage.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const retry = @import("retry.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;

/// Maximum number of protocols in an offer; longer lists are refused, not truncated.
pub const max_alpns: usize = 8;

/// The longest protocol name this stack can select, in bytes.
///
/// Read off the core's own selection storage rather than restated as a
/// literal, so the bound cannot drift from the buffer a selection is written
/// into. The vendored constant behind it (`negotiated_alpn_len_max`,
/// `tls13.zig:915`) is private to that tree; the field it sizes is public and
/// is where the core records what it chose.
///
/// **This is not RFC 7301 §3.1's 255-byte offer ceiling.** That ceiling bounds
/// what may be *offered* and the core's `buildClientHello` writes any name its
/// length byte encodes, so nothing here claims to bound the wire. It bounds
/// what this stack could ever *negotiate*: the server's walk skips an entry it
/// cannot hold whole (`tls13.zig:3099`) because a prefix of a name is a
/// different protocol, and a client refuses a selection too long to record
/// (`tls13.zig:4020`). A longer name is therefore refused here rather than
/// offered, since an offer that can never be answered is not an offer.
pub const max_alpn_name_len: usize =
    @typeInfo(@FieldType(quic.tls13.Tls13Handshake, "selected_alpn")).array.len;
comptime {
    // 32 is also the number `quic_bridge.retired_alpn` is written against — a
    // withdrawal sentinel must stay longer than a selection — so this states
    // the relationship once instead of leaving two literals to agree.
    std.debug.assert(max_alpn_name_len == 32);
}

/// DER Ed25519 SubjectPublicKeyInfo size, without a certificate chain or host name.
pub const spki_length = quic.tls13.ed25519_spki_len;

/// Refusals shared by bridge creation and the dialer's ALPN configuration.
///
/// Every one of them is decided from the offer list before either creator
/// allocates, copies, or draws anything. See `validateAlpns`.
pub const AlpnError = error{
    /// More than `max_alpns` protocols, refused before any allocation.
    TooManyAlpns,
    /// No protocol to negotiate: an empty list, or an entry whose name is
    /// empty.
    ///
    /// RFC 7301 §3.1 types a `ProtocolName` as `1..2^8-1` and forbids an empty
    /// string outright. An empty entry is worse than useless here, because it
    /// is what a handshake that has not chosen yet reports
    /// (`tls13.zig:2040`) — a name that could not be told apart from the
    /// absence of a negotiation.
    NoAlpn,
    /// A name longer than `max_alpn_name_len`, which this stack can offer but
    /// never select, and so could never be the protocol a connection runs on.
    AlpnNameTooLong,
};

/// Bridge construction failures, preserving entropy and cancellation separately.
pub const CreateError = AlpnError || error{
    /// The caller's allocator refused the bridge.
    OutOfMemory,
    /// The supplied `std.Io` has no secure entropy source for an unsupplied key.
    EntropyUnavailable,
    /// The caller canceled secure key generation; this is not an entropy failure.
    Canceled,
};

/// Checks one offer list on every axis it can be wrong on, before anything is
/// allocated or copied.
///
/// This is the whole of the ALPN policy, so bridge creation and the dialer
/// cannot drift apart on it: both call this before their first allocation,
/// which is what makes a refusal leave no identity storage behind it and no
/// truncated or unselectable list for the core to see. It borrows nothing and
/// keeps nothing; the caller still owns every byte of `alpns`.
pub fn validateAlpns(alpns: []const []const u8) AlpnError!void {
    if (alpns.len == 0) return error.NoAlpn;
    if (alpns.len > max_alpns) return error.TooManyAlpns;
    for (alpns) |name| {
        if (name.len == 0) return error.NoAlpn;
        if (name.len > max_alpn_name_len) return error.AlpnNameTooLong;
    }
}

/// Configuration supplied to bridge creation in the transport's vocabulary.
///
/// ALPN entries borrow caller storage; identity and TLS storage are owned by
/// the bridge rather than by this value.
pub const Config = struct {
    /// Identity seed used to build the presented certificate and its node id.
    secret: SecretKey,
    /// Required peer identity when known before the handshake.
    ///
    /// A pin demands and verifies a certificate even if
    /// `require_peer_certificate` is false. Null does not mean any peer:
    /// `require_peer_certificate` still requires proof of the presented key.
    expect_peer: ?NodeId = null,
    /// Whether a peer must present a certificate when no pin is configured.
    ///
    /// True by default because an address identifies a path, not a peer.
    /// False permits an anonymous peer only when `expect_peer` is also null.
    require_peer_certificate: bool = true,
    /// Protocols in preference order; creation refuses an offer it could not
    /// negotiate, by name.
    ///
    /// At most `max_alpns` entries, each between 1 and `max_alpn_name_len`
    /// bytes; `validateAlpns` decides all of it before creation allocates,
    /// copies, or draws a secret. The outer slice is borrowed only during
    /// creation and copied into bridge storage. Each entry remains borrowed
    /// for the bridge's lifetime because the core's TLS configuration points
    /// at it, and nothing here copies the bytes behind one.
    alpns: []const []const u8,
    /// Idle timeout advertised to the core, which uses the same millisecond unit.
    idle_timeout_ms: u64 = 30_000,
    /// Secret signing Retry tokens and NEW_TOKENs; null draws from creation's `io`.
    retry_token_key: ?[retry.key_length]u8 = null,
    /// Stateless-reset secret; null draws from the same caller-supplied `io`.
    /// Every connection on the bridge advertises tokens under this one key.
    static_reset_key: ?[retry.key_length]u8 = null,
    /// Answer Initials without a valid token with Retry rather than accepting them.
    /// A valid token is honored whether or not this policy is enabled.
    require_retry: bool = false,
    /// Retry once this many connections are live; null disables the threshold.
    retry_threshold: ?usize = null,
    /// Advertised DATAGRAM frame size including its type and length fields.
    /// Null advertises no DATAGRAM support, not an unlimited size. Both ends
    /// must advertise support before a connection can send datagrams.
    max_datagram_frame_size: ?u64 = null,
    /// Initial peer-initiated unidirectional-stream limit; null uses the core's 100.
    /// MAX_STREAMS can raise this bound after connection establishment.
    initial_max_streams_uni: ?u64 = null,
    /// Initial receive window on each peer-initiated unidirectional stream.
    /// Null uses the core's 1 MiB default; MAX_STREAM_DATA can raise the window.
    initial_max_stream_data_uni: ?u64 = null,
};

/// Whether a connection must present a certificate: a pin always demands one.
/// Only an unpinned configuration explicitly disabling certificates accepts anonymity.
pub fn demandsPeerCertificate(config: Config) bool {
    return config.expect_peer != null or config.require_peer_certificate;
}

/// Translates transport settings without changing the core's optional semantics.
/// The manager's Retry key is also the connection's NEW_TOKEN key. Null stream
/// limits resolve to the core's defaults of 100 streams and 1 MiB per stream.
pub fn connectionConfig(
    config: Config,
    retry_token_key: [retry.key_length]u8,
) quic.connection.ConnectionConfig {
    return .{
        .max_idle_timeout = config.idle_timeout_ms,
        .token_key = retry_token_key,
        .max_datagram_frame_size = config.max_datagram_frame_size,
        // The core's non-optional stream count defaults to 100 (connection.zig:926).
        .initial_max_streams_uni = config.initial_max_streams_uni orelse 100,
        // The core's receive window defaults to 1 MiB (connection.zig:917).
        .initial_max_stream_data_uni = config.initial_max_stream_data_uni orelse 1_048_576,
    };
}

/// Returns the supplied key or draws secure entropy through the caller's `io`.
/// `io` is not retained. An unsupplied key can fail with `error.EntropyUnavailable`
/// or `error.Canceled`, preserving each failure's own meaning; no key escapes on error.
pub fn drawKey(io: std.Io, supplied: ?[retry.key_length]u8) CreateError![retry.key_length]u8 {
    if (supplied) |key| return key;
    var drawn: [retry.key_length]u8 = undefined;
    io.randomSecure(&drawn) catch |err| switch (err) {
        error.EntropyUnavailable => return error.EntropyUnavailable,
        error.Canceled => return error.Canceled,
    };
    return drawn;
}
