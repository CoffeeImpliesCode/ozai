//! The vendored sans-IO QUIC + TLS core, as a module root.
//!
//! Upstream `src/lib.zig` re-exported four layers: the sans-IO core, the
//! HTTP/3 and WebTransport protocol layers, a second TLS-over-TCP stack, and
//! the socket-owning event loop. Only the first is here. The other three are
//! gone because they are gone upstream of this module, not because they were
//! left unused — a socket-owning stack is precisely what this project must not
//! have, and HTTP/3 is a protocol ozai does not implement. See VENDORED.md.
//!
//! There is no `sys` re-export. Upstream had one: a syscall seam holding the
//! sockets, the clock and the process CSPRNG behind one import. Every one of
//! its callers are gone, and the file with it. That is the whole claim in one
//! line — the core this project depends on has no seam through which it could
//! reach the operating system, and nothing in it can be made to do so without
//! writing a new file.
//!
//! # The four things every consumer of this module needs to know
//!
//! 1. **Time is a parameter.** Every ingress, egress and timer pass takes
//!    `now: i64`, nanoseconds on a monotonic clock of the caller's choosing,
//!    and the core reads no clock of its own. Two runs started at different
//!    instants are two different runs.
//! 2. **Randomness is a parameter.** Every draw — connection ids, packet
//!    number skips, reset keys, path challenges, token nonces — comes from a
//!    `std.Random` the caller passes in. `std.Random` is an interface over a
//!    pointer to an engine, so the engine has to outlive every value handed
//!    out from it.
//! 3. **Allocators are parameters,** and every allocation a caller gets back
//!    is freed with the allocator that made it. There is no hidden pool and
//!    no global.
//! 4. **Ownership is stated per declaration,** not inherited: a function that
//!    hands back a slice says whether the caller owns it, and a struct that
//!    borrows a caller's bytes says so on the field. The rule the tree
//!    applies is that anything returned across a call boundary is either
//!    owned by the receiver (and freed with the allocator that made it) or
//!    explicitly documented as a borrow valid only until the next call on the
//!    same value.
//!
//! The modules below are the whole public surface. Nothing else in the tree
//! can be named from outside, and a declaration that is not `pub` is not part
//! of a contract this module offers.

/// Addresses and connection ids as the core holds them: a tagged union over
/// the two families with no kernel struct behind it, plus the identity
/// comparisons the transport makes. Everything here is a value; nothing in
/// this module owns a socket or reads a clock.
pub const address = @import("address.zig");

/// The buffer abstraction every encoder and decoder in the tree is written
/// against, so the core depends on no concrete stream type. A reader or
/// writer that runs out of room is an error, never a short write.
pub const io_compat = @import("io_compat.zig");

/// One connection's state machine, its packet-number spaces, its streams and
/// its send path. Built in place by `connectInto`/`acceptInto`: a connection
/// borrows its own connection-id buffers into its transport parameters, so
/// it must not be moved once built.
pub const connection = @import("quic/connection.zig");

/// The server side: routing packets to connections by destination CID,
/// stateless replies, and accepting new ones. Owns every connection it
/// creates and frees them through the allocator it was given.
pub const connection_manager = @import("quic/connection_manager.zig");

/// Wire format: the long and short header, packet-number encoding, the
/// version-negotiation and Retry writers, and the address-validation tokens.
/// A parsed `Header` borrows its connection ids and token out of the buffer
/// it was parsed from.
pub const packet = @import("quic/packet.zig");

/// Frame encoding and decoding. A parsed `Frame` borrows the bytes it was
/// decoded from, and a queued `PendingControlFrame` copies what it must keep.
pub const frame = @import("quic/frame.zig");

/// Packet protection: key derivation, the AEAD and header-protection
/// contexts, and the key-update schedule. `Open` and `Seal` are values that
/// own no allocation, so copying one is cheap and copying it is safe.
pub const crypto = @import("quic/crypto.zig");

/// The AES-128-GCM context the core uses on the hot path, with the key
/// schedule and GHASH powers precomputed once per key.
pub const aes_gcm = @import("quic/aes_gcm.zig");

/// TLS 1.3 for QUIC, including the QUIC transport-parameters extension. The
/// handshake owns its buffers and frees them in `deinit`; the config a
/// handshake borrows (`cert_chain_der`, `alpn`, the client-auth block) must
/// outlive it.
pub const tls13 = @import("quic/tls13.zig");

/// Montgomery arithmetic for the big-integer signing operations.
pub const mont = @import("quic/mont.zig");

/// ECDSA over P-256, used for the X.509 path a node never takes.
pub const ecdsa_p256 = @import("quic/ecdsa_p256.zig");

/// RSA signing, for the same reason.
pub const rsa = @import("quic/rsa.zig");

/// The QUIC transport parameters, both directions. A decoded
/// `TransportParams` borrows the connection ids it carries out of the buffer
/// it was decoded from.
pub const transport_params = @import("quic/transport_params.zig");

/// Stateless resets: the token behind one and the packets that carry it.
pub const stateless_reset = @import("quic/stateless_reset.zig");

/// QUIC-LB connection-id encoding: the config a server encodes its own ids
/// with, and the length rules that config has to satisfy.
pub const quic_lb = @import("quic/quic_lb.zig");

/// ECN validation: the marks to send with and the counts a path has to
/// agree with before it is validated.
pub const ecn = @import("quic/ecn.zig");

/// Streams: reassembly, flow control, retransmission and reclamation. The
/// receive side hands out owned slices (`ReceiveStream.read`), the send side
/// hands out frames that borrow the send buffer.
pub const stream = @import("quic/stream.zig");

/// Congestion control and loss recovery: one algorithm's window, pacing and
/// recovery decisions over the connection's packet ledger.
pub const congestion = @import("quic/congestion.zig");

/// The in-process harness from upstream: it drives `Connection` directly over
/// hand-built socket addresses and opens no socket, so it is the evidence that
/// the core is drivable without one. Kept because this is the property this
/// vendoring exists to preserve.
pub const lossy_link_test = @import("quic/lossy_link_test.zig");