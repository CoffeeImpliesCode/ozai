//! The vendored sans-IO QUIC + TLS core, as a module root.
//!
//! Upstream `src/lib.zig` re-exported four layers: the sans-IO core, the
//! HTTP/3 and WebTransport protocol layers, a second TLS-over-TCP stack, and
//! the socket-owning event loop. Only the first is here. The other three are
//! gone because they are gone upstream of this module, not because they were
//! left unused — a socket-owning stack is precisely what this project must not
//! have, and HTTP/3 is a protocol ozai does not implement. See VENDORED.md.
//!
//! The core owns no sockets and reads no clock or process entropy. The caller
//! supplies those inputs. Diagnostics may use `std.log`; cryptographic helpers
//! may maintain an internal synchronized cache.
//!
//! # The four things every consumer of this module needs to know
//!
//! 1. **Time is a parameter.** Every ingress, egress and timer pass takes
//!    `now: i64`, nanoseconds on a monotonic clock of the caller's choosing,
//!    and the core reads no clock of its own. Two runs started at different
//!    instants are two different runs.
//! 2. **Randomness is a parameter.** Every draw — connection ids, packet
//!    number skips, reset keys, path challenges, token nonces — comes from a
//!    `std.Random` the caller passes in. Its engine must remain live and unmoved
//!    while a call uses it; drawn bytes do not borrow the engine.
//! 3. **Allocators are explicit.** Owners retain the allocator stated in their
//!    contract and release allocations through that allocator.
//! 4. **Ownership is stated per declaration,** not inherited: a function that
//!    hands back a slice says whether the caller owns it, and a struct that
//!    borrows a caller's bytes says so on the field. Each borrow has its own
//!    invalidation rule; a later call does not invalidate every view.
//!
//! These exports are supported consumer routes. Returned types and accessible
//! struct fields are also part of their contracts, regardless of field spelling.

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

/// Packet protection: key derivation, AEAD, header protection and key updates.
/// `Open` and `Seal` have inline state and no allocation; copies are independent.
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

/// ECDSA P-256 signing and verification for configured TLS identities.
pub const ecdsa_p256 = @import("quic/ecdsa_p256.zig");

/// RSA signing and verification for configured TLS identities.
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
