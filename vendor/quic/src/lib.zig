// The vendored sans-IO QUIC + TLS core, as a module root.
//
// Upstream `src/lib.zig` re-exported four layers: the sans-IO core, the
// HTTP/3 and WebTransport protocol layers, a second TLS-over-TCP stack, and
// the socket-owning event loop. Only the first is here. The other three are
// gone because they are gone upstream of this module, not because they were
// left unused — a socket-owning stack is precisely what this project must not
// have, and HTTP/3 is a protocol ozai does not implement. See VENDORED.md.
//
// There is no `sys` re-export. Upstream had one: a syscall seam holding the
// sockets, the clock and the process CSPRNG behind one import. Every one of
// its callers is gone, and the file with it. That is the whole claim in one
// line — the core this project depends on has no seam through which it could
// reach the operating system, and nothing in it can be made to do so without
// writing a new file.

pub const address = @import("address.zig");
pub const io_compat = @import("io_compat.zig");

pub const connection = @import("quic/connection.zig");
pub const connection_manager = @import("quic/connection_manager.zig");
pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const crypto = @import("quic/crypto.zig");
pub const aes_gcm = @import("quic/aes_gcm.zig");
pub const tls13 = @import("quic/tls13.zig");
pub const mont = @import("quic/mont.zig");
pub const ecdsa_p256 = @import("quic/ecdsa_p256.zig");
pub const rsa = @import("quic/rsa.zig");
pub const transport_params = @import("quic/transport_params.zig");
pub const stateless_reset = @import("quic/stateless_reset.zig");
pub const quic_lb = @import("quic/quic_lb.zig");
pub const ecn = @import("quic/ecn.zig");
pub const stream = @import("quic/stream.zig");
pub const congestion = @import("quic/congestion.zig");

/// The in-process harness from upstream: it drives `Connection` directly over
/// hand-built socket addresses and opens no socket, so it is the evidence that
/// the core is drivable without one. Kept because that is the property this
/// vendoring exists to preserve.
pub const lossy_link_test = @import("quic/lossy_link_test.zig");
