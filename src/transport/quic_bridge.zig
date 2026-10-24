//! The seam between the vendored QUIC core and this project's transport.
//!
//! The whole surface is re-exported here, so every caller outside
//! `src/transport/` keeps importing one name and no caller changes. The
//! declarations themselves live in five modules named for what they are
//! responsible for, and the split is by responsibility rather than by size:
//!
//! - `bridge_config.zig` — what a caller supplies, and the transport secrets a
//!   caller may leave null.
//! - `bridge_address.zig` — the two address vocabularies meeting.
//! - `bridge_conn.zig` — one connection above a datagram: `Conn`, `Stream`,
//!   `Egress`.
//! - `bridge_ingress.zig` — one datagram in, and what the core did with it.
//! - `bridge_manager.zig` — the vendored `ConnectionManager` and the identity
//!   it presents.
//! - `bridge_peer.zig` — the peer's half of a handshake, for the tests below.
//!
//! # The original module doc, unchanged
//!
// The seam between the vendored QUIC core and this project's transport.
//
//
// What the core is: `vendor/quic/src/`, sans-IO, patched so its clock and
// its randomness are parameters and its peer certificate is a bare 44-byte
// Ed25519 `SubjectPublicKeyInfo`. See `vendor/quic/VENDORED.md`. What it is
// not: anything that owns a socket. It has no syscall seam left to own one
// with.
//
// # The three things that reach the core
//
//
// # What the core does not know about addresses
//
// Four things, all of them found by reading the vendored tree rather than
// assumed, and all of them load-bearing for `base/ula.zig`:
//
//
// 2. **One active path, not N.** `Connection` holds exactly two
//    `NetworkPath`s and indexes one as active (`connection.zig:626`). A
//    datagram from an address that is not the active path's peer address
//    goes to `handleMigration` (`connection.zig:1542`), which makes the
//    second address a *candidate*, challenges it, and promotes it. So the
//    core models one path plus one migration in flight. `ula.Path.any_path`
//    models the opposite: one address every candidate path is reached
//    through, with each datagram duplicated onto each path. `addr_map`'s
//    three subnets therefore name three addresses, and a connection handed
//    all three is a connection the core will read as a migration. This is
//    the largest gap between the two models and it is not fixable in this
//    file.
//
// 3. **The core's path identity includes the port; `ula`'s does not.**
//    `Address.eql` compares family, address, port and scope
//    (`vendor/quic/src/address.zig`); `ula.classify` compares eight octets and
//    ignores the port entirely. Every synthetic address carries
//    `ula.mapped_port`, so the two agree today by construction — but a
//    caller that reached the same /64 on a second port would be invisible
//    to `classify` while the core would see a different path.
//
// 4. **`TlsConfig.expect_peer_node_id` is client-only.** It is read in
//    `clientProcessCertificate` (`tls13.zig:1465`) and nowhere else, and a
//    `ConnectionManager` only ever accepts server connections. The peer pin
//    a server actually enforces is `ClientAuth.expect_node_id`. The
//    translation below sets the one that bites and says so, rather than
//    setting the field that looks like a pin and enforces nothing.
//
// # Why the send side is `transport/batch.zig` and not a second path
//
// The core's egress is `Connection.sendAt(out_buf, now, random)`: it writes
// one datagram into a caller buffer and the caller sends it. `batch.zig`
// already models what a socket is to be asked for — bytes, a segment size,
// a codepoint, and what the socket refused. A core datagram fits that shape
// exactly: it is a contiguous slice of a buffer. The one thing a QUIC burst
// does that the batcher does not want is vary its datagram size inside a
// run, so a run closes at the first datagram that differs from the one
// before it and the rest go out as singles. That is the batcher's own
// fallback (`batch.Send.isSegmented`, `batch.Runs`), not a new one, and it
// is where a burst of equal-sized packets becomes a `UDP_SEGMENT` send.

const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");
const bridge_ingress = @import("bridge_ingress.zig");
const bridge_manager = @import("bridge_manager.zig");

/// See `bridge_config.Config`.
pub const Config = bridge_config.Config;
/// See `bridge_config.CreateError`.
pub const CreateError = bridge_config.CreateError;
/// See `bridge_config.Error`.
pub const Error = bridge_config.Error;
/// See `bridge_config.Instant`.
pub const Instant = bridge_config.Instant;
/// See `bridge_config.spki_length`.
pub const spki_length = bridge_config.spki_length;

/// See `bridge_conn.Conn`.
pub const Conn = bridge_conn.Conn;
/// See `bridge_conn.Egress`.
pub const Egress = bridge_conn.Egress;
/// See `bridge_conn.Stream`.
pub const Stream = bridge_conn.Stream;

/// See `bridge_ingress.Datagram`.
pub const Datagram = bridge_ingress.Datagram;
/// See `bridge_ingress.Ingress`.
pub const Ingress = bridge_ingress.Ingress;
/// See `bridge_ingress.Outcome`.
pub const Outcome = bridge_ingress.Outcome;
/// See `bridge_ingress.Source`.
pub const Source = bridge_ingress.Source;
/// See `bridge_ingress.Tick`.
pub const Tick = bridge_ingress.Tick;

/// See `bridge_manager.Bridge`.
pub const Bridge = bridge_manager.Bridge;
