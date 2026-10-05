//! Originating a QUIC connection: the other direction of `quic_bridge.zig`.
//!
//! The whole surface is re-exported here, so every caller outside
//! `src/transport/` keeps importing one name and no caller changes. The
//! declarations themselves live in four modules named for what they are
//! responsible for, and the split is by responsibility rather than by size:
//!
//! - `dial_config.zig` — what a dial is configured with, and what it refuses.
//! - `dial_route.zig` — a target becomes one address and one key.
//! - `dial_client.zig` — the dialer, and the four steps that register a client
//!   connection with the manager it dials through.
//! - `dial_pair.zig` — two bridges and a dialer over one identity pair, for the
//!   tests of the three above.
//!
//! # The original module doc, unchanged
//!
// Originating a QUIC connection: the other direction of `quic_bridge.zig`.
//
// `transport/quic_bridge.zig` owns a `ConnectionManager` that only ever runs
// a server. Until this file existed nothing under `src/` could open one, and a
// P2P stack that cannot dial is a server. Everything here exists to make the
// client half a first-class member of the *same* machinery, so a dialler and a
// listener differ in who starts the connection and in where the first address
// comes from, and in nothing else.
//
// # The loop is the bridge's, not a second copy
//
// `ConnectionManager` has one client arm and it is this one.
// `ConnectionManager.acceptConnection` (`connection_manager.zig:348`) is the
// whole of what it does to admit a connection: build a `Connection`, wrap it
// in a `ConnEntry`, register the connection's own CID in `cid_map`, append the
// entry. `Dialer.open` does the same four steps with `Connection.connectInto`
// in place of `Connection.acceptInto`, and from there the two are
// indistinguishable. `Bridge.recv` routes a reply to it by DCID, `Conn.drain`
// serialises it into `batch.Send` values, `Bridge.tick` runs its timers,
// `Bridge.sweep` frees it, `Bridge.connectionAt` finds it. There is no second
// `recv`, no second `drain` and no second timer pass in this file, and a
// dialled connection is driven by exactly the calls an accepted one is. That
// is the finding, and it is the reason this file is short.
//
// One asymmetry in the registration is real and was read rather than assumed.
// An accepted entry registers *two* CIDs: its own SCID, and the DCID the
// client chose, so retransmitted Initials still route (`connection_manager.zig:394`).
// A dialled entry registers *one*, its SCID, because a peer never sends with
// the DCID we chose — it answers with the CID from our ClientHello. Version
// negotiation needs none of this: `route` answers a VN at
// `connection_manager.zig:549`, before it looks anything up.
//
// What a caller drives, then, is two states and a timer. The core sets
// `.handshake` on the first Initial (`connection.zig:1561`) and clears it to
// `.connected` on the same datagram's later packets (`connection.zig:2559`),
// coalesced into one `recv` — so `.handshake` is not observable from outside
// the core, and a dialled connection is seen going straight from
// `first_flight` to `connected`. The test "a dial runs initiated to connected
// as a function of datagrams and nothing else" pins that trace rather than
// the state machine it was expected to have.
//
// # `io`, the instant and the generator
//
// `Instant` and `std.Random` are parameters of every call that moves the core
// forward, and nothing in this file reads a clock or draws entropy, for the
// reason `quic_bridge.zig`'s module doc gives. `std.Io` is stronger here than
// threaded: **there is no `std.Io` on this path at all.** `Bridge.create` takes
// one because it draws the two transport secrets a caller may leave null; a
// dial draws nothing — a client signs no Retry token and issues no NEW_TOKEN,
// and the one secret a client has is its own seed, which the caller already
// holds in `Config.secret`. A parameter with no work is a parameter a caller
// has to thread for a fiction, so there is not one, and this is the same
// property `docs/DECISIONS/0002` buys from the other side: a dialler driven
// twice at two instants with two generators is two dialler's worth of answers.
//
// # The address, and what the core is told
//
// A dial starts from a target: a direct `SocketAddr`, a `RelayUrl`, or a
// `CustomAddr`. `base/ula.zig` maps the two non-IP arms onto synthetic RFC
// 4193 addresses and `transport/addr_map.zig` memoises them, and both are used
// here — `resolveRoute` is the one place a target becomes an address, and the
// core is told the *socket address* while the caller is handed the *key* it
// stands for. That split is the point: the core gets an address it can hold
// and compare, and the caller gets back the peer and relay or the custom
// bytes it has to open a socket for. `Conn.drain` gives the
// caller an `Egress` carrying only the address, so the address is all the
// socket layer ever sees and `ownerOf` is how it turns one back into a key.
//
// **One target, one address, one connection.** The core holds two
// `NetworkPath`s and indexes one as active (`connection.zig:626`), and a 1-RTT
// packet carrying at least one non-probing frame, from any other address,
// becomes a migration rather than a second path (`connection.zig:1540`). So
// the multipath cost `DECISIONS/0001` records is observable here as a hard one:
// a peer reachable over a relay and a direct path is **two dials**, and the
// caller owns the policy that says which. Nothing in this file can widen it,
// and pretending otherwise would be a second core.
//
// The migration adds no path and queues none either: `handleMigration` writes
// the alternate slot (`connection.zig:3442`) and promotes it (`:3452`), so the
// address that was active is written over rather than kept. The moment the peer
// answers on the second address the first stops being used at all — measured,
// the client sent nothing further to the address it left — which makes a
// second address a hazard on a live connection rather than spare capacity on it.
// Only non-probing frames do this: padding, PATH_CHALLENGE, PATH_RESPONSE and
// NEW_CONNECTION_ID from an address the connection has never heard of are
// answered and otherwise ignored, so an address that has not spoken is never
// discovered and the candidate slot is never filled for one. Nothing in a
// resolved address distinguishes those two kinds, which is why the choice
// belongs to the dial and not to the connection.
//
// Two further things the core does with an address, both found by reading it:
//
// 1. **A dialled connection's first inbound datagram rewrites its path.**
//    `connectInto` leaves `path_initialized` false and `paths` zeroed, and
//    `recv` builds the path from the first datagram it sees
//    (`connection.zig:1533`). So the two addresses `open` writes are what the
//    first flight is sent to and nothing more, and they are written only
//    because `Conn.drain` reads the destination off the active path before any
//    packet has arrived. For a relay that is the right answer — the reply
//    arrives from the relay's real address and the core should keep sending
//    there — and it means the caller's job after the first exchange is to hold
//    a socket for whatever address the core now holds.
// 2. **The synthetic address is never validated.** The core's only
//    address-sensitive policy is `NetworkPath.canSend`
//    (`connection.zig:127`), the server-side anti-amplification limit, and it
//    is guarded by `is_server` at both uses (`connection.zig:3270`, `:3381`).
//    An RFC 4193 ULA is a peer address like any other to a client, which is
//    the answer `DECISIONS/0001` asks for and it is a different answer than
//    the server side's.
//
// # The pin, and the shape that keeps it set
//
// Verification on a dial is `TlsConfig.expect_peer_node_id`, a byte comparison
// of the 32 bytes lifted out of the peer's `SubjectPublicKeyInfo`
// (`tls13.zig:1465`). The mirror of what `Bridge` does with
// `ClientAuth.expect_node_id`. `expect_peer_node_id` is `?` in the core, and
// null is a connection that proves nothing about who is on the other end, so
// two things here are built to make the null case reachable only by naming it:
//
// - The pin is a **parameter of the dial**, not a field of the dialer, because
//   one dialer dials many peers and a config-wide pin would be a pin for
//   whichever peer was named last.
// - `Config.require_peer_pin` defaults to true and `dial` returns
//   `error.NoPeerPin` before it touches the map, so a refused dial allocates
//   nothing at all.
//
// Relay routes require a peer id: `Key.relay` is a `(relay, node)` pair.
// Custom routes use `CustomKey` alone and do not require that id. Setting
// `require_peer_pin = false` therefore permits unpinned direct and custom
// dials, but a relay route still returns `error.NoPeerId`.
//
// One more asymmetry, and the one a caller is most likely to trip on. The pin
// is enforced, but the bytes it was compared against are not kept on this
// side: `clientProcessCertificate` lifts the key out of the peer's
// `SubjectPublicKeyInfo`, compares it and drops the certificate
// (`tls13.zig:1463`), where the server arm of the same handshake is the one
// that copies it (`tls13.zig:2091`). So a dialled connection names its peer
// by node id — `tls13_hs.?.peerNodeId()` — and
// `Connection.peerCertificate()` is null on it even after a handshake that
// verified. The bridge's own test reads the certificate off the *accepted*
// connection, where it is there, and nothing about a dial can read it back.
//
// # What `server_name` means on a dial
//
// It is not a host being verified, and after the M8 certificate patch it could
// not be: the peer certificate is a bare 44-byte SPKI with no name in it, and
// the pin is a 32-byte comparison. Nothing in ozai populates
// `TlsConfig.certs`, so no server here ever calls `selectCertificateFor` and no
// name selects anything. What the field *is* on a dial is the SNI extension
// the client sends, and this project sends `default_server_name` — one
// constant, `"ozai.invalid"`, RFC 2606 reserved so it can never resolve, on
// every dial. It names the protocol, discloses nothing, and is the same bytes
// to every observer.
//
// It is deliberately **not** `NodeId.toLocalTlsName()`. That helper exists and
// is documented in `base/key.zig` as never sent: iroh stopped transmitting it
// in 1.0.3 because it discloses the peer id, and the core's signature takes
// `server_name: []const u8` with no null to opt out with
// (`connection.zig:4540`), so the only lever left is what the bytes are. A
// caller that wants the peer-id label — a future multi-identity bridge
// selecting by SNI, say — sets `Config.server_name` itself, and the field is
// there for that reason rather than as decoration.
//
// # Who owns the socket
//
// Nobody here, and that is a position rather than an omission. `dial` takes
// the caller's `local` address and returns the address to send to; opening the
// socket, waking on a read, and sleeping until the next deadline are the
// caller's. A dial that opened a socket would have to hold it, and a held
// socket is held state with a file descriptor and a lifetime — the same
// objection `endpoint/endpoint.zig` records for `std.Io`, and for the same
// reason. It is also what makes every decision in this file testable without
// one.

const dial_client = @import("dial_client.zig");
const dial_config = @import("dial_config.zig");
const dial_route = @import("dial_route.zig");

/// See `dial_config.Instant`.
pub const Instant = dial_config.Instant;
/// See `dial_config.spki_length`.
pub const spki_length = dial_config.spki_length;
/// See `dial_config.default_server_name`.
pub const default_server_name = dial_config.default_server_name;
/// See `dial_config.Error`.
pub const Error = dial_config.Error;
/// See `dial_config.DestroyError`.
pub const DestroyError = dial_config.DestroyError;
/// See `dial_config.Config`.
pub const Config = dial_config.Config;

/// See `dial_route.Dial`.
pub const Dial = dial_route.Dial;
/// See `dial_route.Route`.
pub const Route = dial_route.Route;
/// See `dial_route.resolveRoute`.
pub const resolveRoute = dial_route.resolveRoute;
/// See `dial_route.ownerOf`.
pub const ownerOf = dial_route.ownerOf;

/// See `dial_client.Dialer`.
pub const Dialer = dial_client.Dialer;
