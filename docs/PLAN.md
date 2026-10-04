# ozai plan

Where this project goes, in the order it should go there, and why that order.

The governing observation: **roughly half of iroh is pure logic over bytes.**
Relay framing, the relay handshake, pkarr signing, ticket encoding, gossip's
HyParView and PlumTree state machines, the range algebra in blobs, the NAT
classifier, the holepunch trigger gate — none of it touches a socket. All of it
is testable without a network, which is exactly the property AGENTS.md §2
demands. The plan front-loads that half and defers the half that needs QUIC.

## The constraints that shape everything

1. **QUIC is the risk, not the work.** iroh 1.3.0 runs `noq`/`noq-proto`/`noq-udp`
   — n0's own QUIC fork with multipath `PathId` and QNT
   (`draft-seemann-quic-nat-traversal-02`) grafted on. There is no QUIC in the Zig
   0.16 standard library, and `std.crypto.tls` ships a client-only driver with no
   server and no raw-key certificate support. M8 is built on a recorded
   decision with a recorded price
   ([`DECISIONS/0001`](DECISIONS/0001-transport-substrate.md)), so this is a
   known cost rather than an open risk. It is still partial, though: the
   vendored TLS negotiates no RFC 7250 certificate type, no external exchange
   has run, the bridge exposes bidirectional streams only and does not enable
   DATAGRAM, and the node has no authenticated 0-RTT.
2. **The TLS handshake is not a detail.** iroh's peer authentication *is* TLS 1.3
   with raw Ed25519 public keys: the certificate is a 44-byte DER
   `SubjectPublicKeyInfo` wrapping the 32-byte node id, in both directions, and
   verification reduces to a byte comparison against the id you expected. That is
   a requirement on the *chosen* QUIC rather than on ozai's own code, and it is
   what eliminated two of the three candidates outright.
3. **I/O is injected at the drivers.** Zig 0.16 threads `io: std.Io` through
   the I/O-capable drivers rather than caching it or reaching for a global.
   `transport/socket.zig` is the Linux bridge: it uses libc for ancillary
   messages, polling and eventfd, and the injected `Io` for cancellation.
   The network state machines remain pure over messages, state and supplied time;
   the real-socket runs are not a claim of whole-endpoint I/O simulation.
4. **Interop is a test, not an intention.** Every wire format below ships with
   bytes captured from the Rust implementation. A claim of compatibility with no
   golden vector attached is an unverified claim and gets deleted.

## Milestones

### M1 — identity and addressing ✅

`src/base/`: `NodeId`, `SecretKey`, `Signature`, `RelayUrl`, `IpAddress`,
`SocketAddr`, `CustomAddr`, `TransportAddr`, `NodeAddr`, and the two base32
alphabets.

Pinned against iroh's own vectors: the all-zero seed yields node id
`3b6a27bc…da29`, DNS label `7dl2ff6emqi…8kg.iroh.invalid`.

Why first: every other milestone serialises a `NodeId` and an ordered
`TransportAddr` set. Getting ordering or encoding wrong here corrupts tickets
everywhere else, and it is the cheapest possible place to be wrong.

**Divergences recorded, not hidden:**

- iroh's `PublicKey::from_bytes` runs a full ed25519 point validation and
  rejects a non-point. Zig 0.16's `Ed25519.PublicKey.fromBytes` only rejects a
  non-canonical `y`. ozai constructs with the weaker check and documents that
  `verifyStrict` is the check to use on any key that arrived from the network.
- iroh's `NodeId::Display` parser accepts hex *or* base32 based on length. ozai
  makes the encoding explicit in the function name (`parseHex`, `parseZ32`,
  `parseLocalTlsName`) so a caller cannot pick by accident.
- The iroh TLS server name uses hex-extended base32 (`0-9a-v`), **not** RFC 4648
  and **not** z-base-32. All three are 52 characters for 32 bytes, so the
  distinction is invisible until a handshake fails. ozai names them separately.

### M2 — wire codecs

A `postcard`-compatible reader and writer, plus varint. postcard is not a
dependency to adopt; it is a byte format to reproduce. In scope:

- varint (`std.math.VarInt` plus a length-prefix helper)
- the postcard field order for every type listed in M3–M6
- `RangeSpec` / `RangeSpecSeq` from iroh-blobs' `range_spec.rs`: alternating
  OFF/ON span widths, with an odd element count meaning open-ended ON
- fuzz the postcard and range decoders, with three properties as the oracle:
  - round-trip: `encode(decode(encode(x))) == encode(x)`, so the pair is a
    fixed point
  - round-trip stability: decoding is order-independent. An encoder is
    canonical, so decoding *any* accepted encoding and re-encoding it yields
    the same bytes — two spellings of one value may not produce two tickets.
  - rejection: arbitrary bytes never panic and never read out of bounds. They
    either decode or land in a declared error; an undeclared one is a bug, not
    a fuzz finding.

### M3 — tickets and discovery records

`EndpointTicket` and `BlobTicket` (the only two ticket kinds iroh 1.3.0 has —
`Node`/`Relay`/`Ping`/`Addrs`/`Share` are gone), plus the pkarr signed packet.

- Ticket text form is `kind` + unpadded base32 of the postcard bytes,
  lowercased **after** the prefix is concatenated. Getting that order wrong is
  silent.
- `BlobTicket` variant 0 flattens a `NodeAddr` back into
  `relay_url + direct_addresses`, which **silently drops `TransportAddr::Custom`**.
  Reproduce the loss, and log it; a round trip that quietly changes the value is
  worse than one that fails.
- pkarr: `[32 pubkey][64 sig][8 BE timestamp µs][DNS packet]`, ≤ 1104 bytes. The
  signature covers the BEP-0044 *signable* form,
  `"3:seqi{ts}e1:v{n}:" ++ dns`, not the raw bytes. Signing raw bytes produces
  packets no pkarr implementation accepts.

### M4 — relay wire protocol, the part below the carrier

The relay is HTTP/1.1 → WebSocket → `[varint frame type][payload]`, derived from
tailscale DERP. Everything below the WebSocket is pure and testable now:

- `FrameType` 0–13, including the v1/v2 split: v2 removed `Health` (11) and
  added `Status` (13), and the server translates between them. Both versions must
  be emittable.
- Version negotiation is a real `max()` over `Sec-Websocket-Protocol`, not
  first-match.
- `Datagrams.segment_size.is_some()` ⇔ batch frame type. `takeSegments` must
  clear `segment_size` when the remainder drops to one datagram; the asymmetry
  corrupts the GSO path.
- The handshake has two paths behind one state machine: key-material
  (zero extra round trips, TLS exporter) and signed challenge (plain HTTP,
  browsers). A failed key-material verify is normal operation, not an error.
- Ping tracker: `clamp(3 × last_rtt, 500 ms, max_timeout)`, and only the most
  recent ping matters.
- Server: the client registry admits once and reports disconnect exactly once
  (`OnDisconnectGuard` is a handle whose `deinit` is the only exit), plus two
  separate queues per connection so a `Status` cannot sit behind a datagram
  backlog.

**Built: the codec and both state machines. Not built: the carrier.** What
carries this in the tree is the private QUIC ALPN `/iroh-relay/1`, not RFC 6455
WebSocket over an HTTP/1.1 upgrade with TLS. There is no production version and
Health/Status translation, no exporter authentication, no ping driver, no
reconnect, no policy ACL or rate limiter, and synthetic relay egress is handed
to UDP rather than routed through the carrier.

### M5 — address lookup

`AddressLookup` is a two-method trait where `resolve` returns a **stream**, and
returning `None` means "cannot resolve at all". Dropping the stream must cancel
its work. There is no `DiscoveryItem` enum any more: results are `Item` structs
tagged by `provenance`.

In tree: `PkarrPublisher`, `PkarrResolver`, `DnsAddressLookup`. mDNS and the
Mainline DHT are external crates upstream, and in ozai they are simply more
implementations of the same interface.

Ordering: timestamp, node id, address value via `TransportAddr.order`, then
provenance. A total order prevents arrival-dependent results.

Built as codecs and pure resolvers. Not built: the A/AAAA path, the TCP retry
the TC bit calls for, the live pkarr HTTP transport, the publication timer, or
any production source fan-in. A timeout is not an empty answer, and
`error.Truncated` is the RFC 1035 TC bit rather than either of them.

### M6 — net report and NAT classification

`mapping_varies_by_dest_*` is the actual classifier: two probes to *different*
relays returning *different* public addresses means destination-dependent
mapping, and holepunching gets much harder. The fold from probe results to a
report is pure arithmetic over timestamps and latencies.

`UserData` caps at 245 bytes for a reason worth writing down: a DNS TXT character
string is capped at 255 and `user-data=` costs 10.

Built as the fold and the classifier. Not built: any real probe transport, the
live QAD or captive-portal probe, or the interface and network-change watcher.

### M7 — the transport seam

The synthetic-ULA map. A QUIC stack speaks IP and nothing else, so iroh dresses
relay and custom paths up as RFC 4193 unique local addresses and remembers
which key owns which address. One connection then carries a relay path and N
direct paths with no change to the QUIC stack at all.

```
fd15:070a:510b:0000::/64   the peer, path not yet chosen  (subnet 0000)
fd15:070a:510b:0001::/64   one (peer, relay) pair        (subnet 0001)
fd15:070a:510b:0003::/64   one custom transport address  (subnet 0003)
fd15:070a:510b:0000:ffff:ffff:ffff:ffff  the default fake address
port 12345 on all of them
```

Two halves, and the milestone is honest about which is done.

**Done: the pure half, vector-pinned.** `src/base/ula.zig` builds the /64
prefix, attaches the mapped port, carries the default fake address, and
classifies an address that arrives off the wire — upstream's
`From<SocketAddr> for MultipathMappedAddr`, which tries the endpoint-id subnet,
then relay, then custom, and falls through to `Ip` for anything else,
including all of IPv4. Every constant is a byte captured from
`iroh/src/socket/mapped_addrs.rs` at iroh `1.3.0`, commit
`187f59e80afdae6bd9866002b33d3365c00b06d8`, and the golden vectors sit next to
them. A direct IP path is **not** mapped: it is already a socket address and
upstream types it `MultipathMappedAddr::Ip`.

**Done: the allocation.** Upstream fills the eight host bits from
`rand::rng()` and memoises both directions in an `AddrMap` behind a `Mutex`. It
is not a derivation from the node id and upstream makes no such claim; stability
comes from the map. ozai injects the host bits instead — a deliberate
divergence, recorded under "Divergences from upstream" in
[`ARCHITECTURE.md`](ARCHITECTURE.md) — so that the map stays deterministic and
the seam can be tested. The map itself is transport-layer state, and it landed
with the transport: `src/transport/addr_map.zig` is that map with the entropy
injected and no `Mutex`, and [`TODO.md`](../TODO.md) lists it under M7 Done.

Get the /l, the global id, or a subnet discriminator wrong and two paths to one
peer land on one address with no error anywhere: the receiver has no way to tell
them apart.

### M8 — the QUIC substrate ✅

**Built 2026-09-30, and still partial: the open list below has four items.** The
decision and its price
in [`DECISIONS/0001`](DECISIONS/0001-transport-substrate.md); the
[execution record](DECISIONS/0001-transport-substrate.md#execution-record-of-2026-09-30)
says what was built, what it cost against what was predicted, and what was not
finished.
The substrate is quic-zig; the price came in at roughly double what the first
version of the record implied. The cost accepted with the decision is the loss
of native multipath, mitigated by M7's synthetic-ULA map at the price of
slower convergence.

**What is in the tree.** `vendor/quic/`, vendored from
`endel/quic-zig@14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` — 33 `.zig` files.
The `quic` module is declared in `build.zig`, and its suite runs under
`zig build quic-test`.

**Consumed from `src/` since M9.** The module is no longer compiled and left
alone. `transport/quic_bridge.zig` drives it as a server, and
`transport/dial.zig` opens the client half `ConnectionManager` has no arm for;
`discovery/dial_source.zig` imports it in its own test harness, where a dial is
closed against a bridge that answered.

The socket-owning layers were **never copied** — `event_loop.zig` (5,211 lines),
`ecn_socket.zig` (584), `http1/socket.zig` (364), `http1/timers.zig` (194),
`xev_backend.zig` (31) and `http1/e2e_test.zig` (759) — and neither did `h3`,
`webtransport`, `h0`, `moq`, `http1` or the second TLS-over-TCP stack. That is
why the module needs no `xev`, why `build.zig.zon`'s `.dependencies` is empty,
and why the tree has never had a window in which it owned a socket. Deleted
after vendoring, because something else stopped needing them: `qlog.zig` (411
lines, it wanted a clock and an I/O sink), `tls/test_certs.zig` and
`quic/ca_bundle.zig` (fixtures and trust anchor for a chain walk that is gone),
`Connection.send` (it read the clock itself; `sendAt` already took the
timestamp) and `sys.test_clock`, the mutable global that made the library
deterministic only under `zig build test`. **`rsa.zig` stayed**: RSA is still a
legal TLS 1.3 CertificateVerify signature scheme, which is a different thing
from the certificate being an Ed25519 key.

**The order changed, and that is the point worth keeping.** The first version of
this milestone had two steps and neither of them was the threading. The socket
layer stopped being a step at all — it was never vendored — so what actually ran
was two phases, threading first and the certificate patch second. Threading had
to come first because a core that reads its own clock cannot be stepped at all,
and because a simulated handshake is the only cheap way to drive certificate
gates exhaustively rather than once. Leaving it out was the decision record's
most expensive error, and it is why the record now carries it as its own phase
instead of a line inside the certificate work.

60 hidden-input call sites — 34 clock, 26 CSPRNG — became two parameters: `now:
i64`, a monotonic instant the caller read, and `random: std.Random` **by
value**, because a handshake holding a pointer could be driven twice from one
generator. Both public entry points changed shape with them, to
`recvDatagram(bytes, from, local, ecn_val, out_buf, now, random)` and
`sendAt(out_buf, now, random)`. `src/sys.zig` went with them: split, emptied to
the clock and entropy alone, then deleted, so the module has no file through
which it could reach the operating system.

The certificate work came out the other way from what was planned. It does not
split the `skip_cert_verify` bit and leave the chain walk behind the flag; it
**deletes the walk**. `certificateWellFormed`, `Certificate.parse`,
`verifyHostName`, `verifyPeerChain`, `clientLeafUsageOk`, the extension parsers
and `ChainError` are gone, and `skip_cert_verify`, `ca_bundle` and `keylog_file`
went with them. A bare 44-byte DER `SubjectPublicKeyInfo` is the only accepted
peer certificate, in both directions, compared byte for byte against
`TlsConfig.expect_peer_node_id` or `ClientAuth.expect_node_id`. Both
CertificateVerify checks are now unconditional, and an Ed25519 signature draws
no nonce at all.

**Still open, and recorded as open rather than closed:**

- **0-RTT.** `session_ticket` and `ticket_key` must be stable across every
  client-config construction or resumption silently stops matching. The
  certificate patch did not discharge it and M8 did not touch it.
- **Interop, and with it requirement 3.** The matrix `DECISIONS/0001` leaned on
  was upstream's, run at a different commit, and is not reproducible from this
  repository — upstream's runner is a git submodule outside the published
  package. M8 did not re-run it, so requirement 3 is re-established against
  this fork or not at all.
- **RFC 7250.** The vendored TLS writes the 44-byte Ed25519 SPKI certificate but
  negotiates no client or server certificate type, and upstream's raw-key
  resolver and verifier require that negotiation. The fix is in the ClientHello
  offers and the TLS 1.3 EncryptedExtensions selections, fail-closed parsing,
  captured wire vectors, and a live Rust partner in both directions — not in
  ServerHello and not in CertificateRequest.
- **A recorded resumption deviation.** Pinned-client resumption requests a fresh
  client certificate after PSK selection and fails closed through
  `serverIdentityEstablished`. That is an added RFC 8446 deviation and an
  additional compatibility limitation; it is not an identity bypass, and it is
  not a guard to restore.

**One divergence to know before touching TLS.** `Tls13Handshake.step` takes
`now_s`, and it is a second on the **caller's** clock, not the epoch. The
connection hands it a monotonic instant. Nothing may compare it against an
epoch-derived quantity: it is only ever differenced, and only inside one
process. See the execution record.

**Upstream does not compile on Zig 0.16.0.** Its `build.zig.zon` claims
`minimum_zig_version = "0.16.0"` and its `src/sys.zig:513` passes `posix.errno`
an `@bitCast`ed `isize` where a `c_int` is wanted. So the "drop the fork and
consume the dependency directly" exit is not open today; the revisit triggers in
`DECISIONS/0001` say so and say when it reopens.

### M9 — endpoint, router, connection

- `Router` is an ALPN → handler table. ALPNs are application-chosen byte
  strings; registration order is the server's preference order. The one
  iroh-internal ALPN is `/iroh-qad/0`.
- `ProtocolHandler` in Zig is a vtable: `{ ptr, on_accepting, accept, shutdown }`.
  `accept` runs on its own task and may be long-lived; shutdown waits for the
  handlers, then cancels the accepts, then closes the endpoint, in that order.
  On `accept` failure the connection is dropped with a warning and **no error
  code is sent** — reproduce that, and document it, because it is a behavioural
  quirk, not an oversight.
- `IncomingFilter` runs before the handshake completes. `Retry` on a direct path
  is QUIC source-address validation; on a relay there is no address to validate,
  so it is purely a cost-imposition filter. Same verb, two meanings.
- Graceful close is mandatory: dropping an `EndpointInner` without `close()` is
  an error, not a cleanup.

Retry is refused because no hook runs before `acceptConnection` in the vendored
core, the node admits one ALPN, and the CLI's exceptional close path does not
reach the protected wind-down.

### M10 — NAT traversal

Holepunching is not an application protocol. It is one call into the QUIC stack
(`initiate_nat_traversal_round`); relay and direct are two paths on one
connection. What ozai owns is the gate around it:

- Re-punch only when a **new** local or remote candidate address appears.
  Otherwise honour the 5 s interval. Punching on every wakeup floods the relay
  and never converges.
- Error classification is load-bearing: `Multipath` and `NotEnoughAddresses`
  retry in 100 ms; `Closed`, `TooManyAddresses`, `WrongConnectionSide` and
  `ExtensionNotNegotiated` are fatal.
- Prune `Unusable` paths first and always. Keep at most 10 previously-successful
  `Inactive` paths, out of 30 non-relay paths per peer. A burst of untested
  address-lookup results must not evict the paths that work.
- A selected relay path is not a reason to stop trying to punch.

All of the above is pure over state, and therefore testable before QUIC exists.

The gate is the whole of what exists. Three of the seven inputs have producers;
four do not — the connection to punch on, the QUIC round result, whether a path
carried traffic, and the socket's interface addresses — and no action can start
a real QNT round, because QNT is absent from the vendored core. Increasing the
two-path array does not create per-path congestion control, packet numbers,
RTT, validation, ECN or egress selection.

### M11+ — compose protocols

`iroh-blobs` (ALPN `/iroh-bytes/4`, bao content-addressed transfer) and
`iroh-gossip` (ALPN `/iroh-gossip/1`, HyParView membership + PlumTree broadcast).

Gossip first, and for a reason worth stating: the whole protocol is I/O-free.
`proto/sim.rs` upstream is a deterministic in-process network, and re-implementing
that simulator is the correct first test — two Zig nodes must agree with the
reference on membership convergence, not merely exchange bytes.

Its hard invariants:

- HyParView's active view is bidirectional, and upstream **deliberately deviates
  from the paper** by sending `Neighbor` instead of inserting the peer, so a
  peer joins the active view only after it replies. Two implementations that
  insert eagerly will diverge from the reference on the simulator.
- PlumTree's `MessageId` is `blake3(content)` with no domain separation, and
  every received `Gossip` is re-validated; a spoofed id is dropped without
  penalising the peer.
- `TopicId` is 32 opaque bytes supplied by the application. There is no topic
  derivation, no public/private scope, and no encryption upstream. Privacy has to
  be layered above, and ozai should say so rather than invent a scheme.
- Actor event ordering is biased and fixed. Reordering the arms changes
  observable behaviour under load.

**Not built yet, and self-interoperation does not stand in for it.** There is no
production gossip codec: the encoder used by the loopback test inverts the
`DeliveryScope` tags, upstream emits Swarm before Neighbors, and that codec
cannot become the production one unchanged. `plumtree.max_content` is 1024
bytes against upstream's 4096-byte default. The peer-ID connection index,
bounded per-topic routing and the real send and disconnect actions are absent —
production gossip counts `send_message` and `disconnect_peer` without
performing either.

Blobs: the framing is type-dependent (Get/GetMany/Observe consume the stream to
EOF; Push is varint-length-prefixed with bao data following on the same
stream), all ranges are in 1024-byte BLAKE3 chunks with a 16384-byte block size,
and **missing data is EOF, not an error frame**.

**Not built yet.** Framing and range algebra are done. The Bao tree, the proof
and root verifier, the store and any production provider or getter are not, so
no getter verifies content; collections, tags and GC, resume, Observe and Push
are all absent.

`iroh-willow` and `iroh-docs` stay outside the project rather than waiting for
the transport, and two of the earlier descriptions of them were wrong.
`iroh-docs` is signed-entry range-based reconciliation over signed entries and
byte ranges, not a Loro-backed implementation. `iroh-willow`'s Rust generation
and its group choice are not the current Willow specification's defaults, so one
implementation's parameterization is not evidence about the protocol. A line
count for either crate is not an argument for porting it to Zig.

## Open work, in dependency order

Planned, not started, and none of it is a claim about the tree as it stands.
Each wave's acceptance is something a caller or a peer can observe; a count of
tests is not acceptance.

### Wave 0 — runtime safety and an honest baseline

1. Replace the production generator with a full-strength CSPRNG seeded from an
   injected `Io.randomSecure`, covering TLS ephemeral scalars, relay admission
   challenges and every cryptographic nonce and id draw, keeping deterministic
   simulation behind explicit test seams.
2. Protected exceptional wind-down around the CLI driver: preserve the original
   error, attempt the close where I/O permits, release resources once.
3. Bound accepted connection-id tracking at the reap and expiry boundaries.
4. Make native, portable and core verification reachable from one documented
   entry point with the overlapping roots labelled separately, run both safety
   modes explicitly, resolve the four recorded lint findings, and carry each
   static-analysis disposition as gate policy instead of as suppression.

Acceptance: equivalent production sessions never repeat an ephemeral key or an
admission challenge while deterministic replay remains a simulation input;
invalid signatures and a captured reply for another challenge are refused;
forced post-creation errors reach closed teardown; sequential connection churn
leaves bounded tracking; a failure in each required suite and mode fails the
documented gate; a wrong-scope or duplicate expected error log fails the runner.

### Wave 1 — the endpoint contract, proved against Rust

A minimal Rust partner locked to iroh 1.3.0, with no container dependency.
Capture the current mixed-peer handshake and a failing RFC 7250 regression
before the repair, then implement certificate-type negotiation in both roles.
Prove mutual NodeId authentication, wrong-peer rejection, ALPN
selection and refusal, and application bytes in both directions. Add the
pre-accept Retry hook with token validation and the already-validated filter
behaviour; expose uni-stream and datagram operations with explicit limits and
ownership; and replace the single-ALPN runtime restriction with bounded
configured ALPN selection and per-protocol task routing over the existing pure
router, migrating every caller.

Acceptance: ozai→Rust and Rust→ozai handshake and transfer, captured immutable
wire vectors, negative identity, ALPN and certificate-type tests, Retry
validation, stream and datagram boundary behaviour, several ALPN handlers with
correct dispatch, wrong-protocol refusal and independent close lifetimes.
Self-interoperation is not enough.

### Wave 2 — independent vertical slices over one shared I/O seam

One resolver/TCP/HTTPS owner first: A/AAAA, certificate trust, cancellation,
and the DNS TC → TCP retry with staggering. Relay hostnames and pkarr HTTPS both
consume it. The leaves below then develop in parallel and share no files; one
integration owner edits the shared node and root.

- **A, the standard relay carrier.** RFC 6455 WebSocket binary messages over the
  HTTP upgrade and the TLS seam — `GET /relay`, `Upgrade: websocket`, version 13,
  accept-key, masking and framing, `iroh-relay-v1|v2` negotiation — with
  Health/Status translation, exporter or signed-challenge authentication, ping,
  restart and reconnect, configured access policy, and synthetic relay egress
  mapped through the carrier instead of sent to UDP. Acceptance: a Rust client
  against an ozai server and the reverse where server parity is claimed, an
  authenticated inner QUIC session through the relay with direct UDP blocked
  transferring application bytes, and v1/v2 refusal and translation, queue
  pressure, ping timeout, restart and exact-once disconnect covered. A renamed
  private ALPN or an outer opaque datagram cannot pass it.
- **B, discovery and network producers.** DNS TXT and pkarr publish, resolve,
  republish, source fan-in and live probe execution over that seam, plus the
  production/staging N0 preset with relay-only publication by default. The
  pinned `iroh-dns` tree is the behavioural referent, not a dependency to add.
  Acceptance: a locally controlled Rust DNS and pkarr service supplies signed
  endpoint addresses an ozai node resolves and dials; signer rejection;
  timeout, empty result and the TC bit kept distinct; cancellation; republish;
  relay-only default publication; and real probe outcomes with no fakes.
- **C, gossip wire and actor integration.** One production postcard codec
  carrying the field order upstream emits, replacing the test-only encoder; the
  peer-ID connection index, bounded per-topic routing, and real send and
  disconnect actions. The captured-reference membership, convergence and
  broadcast expectations already in `src/gossip/` are the floor and are
  preserved, Neighbour/reply admission included; upstream's randomized
  iteration and different PRNG mean event-for-event trace equality is not
  claimed. Acceptance adds captured wire vectors and a mixed Rust/Zig
  multi-node broadcast over real sockets, with topic event order, disconnect
  cleanup, duplicate handling and message-size boundaries preserved. Counters
  alone cannot pass.
- **D, Bao and blob transfer.** The BLAKE3/Bao tree, outboard, range and size
  proof processing, and fail-closed verification before any production getter
  reports success; then owned storage and provider/getter drivers. Acceptance:
  captured bao-tree vectors, valid mixed-peer transfers, corrupt, truncated,
  proof, root and range rejection, exact missing-data EOF semantics and
  allocation/I/O failure cleanup; then collections, tags and GC, resume,
  Observe and Push as separate slices with permission and ownership tests.

### Wave 3 — automatic reachability, not a better punch gate

Reopen `DECISIONS/0001` before claiming automatic NAT traversal and compare a
real per-path extension of the fork against a verified alternative; an
available alternative is not assumed to meet Zig 0.16 and raw-key requirements.
Required surfaces: per-path identity and state, observed-address reporting, the
relay-role QAD service and its client, QNT round initiation and results,
interface and network-change input, biased-RTT selection and pruning, and
bounded ordered candidate dialing instead of the current single-target policy.
All seven holepunch inputs get real producers. Acceptance: independent peers
behind controlled NATs showing relay fallback, transition to direct traffic,
new-address and retry behaviour, traffic-aware pruning and interface changes,
with congestion, RTT and ECN state preserved across simultaneous paths. A
loopback transfer has no NAT and cannot prove this wave. Wave 2's inner-QUIC
routing is its prerequisite.

### Wave 4 — authenticated resumption and release evidence

Node-level resumption only after standards-compatible peer identity and stable
session-store ownership are proven. Replace the post-PSK certificate flight
with an RFC-compatible authenticated design, or fall back to a full handshake
while a pin is required; never weaken `serverIdentityEstablished` and never
accept an unbound ticket. Acceptance: resume to the correct peer, reject
cross-peer, ALPN and version misuse and forbidden early data, keep the
authenticated identity on resumed sessions, define application replay
acceptance, run Debug and ReleaseSafe with the bounded decoder fuzz, publish the
current portable, native and core cross surveys with build-only and failed cells
labelled honestly, and check against independent QUIC implementations.

Only then are optional bindings, browser support, extra lookup transports,
content discovery and RPC scheduled.

## What is deliberately not planned

- **A QUIC implementation.** If M8 resolves against writing one, this document
  changes and the reason gets recorded in DECISIONS/0001.
- **An HTTP/3 client.** iroh does not have one and ozai does not need one. This
  is not a decision against HTTP: the standard relay carrier is WebSocket over
  an HTTP upgrade with TLS, and discovery publishes and resolves over HTTPS.
  Both are Wave 2 work, not exclusions.
- **CAR files.** iroh-blobs uses its own Collection format now.
- **Backward compatibility.** No iroh 0.x ticket layouts, no deprecated ALPN
  aliases, no shims. Delete rather than deprecate.
- **`iroh-docs` and `iroh-willow`.** Excluded rather than deferred, with the
  corrections recorded under M11+.
- **RPC and application layers.** `irpc`/`irpc-iroh` and the older
  `quic-rpc`, content discovery, share and services, and bindings for Rust, JS,
  Python, Swift, Kotlin, C or Go are deferred until a verified endpoint and
  ownership contracts exist. They sit above this transport, not inside it.
- **Browser, alternate lookup and alternate transport carriers.** WASM/browser
  reachability, mDNS, the Mainline DHT, and custom Tor, Nym or BLE transports
  are deferred for the same reason. A `CustomAddr` value is not a live
  transport implementation, and an address codec is not a carrier.
