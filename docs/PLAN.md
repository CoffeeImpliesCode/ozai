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
   known cost rather than an open risk — with interop and 0-RTT named as still
   open under M8.
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

### M4 — relay wire protocol

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

### M6 — net report and NAT classification

`mapping_varies_by_dest_*` is the actual classifier: two probes to *different*
relays returning *different* public addresses means destination-dependent
mapping, and holepunching gets much harder. The fold from probe results to a
report is pure arithmetic over timestamps and latencies.

`UserData` caps at 245 bytes for a reason worth writing down: a DNS TXT character
string is capped at 255 and `user-data=` costs 10.

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

**Done 2026-09-30, with two items still open.** The decision and its price are
in [`DECISIONS/0001`](DECISIONS/0001-transport-substrate.md); the
[execution record](DECISIONS/0001-transport-substrate.md#execution-record-of-2026-09-30)
says what was built, what it cost against what was predicted, and what was not
finished.
The initial quic-zig cut cost roughly double the first estimate.
Its loss of native multipath was the historical cost accepted on 2026-09-30.
That capability description no longer describes the patched core.
The vendor now implements native Noq observed-address, NAT traversal and multipath wire extensions.
`Node.step` drives native candidates and validated path selection through `node_native.pass`.
The core retains path IDs 0 and 1 for the connection lifetime.
The eight historical address pairs in `transport/multipath.Table` do not increase that limit.
The generic path table, selection, revalidation and probe models remain standalone.

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
- **Interop, and with it requirement 3.** The upstream matrix remains the
  evidence needed to close this requirement. It ran at a different commit, and
  its runner is a git submodule outside the published package. M8 did not
  re-run it. A separate current process/socket smoke passes four routes between
  the Zig stack and strict `noq` 1.3.0 or stock iroh 1.3.0. It exchanges
  17-byte application payloads in both directions in Debug and ReleaseSafe.
  That smoke does not run the matrix or close requirement 3. See `README.md`
  for its commands and scope.

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

Blobs: the framing is type-dependent (Get/GetMany/Observe consume the stream to
EOF; Push is varint-length-prefixed with bao data following on the same
stream), all ranges are in 1024-byte BLAKE3 chunks with a 16384-byte block size,
and **missing data is EOF, not an error frame**.

`iroh-willow` (~14.3k lines) and `iroh-docs` (~14.7k lines) are out of scope
until the transport is proven. Willow is capability-secured with ristretto255
private-area-intersection; docs is a Loro-backed CRDT, and most of what makes it
"docs" is not portable to Zig anyway.

## What is deliberately not planned

- **A QUIC implementation.** If M8 resolves against writing one, this document
  changes and the reason gets recorded in DECISIONS/0001.
- **An HTTP/3 client.** iroh does not have one and ozai does not need one.
- **CAR files.** iroh-blobs uses its own Collection format now.
- **Backward compatibility.** No iroh 0.x ticket layouts, no deprecated ALPN
  aliases, no shims. Delete rather than deprecate.
