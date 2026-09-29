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
   0.16 standard library. Every milestone that needs a live connection is gated
   on the decision in
   [`DECISIONS/0001-transport-substrate.md`](DECISIONS/0001-transport-substrate.md).
2. **The TLS handshake is not a detail.** iroh's peer authentication *is* TLS 1.3
   with raw Ed25519 public keys: the certificate is a DER `SubjectPublicKeyInfo`
   wrapping the 32-byte node id, and verification reduces to a byte comparison
   against the id you expected. A QUIC stack that cannot accept a raw key as its
   certificate cannot be an iroh peer. This is the single hardest interop
   requirement, and it is a requirement on the *chosen* QUIC, not on ozai's code.
3. **`std.Io` is the only I/O vocabulary.** Zig 0.16 threads `io: std.Io` through
   every I/O-capable call. ozai never caches an `Io` in a struct, never reaches
   for a global, and never calls a syscall directly except through `Io` or
   `zio.ev`. That is what makes a whole endpoint deterministically simulatable.
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
- fuzzed at every decoder boundary, with round-trip properties as the oracle

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

Ordering: timestamps first, encoded-packet bytes as the tiebreak. A total order
or zones flap.

### M6 — net report and NAT classification

`mapping_varies_by_dest_*` is the actual classifier: two probes to *different*
relays returning *different* public addresses means destination-dependent
mapping, and holepunching gets much harder. The fold from probe results to a
report is pure arithmetic over timestamps and latencies.

`UserData` caps at 245 bytes for a reason worth writing down: a DNS TXT character
string is capped at 255 and `user-data=` costs 10.

### M7 — the transport seam

`TransportAddr → SocketAddr` via iroh's synthetic-ULA map, which is the single
most reusable idea in the upstream codebase:

```
fd15:070a:510b:0000::/64   a peer, any path      (subnet 0000)
fd15:070a:510b:0001::/64   a peer via one relay (subnet 0001)
fd15:070a:510b:0003::/64   a peer via a custom  (subnet 0003)
port 12345 for all of them
```

A QUIC stack only speaks IP. Mapping relay and custom paths onto RFC 4193 unique
local addresses lets one connection carry a relay path and N direct paths with
no change to the QUIC stack at all. `From<SocketAddr>` must be a pure, total,
deterministic function; get the prefix, global id, or subnet discriminator wrong
and paths silently alias.

### M8 — the QUIC substrate

Gated on DECISIONS/0001. Whichever way it goes, the contract is fixed: a
`feedPacket`-shaped seam that accepts a datagram from a transport multiplexer
ozai owns and hands back an outgoing datagram, per connection, without the QUIC
stack owning the socket. If the chosen stack cannot do that, it cannot be an
iroh peer, and the decision is revisited rather than worked around.

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
