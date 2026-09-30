# ozai architecture

The module tree, the seams, and the invariants a change must not break.

Read [`PLAN.md`](PLAN.md) first for why the tree is shaped this way. This
document is the reference: what exists, what each boundary is for, and what
would break if it moved.

## Layering

```
                    application protocol
                            │  ALPN
┌───────────────────────────┴───────────────────────────┐
│  ozai.router          ALPN → ProtocolHandler vtable   │
├───────────────────────────────────────────────────────┤
│  ozai.endpoint        secret key, QUIC stack,         │
│                       transports, accept loop         │
├───────────────────────────────────────────────────────┤
│  ozai.transport       the QUIC seam. Owns the socket. │
│                       Maps a path to a synthetic ULA  │
│                       and classifies one coming back. │
├───────────────────────┬───────────────────────────────┤
│  ozai.relay           │  ozai.discovery                │
│  client + server      │  pkarr, DNS TXT, publisher     │
│  frame codec          │  resolver, merge               │
├───────────────────────────────────────────────────────┤
│  ozai.net             net report, NAT classification,  │
│                       portmapper, direct-address set  │
├───────────────────────────────────────────────────────┤
│  ozai.base            keys, addresses, base32.        │
│                       Pure. No Io, no allocator.      │
└───────────────────────────────────────────────────────┘
```

The rule that makes the whole thing testable: **nothing below `ozai.base` may
read a clock, read the environment, or take an allocator it was not handed.**
Everything above it may, as long as `io: std.Io` is threaded rather than stored.

The runtime is [`DECISIONS/0002`](DECISIONS/0002-async-substrate.md): zio, used
at the transport and endpoint layers and invisible above them. A state machine
that needs a runtime stood up in order to be tested has found a boundary in the
wrong place.

## Module tree

Names are chosen for what they are *for* in Zig, not for their Rust originals.
Where a rename happened, the reason is recorded here so it is not undone by a
well-meaning port.

| Zig | Rust upstream | Why |
|---|---|---|
| `NodeId` | `EndpointId` / `PublicKey` | Upstream uses one type under two names. ozai has one name, because every use of the value is "address a node", never "do crypto with this". |
| `NodeAddr` | `EndpointAddr` | Same reason. |
| `RelayUrl` | `RelayUrl` | Unchanged, but ozai's is an owned fixed-size value rather than an `Arc<Url>`: no allocation, no borrowed lifetime, safe in a set. |
| `TransportAddr` | `TransportAddr` | Unchanged. |
| `ozai.base.IpAddress` | `std::net::SocketAddr` | ozai defines its own so `base` stays free of `std.Io.net` and remains a pure leaf. Conversion happens once, at the transport seam. |
| `ula.Path` | `EndpointIdMappedAddr` / `RelayMappedAddr` / `CustomMappedAddr` | Upstream has three newtypes because each has its own `generate` and its own `TryFrom`. One tagged enum says the same thing, and the /64 prefix is the only thing that differs between them. |
| `ula.syntheticSocketAddr` | `MappedAddr::generate` + `private_socket_addr` | Named for what it does rather than `toSocketAddr`, which reads as a conversion any caller could reach for. It does not allocate: the eight host bits upstream draws from `rand::rng()` are an explicit argument here. |
| `ula.classify` | `From<SocketAddr> for MultipathMappedAddr` | The inbound direction, and the half that actually is pure upstream. |
| `ProtocolHandler` | same | Becomes a vtable, not a trait object. |
| `AddressLookup` | same | `resolve` returns a stream, and `None` means "cannot resolve at all". |

## Boundaries that must not move

**`ozai.base` is pure.** No `Io`, no allocator, no clock, no environment. The
value types here are what a state machine carries *as* its state, and a state
machine that carries an `Io` cannot be driven by a test.

**Wire codecs are pure and separate from the transport.** Relay framing, ticket
encoding, pkarr signing, `RangeSpec` algebra: each is a function from bytes to a
value and back. None of them may open a socket. This is the single most
consequential boundary in the project — it is what makes roughly half of iroh
verifiable without a network.

**The transport seam is the only place a path becomes a socket address.** iroh
dresses relay and custom paths up as RFC 4193 unique local addresses
(`fd15:070a:510b:0000/0001/0003::/64`, port 12345) because that stack only
understands IP, and that stack is not ozai's business. The construction and the
classification are pure and live in `base` as `ula`; the state that makes the
same path answer with the same address again lives here.

**The router owns ALPN dispatch and nothing else.** It turns a negotiated ALPN
into a handler call. It does not know what any protocol does.

## Invariants

These are the things that break silently. Each is stated with the failure it
prevents, and each belongs in a test.

### Identity and ordering

1. **`NodeId` ordering is lexicographic over the 32 bytes**, not by curve order.
   Every sorted collection depends on it, and a ticket's bytes depend on it.
2. **A `NodeAddr` address list is sorted and duplicate-free.** Insertion order
   must not change the rendered bytes; that is what makes a ticket an identifier
   rather than a fresh value on every send. Covered by an integration test.
3. **The local TLS name is never sent as SNI.** It exists to select the expected
   peer id and to bucket the 0-RTT session cache. SNI is disabled. A port that
   transmits it leaks peer ids and breaks 0-RTT resumption partitioning.
4. **A relay URL's canonical text carries a trailing `/`.** iroh writes relay
   URLs in that shape and a ticket carries the URL as bytes, so any other
   spelling is a different address to a peer.
5. **`SecretKey.deinit` zeroes.** A secret key left in freed heap is a secret key
   an attacker reads.
6. **A value never carries a slice into a frame it does not own.** A function
   that decodes into a local and returns a slice of it hands back a pointer to
   a stack frame that died on return, and the default build will agree with you
   about it for as long as the bytes happen to survive. `NodeAddr` copies a
   `TransportAddr` onto the heap, so such a pointer is read back much later,
   in another frame. Anything that parses into storage takes that storage from
   the caller, the way `CustomAddr.parse` and `RelayUrl.hostSlice` now do.

### Relay

7. **`segment_size.is_some()` ⇔ batch frame type.** `takeSegments` clears
   `segment_size` when the remainder drops to a single datagram. The asymmetry
   corrupts the GSO path.
8. **Version negotiation is `max()`, not first-match**, and both v1 and v2 frames
   are emittable. `Health` (v1) and `Status` (v2) are the same semantic event in
   different encodings; the server translates.
9. **Two queues per relay connection**, data and control. Merged, a `Status` can
   sit behind a 512-deep datagram backlog.
10. **Admit once, report disconnect exactly once.** In Zig this is a guard handle
   whose `deinit` is the single exit path; the connection actor must never
   outlive it.

### Discovery

11. **pkarr signs the BEP-0044 signable form** —
    `"3:seqi{ts}e1:v{n}:" ++ dns` — not the raw bytes. Raw-byte signatures are
    accepted by nobody.
12. **Packet ordering is total**: timestamp first, encoded bytes as tiebreak.
    A partial order makes zones flap.
13. **Dropping a resolve stream cancels its work.** Returning `None` means
    "cannot resolve", and must not be confused with "resolved to nothing".

### Transport and NAT

14. **The synthetic-ULA construction and its inverse are pure, total and
    deterministic.** A wrong /l, global id or subnet discriminator makes two
    paths to one peer land on one address, and nothing anywhere reports it.
    Allocating an address to a key is *not* pure, upstream or here, and is not
    in `base`: see the divergence below.
15. **Re-punch only on a genuinely new candidate address.** Otherwise honour the
    5 s interval. Always punching floods the relay and never converges.
16. **Prune `Unusable` paths first, always**, and cap `Inactive` at 10 of 30
    non-relay paths per peer.
17. **A selected relay path is not a reason to stop punching.**

### Endpoint

18. **Graceful close is mandatory.** Dropping an endpoint without closing logs an
    error upstream. The same must be true here, and be tested.
19. **`accept` failure sends no error code.** The connection is dropped with a
    warning. Upstream deliberately does this, and a handler that wants the peer
    to know calls `close` itself.
20. **The TLS verifier and session-store identities must be stable** across every
    client-config construction, or 0-RTT silently stops working. In Zig this means
    one long-lived config object, not a value rebuilt per call.

## Divergences from upstream, in one place

- **Ed25519 validation.** Upstream rejects a non-point at construction; Zig 0.16's
  `PublicKey.fromBytes` only rejects a non-canonical `y`. ozai constructs with the
  weaker check and uses `verifyStrict` for any key that came off the network.
- **`RelayUrl` is owned, not `Arc`.** Fixed 253-byte host, no allocation, no
  borrowed lifetime. `hostSlice` takes a pointer receiver for exactly this reason:
  a 258-byte struct taken by value can hand back a slice into a dead temporary.
- **Ticket and address encodings are explicit.** `parseHex` / `parseZ32` /
  `parseLocalTlsName` rather than one `FromStr` that guesses by length.
- **The synthetic-ULA host bits are injected, not drawn.** Upstream's
  `MappedAddr::generate` calls `rand::rng().fill_bytes(&mut addr[8..16])` and
  gets stability from an `AddrMap` — a bi-directional `FxHashMap` behind a
  `Mutex` that retries on collision and memoises both directions. That is a
  process-global RNG, which AGENTS.md §2 forbids, and hidden state, which
  `base` forbids. `ula.syntheticSocketAddr` therefore takes the eight host bits
  as an argument. The map that reuses them is transport-layer state and lands
  with M7's transport seam. The `/l`, the global id, the subnets and the port
  are upstream's bytes and are pinned by golden vectors in `base/ula.zig`.
- **A folded report names a global address, not the first one seen.**
  Upstream's `global_v4` / `global_v6` store the first address a probe reported
  and never replace it, so the published address is a function of the order the
  probes happened to arrive in. ozai picks lowest latency, then freshest instant,
  then lowest relay URL. The two can only differ when probes to several relays
  disagree, and that is exactly the case where arrival order was deciding a
  question of fact.
- **The discovery ordering key writes a custom id big-endian.** Ordering is
  timestamp, then the canonical encoding, and an ordering key has to sort in the
  same order as the values it orders. `CustomAddr.writeBinary` is deliberately
  little-endian for the wire, and little-endian integers do not sort that way
  (1 before 256 does not survive a byte comparison). The two encodings are
  therefore different on purpose, and a test pins that they agree on every
  representable address.
- **No `DiscoveryItem` enum.** Upstream replaced it with `Item` plus a
  `provenance` string; ozai keeps the stream, drops the stringly-typed tag in
  favour of a typed provenance enum. Upstream derives no ordering on `Item` and
  nothing in its tree sorts one, so the total order the plan asks for is
  entirely ozai's own construction.
- **`NodeId` is one type, not two names.** See the table above.
- **The relay frame header is a QUIC varint, and relay payloads are not
  postcard.** The frame type is `noq_proto::VarInt`, and postcard appears in
  exactly one place upstream — the `ServerDeniesAuth` reason. Segment sizes are
  raw big-endian `u16`, restarting is two raw `u32`s, ping is eight raw bytes.
  For types 0–13 the two varint encodings agree byte for byte, so this only
  bites on decode, where a QUIC varint can spell a value a postcard reader would
  take for something else entirely. A batch frame declaring a zero segment size
  is rejected rather than accepted-and-normalised, so the
  `segment_size ⇔ batch` rule is a property of the codec instead of a property
  of a peer's cooperation.
