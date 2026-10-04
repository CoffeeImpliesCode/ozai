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
│                       holepunch gate, candidate paths │
├───────────────────────────────────────────────────────┤
│  ozai.base            keys, addresses, base32.        │
│                       Injected allocators and Io.    │
└───────────────────────────────────────────────────────┘
```

Wire codecs and network state machines consume caller-supplied bytes, state,
time and entropy. They do not fetch a clock, environment or hidden allocator.
`SecretKey.generate` is an explicit entropy edge: it borrows the caller's
`std.Io` rather than hiding a process random source. That is an ownership
property, not a strength one — the draw is `Io.random`, which Zig 0.16.0
documents as seeded by `Io.randomSecure` *or by a less secure mechanism when
that fails* (`lib/std/Io.zig:2462-2469`). A caller that needs the guarantee
passes an `Io` whose `random` is `randomSecure`.

The socket and node drivers borrow `std.Io` per operation. Its backend and
userdata must outlive the operation and any task that uses them.
Runtime owners keep their allocator, but pure actions keep no socket handle.
See [`DECISIONS/0002`](DECISIONS/0002-async-substrate.md) for the runtime choice.

The current Linux driver uses `Io.Threaded`. `Io.Uring` cannot send a UDP
datagram in Zig 0.16.0 (`lib/std/Io/Uring.zig:5042-5054`), and `Io.Evented` is
`Io.Uring` on Linux (`lib/std/Io.zig:31-37`). Neither runtime owns this stack's
send path.

**One boundary the runtime still violates.** `Node.create` initializes
`std.Random.DefaultPrng` from a `u64` the caller passes, and `ozai-node` passes
the fixed public constant `0x6f7a_69`. That generator reaches the TLS
handshake's ephemeral scalars, the relay admission challenges and the QUIC
connection-id and path-validation draws, so the production randomness is
predictable even though `ozai.base`'s seam is not. Identity keys do not come
from it. This is the first Wave 0 repair in [`PLAN.md`](PLAN.md) and it is not
yet made.

## Module tree

Names are chosen for what they are *for* in Zig, not for their Rust originals.
Where a rename happened, the reason is recorded here so it is not undone by a
well-meaning port.

The diagram names responsibilities, not import routes. The package registers
`ozai` and `quic` separately. `src/root.zig` lists the supported `ozai`
namespaces. Owning declarations state each result's lifetime and release duty.
Reachable fields are not private, and copying an owner does not duplicate its
resources. Allocating owners require exactly one teardown.

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

**`ozai.base` has no hidden resources.** Value types never store `Io` or an
allocator, and never read a clock or the environment. Owned address storage
takes an explicit allocator; secret-key generation takes an explicit `Io`
for entropy. State machines carry the values, not those resource handles.

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
   different encodings; the server translates. The codec can negotiate and emit
   both today; no production server performs that translation, because there is
   no standard carrier to perform it on.
9. **Two queues per relay connection**, data and control. Merged, a `Status` can
   sit behind a 512-deep datagram backlog.
10. **Admit once, report disconnect exactly once.** In Zig this is a guard handle
   whose `deinit` is the single exit path; the connection actor must never
   outlive it.

### Discovery

11. **pkarr signs the BEP-0044 signable form** —
    `"3:seqi{ts}e1:v{n}:" ++ dns` — not the raw bytes. Raw-byte signatures are
    accepted by nobody.
12. **Item ordering is total**: timestamp, node id, address value, then provenance.
    Equal timestamps do not make the result depend on source arrival order.
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
    one long-lived config object, not a value rebuilt per call. The vendored
    core's pinned-client resumption currently asks for a fresh client
    certificate after PSK selection and fails closed; that is a recorded RFC
    8446 deviation and an added compatibility limitation, not a guard to
    preserve and not an identity bypass.

## Divergences from upstream, in one place

- **Ed25519 validation.** Upstream rejects a non-point at construction; Zig 0.16's
  `PublicKey.fromBytes` only rejects a non-canonical `y`. ozai constructs with the
  weaker check and uses `verifyStrict` for any key that came off the network.
- **`RelayUrl` is owned, not `Arc`.** Fixed 253-byte host, no allocation, no
  borrowed lifetime. `hostSlice` takes a pointer receiver for exactly this reason:
  a 258-byte struct taken by value can hand back a slice into a dead temporary.
  It becomes a socket address only when its host is an IP literal;
  `socketAddr` answers `error.NotAnIpLiteral` for a name, because `base` has no
  `Io`, no allocator and no clock and name resolution belongs to
  `src/discovery/`. Upstream's DERP client parses `url.host` as a socket address
  outright, so the literal case is its shape and the named case is our open half.
  **Nothing in `src/` resolves a name today**: `dns.zig` builds only the
  `_iroh.<z32>.<origin>` TXT query and there is no A/AAAA path. A relay URL
  with a named host cannot yet be reached. A live transport
  does exist — `discovery/lookup_live.zig` is the datagram seam over
  `transport/socket.zig` — but it carries those questions rather than turning a
  host into an address.
- **Ticket and address encodings are explicit.** `parseHex` / `parseZ32` /
  `parseLocalTlsName` rather than one `FromStr` that guesses by length.
- **The synthetic-ULA host bits are injected, not drawn.** Upstream's
  `MappedAddr::generate` calls `rand::rng().fill_bytes(&mut addr[8..16])` and
  gets stability from an `AddrMap` — a bi-directional `FxHashMap` behind a
  `Mutex` that retries on collision and memoises both directions. That is a
  process-global RNG, which AGENTS.md §2 forbids, and hidden state, which
  `base` forbids. `ula.syntheticSocketAddr` therefore takes the eight host bits
  as an argument. The map that reuses them is transport-layer state, and it
  landed with M7's transport seam as `transport/addr_map.zig`. The `/l`, the
  global id, the subnets and the port are upstream's bytes and are pinned by
  golden vectors in `base/ula.zig`.
- **A folded report names a global address, not the first one seen.**
  Upstream's `global_v4` / `global_v6` store the first address a probe reported
  and never replace it, so the published address is a function of the order the
  probes happened to arrive in. ozai picks lowest latency, then freshest instant,
  then lowest relay URL. The two can only differ when probes to several relays
  disagree, and that is exactly the case where arrival order was deciding a
  question of fact.
- **Discovery compares address values, not their encoding.** Host and custom-data
  lengths precede their bytes in the record, so bytewise record order disagrees
  with `TransportAddr.order` for unequal-length values. `Item.order` compares
  values directly. The injective record encoding remains useful for identity,
  but it is not a sort key.
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
- **A relay's outbound text is bounded; upstream's is not.** Upstream bounds no
  relay-authored text. `ServerDeniesAuth` is a bare `reason: String`
  (`handshake.rs:105-107`) and `Health` a `problem: String` (`relay.rs:115`),
  written into a `BytesMut::new()` that grows (`handshake.rs:558-561`), so a
  relay there cannot fail to send a denial — it decides how large its own denial
  is and pays in memory. Upstream's only size rule is inbound:
  `ensure!(frame_len <= MAX_PACKET_SIZE)` at `relay.rs:404` and `:544`.

  Two things differ here, and only the second needed a bound. Upstream's writer
  allocates; this one appends into a buffer the caller owns, and a fixed buffer is
  what turns an unbounded string into an unwritable frame. And upstream's reason
  is the relay's own text, while ours is whatever an access-control trait
  produced (`handshake.rs:495`, `:524`).

  So `relay/frame.zig` owns `max_text_length` (255), `encode` refuses past it as
  `TextTooLong` before writing a byte, and the maximum a caller may write is a
  value in the type: `ServerDeniesAuth.max_reason_length`, with
  `ServerDeniesAuth.max_frame_length` (258) for the buffer. `src/node/node.zig`
  asserts at comptime that the room it reserves covers a denial at that bound, so
  "the relay always has room for the denial it decided to send" is arithmetic
  rather than a hope.

  The same sweep closed two neighbours: a v1 `health` problem takes the same
  constant, and the four datagram frames' payload is now refused by
  `max_packet_size` on the way out as `decode` already refused it on the way in.
  Recorded rather than matched because upstream has no rule to match — this is a
  consequence of the port's fixed-buffer writer, not a different opinion about
  how long a denial should be.
- **The vendored core carries two paths; `ula` models three subnets.** The QUIC
  substrate holds `paths: [2]NetworkPath` with one `active_path_idx` — an active
  path and a candidate, which is RFC 9000 migration and nothing more, and is
  upstream's own structure unchanged. The synthetic-ULA map offers a peer three
  distinguishable subnets at once: any-path, one-per-relay, one-per-custom. A
  connection handed all three is a connection the core reads as a migration, so
  the map and the stack disagree about how many paths a peer has. This is the
  cost `DECISIONS/0001` accepted when it took this substrate over one with
  native multipath, now confirmed against the code rather than estimated. It
  is a convergence cost and not a correctness one: the mapping still keeps the
  paths from aliasing, and a peer that is given a second path before the first
  is used loses the first.
- **`TlsConfig` and `ClientAuth` carry different peer pins.** The client-side
  field is `expect_peer_node_id`; the server-side one is `ClientAuth.expect_node_id`.
  Upstream had `skip_cert_verify` and a `ca_bundle` on `TlsConfig` and treated
  the two directions as the same decision. They are not — a client verifies who
  it connected to, a server decides who to let in — and one field cannot carry
  both without a comment explaining which is which at every use.
- **The relay carrier is private QUIC, and it is not upstream's.** Upstream's
  relay is reached over an HTTP upgrade to RFC 6455 WebSocket; the carrier in
  this tree is the private QUIC ALPN `/iroh-relay/1`. Nothing below the frame
  codec changes because of it, and nothing about interoperability survives it:
  the standard carrier, its TLS seam, the `iroh-relay-v1|v2` negotiation and
  the inner-QUIC egress rewrite are Wave 2 work.
