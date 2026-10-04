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
`SecretKey.generate` borrows the caller's `std.Io` and draws from `io.randomSecure`.
It erases the temporary seed with `std.crypto.secureZero` on every exit.
An unavailable secure entropy source returns an error. There is no fallback to `io.random`.

The socket and node drivers borrow `std.Io` per operation. Its backend and
userdata must outlive the operation and any task that uses them.
Runtime owners keep their allocator, but pure actions keep no socket handle.
See [`DECISIONS/0002`](DECISIONS/0002-async-substrate.md) for the runtime choice.

The current Linux driver uses `Io.Threaded`. `Io.Uring` cannot send a UDP
datagram in Zig 0.16.0 (`lib/std/Io/Uring.zig:5042-5054`), and `Io.Evented` is
`Io.Uring` on Linux (`lib/std/Io.zig:31-37`). Neither runtime owns this stack's
send path.

**Wave 0 repaired production entropy.** `ozai.node_lifecycle.create` draws a 32-byte seed
from `io.randomSecure` into an owned ChaCha `Csprng`.
It erases the temporary with `std.crypto.secureZero`.
The generator supplies TLS ephemeral scalars, relay challenges, QUIC connection IDs, and path-validation draws.
`ozai-node` no longer accepts `--seed`.
Pure state machines still take explicit `std.Random` values for deterministic tests.

## Module tree

Names are chosen for what they are *for* in Zig, not for their Rust originals.
Where a rename happened, the reason is recorded here so it is not undone by a
well-meaning port.

The diagram names responsibilities, not import routes. The package registers
`ozai` and `quic` separately. `src/root.zig` lists the supported `ozai`
namespaces. Owning declarations state each result's lifetime and release duty.
Reachable fields are not private, and copying an owner does not duplicate its
resources. Allocating owners require exactly one teardown.

The transport APIs have separate owning namespaces:

| Namespace | Responsibility |
|---|---|
| `ozai.transport_quic_conn` | `Conn`, `Egress`, `Instant`, `min_datagram`, and the `toCoreAddress` / `fromCoreAddress` translators |
| `ozai.transport_quic_config` | `Config`, `AlpnError`, `CreateError`, `max_alpns`, `max_alpn_name_len`, `spki_length`, `validateAlpns`, `demandsPeerCertificate`, `connectionConfig`, and `drawKey` |
| `ozai.transport_quic_error` | The transport `Error` union |
| `ozai.transport_quic_stream` | Borrowed views `Stream`, `UniStream`, and `RecvUni`, plus `max_drain_runs`, `openBidi`, `openUni`, and `acceptUni` over `*quic.connection.Connection` |
| `ozai.transport_quic_datagram` | `max_payload`, `Error`, `enabled`, `maxPayload`, `queued`, `send`, and `recv` |
| `ozai.transport_retry` | `RetryToken`, `Gate`, `Verdict`, `Error`, `InitialHeader`, `initialHeader`, and the token-length, connection-id, age, and tracking bounds |
| `ozai.transport_dial_route` | `Route`, `Error`, `resolveRoute`, and `ownerOf` |

`Bridge` owns the endpoint. It does not re-export those types, helpers, or modules.
`Conn.close(application_error, reason, at)` queues an application close.
The reason remains borrowed until reaping. The caller must drain the close before freeing the connection owner.

The node separates data from operations. `src/root.zig` registers the data
owner and the twenty-one processor namespaces anchored to it; nothing else is a
node route.

| Namespace | Responsibility |
|---|---|
| `ozai.node` | Stable `Node` data, `Stop`, `Lane`, and `Answer` |
| `ozai.node_config` | `Config`, peers, relay roles, and storage bounds |
| `ozai.node_protocol` | `Protocol`, `Handler`, `Connection`, `Turn`, `LaneStats`, `max_alpns`, and the ALPN constants |
| `ozai.node_error` | Node `Error` |
| `ozai.node_stats` | `Stats` and send-report counters |
| `ozai.node_lifecycle` | `create`, `register`, and `deinit` |
| `ozai.node_runtime` | `start`, `step`, `wait`, `run`, `windDown`, `dispose`, and `instantOf` |
| `ozai.node_close` | `close`, `finish`, `retire`, `cancelLane`, `protocols`, and `laneStats` |
| `ozai.node_relay_client` | Relay-client passes, delivery storage, `sendThrough`, `clientCount`, and `queueDepth` |
| `ozai.node_framing` | Relay stream framing and inbox boundaries |
| `ozai.node_lane` | Handler callback execution and lane shutdown |
| `ozai.node_dispatch` | Endpoint event intake, concrete actions, shutdown steps, and socket release |
| `ozai.node_accept` | Admission, accept-task driving, and lane continuations |
| `ozai.node_connection_close` | Application close on one or every connection, and the egress it produces |
| `ozai.node_ingress` | Datagram intake and delivery |
| `ozai.node_egress` | Outbound datagrams and connection expiry |
| `ozai.node_gossip` | Gossip passes, event feed, and peer departure |
| `ozai.node_relay_serve_admit` | The serving pass, its admission walk, and the handshake machine |
| `ozai.node_relay_serve_read` | The read of every client slot, and the rules for what its stream still means |
| `ozai.node_relay_serve` | The datagram frames a client sends, forwarding, and the queue drain |
| `ozai.node_relay_registry` | Relay registration, replacement, and release |
| `ozai.node_report` | Driver reports |

Each row owns its operations outright. `ozai.node` owns the free functions
`nodeId`, `address`, `generator`, `establishedCount`, `namedPeers` and
`connFor`, and `Node` carries no forwarding method, nested processor namespace
or moved-type alias. There is no second spelling of any of these operations:
no compatibility facade, alias module or shim survived the cutover, so a
caller reaching for a retired method form finds nothing.

Lifecycle allocates and releases the stable owner, runtime drives the pass
order, and close owns shutdown order. Each protocol owns its handler state.

### The module graph

The graph is acyclic apart from the serving-relay half, and its direction is
fixed by ownership.
`node_error`, `node_stats` and `node_framing` import no node namespace at all.
`node_protocol` imports `node_error`, `node_config` imports `node_protocol`,
and `node.zig` imports only the three owners it embeds, so data reaches no
operation. The only importers of `node_runtime` are the CLI driver and the
node's own test module, which is what makes "lower processors do not call
back into the runtime" a property of the imports rather than a convention.

The processor-to-processor edges are few and fixed:

- `node_runtime` → `node_accept`, `node_close`, `node_egress`,
  `node_ingress`, `node_relay_client`, `node_relay_serve_admit`
- `node_close` → `node_dispatch`, `node_lane`, `node_connection_close`
- `node_dispatch` → `node_lane`, `node_connection_close`
- `node_accept` → `node_dispatch`
- `node_egress` → `node_dispatch`, `node_gossip`
- `node_lane` → `node_relay_registry`
- `node_relay_serve_admit` → `node_relay_registry`, `node_relay_serve_read`,
  `node_relay_serve`
- `node_relay_serve_read` → `node_relay_serve_admit`, `node_relay_serve`
- `node_relay_serve` → `node_relay_serve_admit`, `node_relay_serve_read`
- `node_report` → `node_relay_client`

The serving-relay half is the one cycle, and it is one pass rather than a
layering: the admission walk spends a slot, the read drains its stream, and
the datagram half serves the frames and drains the queues, and each of the
three calls back into the other two for the next step of that same pass.
`serveAdmit` and `serveRead` both offer events to `serveHandshake`,
`serveRead` hands the inbox to `serveMessages`, and `serveMessage` offers a
frame back to `serveHandshake`. Splitting the pass by responsibility is what
made the cycle visible at file level; it was inside one file before, and no
module in it can drop an edge without the pass losing a step.

One of those crosses a role boundary: `node_relay_serve_admit` →
`node_relay_client` (`node_relay_serve_admit.zig:21`, `:97-98`). It exists for
`queueDepth` alone, a read of the serve role's configured queue depth that
sizes the queues and the ring of a newly admitted client. It hands no state
across, and
`node_relay_client` imports only `node`, `node_config`, `node_error` and
`node_framing` in return, so the cycle a role-crossing edge could have closed
does not exist.

### The public call shape

A required `std.Io` is a leading argument, not a trailing one. Where one
followed the node or another argument it moved in front of it, and every
non-Io argument kept its order:

```zig
ozai.node_runtime.step(io, node, at, random)
ozai.node_runtime.wait(io, node, timeout_ms)
ozai.node_runtime.run(io, node, stop)
ozai.node_runtime.windDown(io, node, last)
ozai.node_accept.admit(io, node, at, random)
ozai.node_accept.runTask(io, node, at, random, &task, conn)
ozai.node_ingress.take(io, node, at, random)
ozai.node_egress.expire(io, node, at, random)
ozai.node_connection_close.closeConnections(io, node, at, random)
ozai.node_close.close(io, node, at, random)
ozai.node_close.retire(io, node, alpn, at)
ozai.node_close.cancelLane(io, node, at, index)
```

Internal calls use the same order. `node_runtime.step` reads
`ingress.take(io, self, at, random)`, `accept.admit(io, self, at, random)`,
`egress.drain(io, self, at, random)` and `gossip.gossip(self, at)`, and
`node_close.cancelLane` calls
`connection_close.closeOne(io, self, conn, at)`.

Two shapes do not move, and the reason is the same in each:

- **Allocator first, I/O next.**
  `ozai.node_lifecycle.create(gpa, io, config)` allocates the owner it
  returns, so the allocator leads and `io` follows it.
- **An optional runtime stays put.** `io: ?std.Io` is a value the caller may
  not have rather than a backend it borrows, so it keeps its position after
  the node: `ozai.node_close.finish(node, io, at, random)` is what
  `dispose(node)` calls as `finish(node, null, null, generator)`, and
  `ozai.node_dispatch.feed`, `perform` and `performShutdown` keep
  `(node, io, …)`.

An operation with no runtime keeps its own shape: `runtime.start(node, at,
random)`, `runtime.instantOf(io)`, `runtime.dispose(node)`,
`gossip.gossip(node, at)`, `relay_client.converse(node, at, random)`,
`relay_serve.serve(node, at, random)`, `lane.shutdownLane(node, index)`, and
`report.report(&writer, node, holding, close)`, whose first argument is a
writer and not a runtime.

One runtime pass performs ingress, sweep, admission, accept driving, relay work, egress, expiry, and gossip.
Sweep precedes indexed admission. Relay writes precede egress in the same pass.
A failed pass requires closure, not a replay.
`run` closes on every exit. `windDown` protects cleanup without replacing the original driver error.
Close the owner before `deinit`. Keep its allocator alive and deinitialize exactly once.
Stop requests do not join the driver. Wait for `run` before releasing the stop or node.

### What the data owner keeps

The I/O cutover moved no field. `src/node/node.zig` declares `Node` with 30
fields, from `gpa` to `stats`, and that field set is the node's stable shape: a
pointer into it is what a lane, the router table and the relay registry hold,
so changing it changes every borrower at once.

- **One heap.** `gpa` is the only allocator the struct carries.
  `node_lifecycle.create` calls `gpa.create(Node)` once, and every buffer,
  map and the node itself is released through that same allocator by
  `deinit`, exactly once.
- **Lane owner.** Lanes are embedded as `lanes: [max_alpns]Lane`, so
  `Lane.owner` points back at the node rather than copying it, and the router
  table stores `*Lane`. `node_lifecycle.register` writes `.owner = self` for
  each configured protocol.
- **Borrowed ALPN.** `Lane.alpn` holds `registration.alpn` unchanged. ALPN
  bytes, custom handler state and peer payloads are borrowed for the node's
  lifetime, so the caller keeps them alive.

### Two sweep roots, and what each excludes

The native root `src/unit_test.zig` references the whole `ozai` module and
reaches `node/node_tests.zig` exactly once, which is why that module is not
imported anywhere else. The socket-free root `src/portable_test.zig` names
its modules explicitly and imports only `node_stats` and `node_framing` from
the node: the other eighteen node namespaces reach the Linux socket adapters
through `node_error` or the `Node` data owner, so their declarations and their
live tests stay in the native root. That split is the platform boundary, and
relocating a test must not move it.

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

**The offer list and dispatch table use one bounded registration set.**
`ozai.node_config.Config.protocols` supplies each ALPN and its handler selection.
`Router.offers` and `Router.dispatch` use those registrations.
Each negotiated protocol reaches its own handler.
An empty ALPN intersection fails the handshake before router dispatch.
A separately configured table can still return `Drop.refused_protocol`.

**A protocol owns its handler state.** `ozai.node_protocol` owns registrations and handler contracts.
Each registration selects `.standard` or a custom `Handler`.
The protocol slice, ALPN bytes, and custom handler context must outlive the node.
The node calls handler callbacks inside `ozai.node_runtime.step`.
Callbacks must not re-enter `step` or call `ozai.node_close.close`.
The supplied connection is borrowed for that turn. Core reaping invalidates borrowed connections and streams.
`Turn.more` retains the task for another call to the same handler.
`Turn.finished` completes it.
`ozai.node_close.retire` withdraws the ALPN first, calls that lane's shutdown once, and cancels only that lane's accepts.
It also queues the lane's connection closes. Other protocols remain active.

**Where Wave 1 stands.** The ownership cutover is in the tree, and seven actual
native↔Rust exchanges have run against the current Debug build: the receipts
`<scratch>/evidence/resume-w1-live-*.json` record three payload runs —
positives in both role orders plus one `--require-retry` run — exiting 0/0 with
mutually authenticated exact peer ids, the negotiated ALPN `/ozai/w1-fixture`,
and all six distinct bidirectional, uni-stream and datagram payloads verified
by both ends, and four typed refusals exiting 1/1 on alert 42 (wrong peer) or
120 (ALPN), with no payload owed and none verified. **A peer id is keyed by
role, not by implementation:** LISTENER secret seed `0x11` is `d04ab232…` and
DIALER secret seed `0x22` is `a09aa5f4…`, and the native peer holds each role in
a different receipt, so "the native peer id" names no property of the build.
That is evidence about seven observed runs and nothing else. **The full gate
and runtime verification for Wave 1 are pending** against the current bytes, so
no wave is green and no required lint or static result is claimed here; a
pending gate is not recorded as a failed one, and the earlier red lint and
static figures belong to older bytes. The standard relay carrier, Bao and blob
transfer, production gossip send and disconnect actions, and live I/O remain
unimplemented; those are Waves 2–4.

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
