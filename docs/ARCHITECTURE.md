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
`SecretKey.generate` is an explicit entropy edge. It borrows `std.Io` rather
than hiding a process random source.

The socket and node drivers borrow `std.Io` per operation. Its backend and
userdata must outlive the operation and any task that uses them.
Runtime owners keep their allocator, but pure actions keep no socket handle.
See [`DECISIONS/0002`](DECISIONS/0002-async-substrate.md) for the runtime choice.

The current Linux driver uses `Io.Threaded`. `Io.Uring` cannot send a UDP
datagram in Zig 0.16.0, and `Io.Evented` uses Uring on Linux.
Neither runtime owns this stack's send path.

## Strict gate coverage boundary

The gate separates current uninstrumented checks from retained instrumented coverage.
Default always runs configured full checks and current Debug/ReleaseSafe builds and tests before retained validation.
Its test scope includes `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy`.
Format, syntax, ziglint, zlint, native ZBC, Zwanzig and configured cross-target checks remain required.
Missing cross-target runners mean build-only status, not runtime acceptance.
Default does not start a new instrumented measurement.
The legacy `refdecls`/`compile-all` names map to declaration sweeps within executed test roots, not separate driver sections.
Those roots belong to `test`, `test-portable`, `quic-test` and `test-gate-policy`.
`invariants` checks vendored source contracts. It does not replace core runtime tests.
Issue #2 also permits [named standalone-subsystem admissions](../TODO.md#issue-2-named-standalone-admissions).
These cover unused blob variants, ticket use/lifecycle/loss logging, interface discovery, topic tables, statistics, ECN policy, budgets and broader relay authorization.
The admitted models have no claimed Node consumer or real-route proof.
Challenge-authenticated relay, socket ECN and configured native candidates remain distinct implemented paths.

`measure.runSafetyModes(runner, zig)` shares the actual first two `buildMode` stages.
Both default and `measure` use those uninstrumented build/test stages for Debug and ReleaseSafe.
The explicit `measure` command also captures fresh instrumented coverage in both modes.
`record.validateRetained(gpa, io, env)` reads the required machine reference and calls the common full validator.
`validate <path>` uses the same full replay and requires the exact referenced path and file SHA-256.
These helpers use explicit allocators and `Io`. Temporary owners release their data after validation.

The machine ledger and Measurement use schema 3.
One `ozai-coverage-v2` fence requires `measurement: {path, sha256}`.
The reference must have a nonempty path and a 64-hex-character captured-file SHA-256.
The validator checks that hash before it trusts the manifest.
It binds the snapshot to current source, compiler, scope and both modes.
It checks source/artifact/raw/report hashes, raw completeness, ordered report rows, exact-PC projection and exact counters.
The complete positive DWARF numeric-row universe and direct-PC hit method remain unchanged.
Capture binds the original absolute runtime object path and SHA-256.
Replay rehashes that object independently of fresh `OZAI_COVERAGE_RT`.
The source inventory includes absent roots and test sources.
Cold DWARF rows can outnumber mapped PCs without corruption.
Coverage documents have a 64 MiB limit.

Stored `Measurement.cold_items` must match replay-generated tuples by content.
The identity fields are `mode`, `path`, `source_sha256`, `line` and `unit`.
Duplicates, omissions, stale metadata and extra tuples fail.
Ledger decisions must match exact cold tuples. Covered or stale extra decisions do not qualify.
Project-unmapped and source-unowned totals and hits must also match exactly.
Any missing reference or source/compiler/scope/artifact drift fails closed.
There is no advisory mode, opt-out, skip, old-schema fallback, tolerance or retry-to-green.

Issue #15 permits dated source-bound coverage with on-demand refresh.
Earlier schema-2 capture, replay and default-gate receipts are historical after the current source repairs.
Fresh schema-3 capture, exact all-cold dispositions, strict replay and the full default gate remain pending.
The [integration snapshot](../README.md#integration-snapshot-2026-10-08) records current normal-root `bg317` acceptance.
Debug and ReleaseSafe each passed 28/28 steps and 2538/2538 tests, including the repaired public consumer regressions.
Fresh schema-3 capture, full default gate and live smokes have not run.
This integration does not establish final acceptance or new wire-interoperability proof.
Rust interop and controlled-NAT evidence remain separate from this replay.
See the [README workflow](../README.md#strict-coverage-snapshot-workflow) for capture and validation commands.


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

**`/iroh-qad/0` is reserved and not offered, by decision.** The router holds
one ALPN reserved for iroh's own QUIC address discovery. `Builder.accept`
refuses it with `error.reserved_alpn`, and nothing registers it, so a table
built in this tree never offers it and a peer that negotiates it is dropped.
Both halves are deliberate, and the codec over the protocol's bytes
(`src/net/qad.zig`) is tested and deliberately unwired rather than forgotten.

`src/router/qad_route.zig` provides an uncalled `registerLast` route.
The reserved ALPN service is distinct from the native in-connection observed-address extension.
The vendor now supports its transport parameter and observed-address frames.
`node_build` passes opt-in `address_discovery_role` into bridge and dial connection configurations.
The default role is disabled.
`Conn.observedRoles` and `Conn.observedAddress` expose decoded native reports.
No production node/discovery consumer turns those reports into candidates or published addresses.
`observed_reporter` also has no node address-update consumer.

The Zig production route has no strict X.509 QAD client or mapping-learning consumer.
Rust's real QAD client learns a mapping from a standalone certificate service.
Configured `traversal.local_candidates` are caller-provided addresses, not learned mappings.
A runtime observed-address report is different from a configured address.
Peer identity and certificates do not prove a mapping.
Native wire support therefore does not justify offering the separate `/iroh-qad/0` service.
The router keeps that service reserved and unoffered.

### Public ownership and refusal boundaries

Blob transfer decisions are pure. The getter supplies a finite byte allowance to Bao verification.
The response header exposes `claimed_size`, not authenticated total size.
`verified_size` requires matching expected size or authenticated terminal data.
A nonterminal proof verifies selected payload only.
The claim can tighten the getter allowance without granting verification.
Missing data and provider refusal close the affected stream. Other provider errors still propagate.
Node supports GET only. `BlobSet` and `BlobClaim` have no Node transfer consumer.

Node owns root key copies in `config.secret` and optional `config.relay.client.secret`.
`wipeConfigSecrets` clears both on construction rollback and after nested runtime teardown.
Bridge, Dialer and relay client cleanup clear their own separate copies.
Caller-held keys, borrowed keys and independent byte copies remain the caller's responsibility.

DNS fallback retains one pending TCP connection across finite cancellation slices under the original request deadline.
Explicit global Resolver cancellation is terminal. Retrieval cancellation is operation-local and preserves Resolver reuse.
Real follow-up UDP queries passed after cancellation during UDP wait, pending TCP fallback and partial TCP fallback.
The current normal-root Debug and ReleaseSafe suites include these public regressions (`bg317`).
`Answer.records` owns TXT bytes. Lookup streams borrow those bytes and own their parsed items.
The parent keeps the answer alive through stream teardown.

Failed post-spawn child construction retains the actual process owner and its start error.
Cleanup errors and deadlines retain storage and identity until reap succeeds.
Process I/O must establish exact identity before a signal.
Deinitialization requires completed cleanup, not merely an expired watchdog.

Actual incoming gossip permits 4,096 encoded bytes. Outgoing admission requires fewer than 4,096.
Public preflight precedes startup timers, output, cache and statistics mutation.
Derived refill refusal preserves valid receive, departure and timeout cleanup without committing pending requests.
Peer-owned stream assemblies survive another connection for that peer closing.

QUIC assembly failure publishes no usable prefix and closes the connection.
First path abandonment instead requeues reliable retransmission and preserves packet-number history for ordinary ACKs.
The native sequence/last-local cancellation model is standalone, not a Node cancellation route.

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

`relay/tcp_processor.zig` owns the client and server protocol transitions.
Each processor takes a decoded event and explicit state.
It returns new state and at most two ordered actions, without sockets, clocks or allocators.
The TCP client and server decode bounded input through separate protocol drivers.
`tcp_http`, `tcp_forward`, `tcp_execution`, `tcp_listener`, `tcp_native_path` and `tcp_ws_processor` separate their remaining responsibilities.
`tcp_session.Transport` provides a borrowed read/write/close seam for deterministic I/O failures.
The default adapter uses the real TCP driver.
There is no public compatibility `Listener` or obsolete carrier module.
`node_close.closeConnections` drains each inner QUIC close through the mapped transport.
It then calls `node_relay_runtime.State.flush` before endpoint shutdown.
This bounded pass performs output only, without inbound or handshake work.
Partial writes and `WouldBlock` preserve queued bytes and carrier ownership.
An incomplete close leaves the endpoint live. Repeated close resumes the same pending output.
Remote application close code 0 proves completion in the mixed-relay smoke.
A timeout does not satisfy that contract.


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

The production route and generic gate have different inputs.
`node_holepunch.prepare` selects the smallest authenticated client connection ID.
`node_native.pass` restricts client initiation to that ID. Servers advertise and respond without initiating.
`prepare`/`received` compare that connection's accepted packet counter around each datagram.
Only accepted physical-source 1-RTT traffic records `.open`. Synthetic relay sources do not qualify.
This is not a per-path application-byte signal.
No production adapter supplies a Number-Time QNT round or mirrors native counters into the generic path table.
The generic holepunch gate and path policy remain standalone under the explicit admissions in
[`TODO.md`](../TODO.md#issue-16-checklist-disposition).

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
  It becomes a socket address only when its host is an IP literal;
  `socketAddr` answers `error.NotAnIpLiteral` for a name, because `base` has no
  `Io`, no allocator and no clock and name resolution belongs to
  `src/discovery/`. Upstream's DERP client parses `url.host` as a socket address
  outright, so the literal case is its shape and the named case is our open half.
  The production node can resolve identity-only addresses through `dns_live`
  and signed `pkarr_live` records. These routes resolve endpoint identities to
  advertised transport addresses. They do not make `RelayUrl.socketAddr`
  resolve a host name.
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
- **Native paths and synthetic addresses are distinct.**
  `Node.step` calls `node_native.pass` for negotiated native NAT/multipath connections.
  The driver installs caller-configured local candidates and reads vendor remote candidates.
  It selects a validated physical pair through `path_action.planSelect` and `multipath.applyAction`.
  The vendor admits only path IDs 0 and 1 for the connection lifetime, including retired IDs.
  `transport/multipath.Table` retains eight historical address pairs, not eight live core paths.
  Synthetic ULA addresses identify mapped transport routes, not native physical path IDs.
  Generic `path_table`, `path_select`, `path_revalidate` and `path_probe` remain standalone policy models.
  Their tables do not consume the native path byte counters.
  Native PATH_ACK reports packet-number ranges.
  PATH_ACK_ECN adds packet ECN counts, not byte counts or last-active times.
- **`TlsConfig` and `ClientAuth` carry different peer pins.** The client-side
  field is `expect_peer_node_id`; the server-side one is `ClientAuth.expect_node_id`.
  Upstream had `skip_cert_verify` and a `ca_bundle` on `TlsConfig` and treated
  the two directions as the same decision. They are not — a client verifies who
  it connected to, a server decides who to let in — and one field cannot carry
  both without a comment explaining which is which at every use.
