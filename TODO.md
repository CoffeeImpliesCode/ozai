# TODO

The plan is in [`docs/PLAN.md`](docs/PLAN.md); this is only the near-term
checklist, so that the next agent does not have to re-read the plan to find out
what "next" means.

## Done

What exists, not what is finished. Four of these milestones are partial and
the missing half is under **Next** or **Open** below.

- **M1 — identity and addressing.** `src/base/`. Pinned against iroh's
  published vectors.
- **M2 — wire codecs.** `src/wire/postcard.zig`, `src/blobs/range_spec.zig`,
  and the decoder fuzz targets the `fuzz` step declares in `build.zig`.
- **M3 — tickets and discovery records.** `src/ticket/`, `src/discovery/pkarr.zig`.
- **M4 — the relay wire protocol, below the carrier.** `src/relay/frame.zig`,
  `client.zig`, `server.zig`: the frame codec, the signed challenge, the
  registry, the two queues and exact-once disconnect. The carrier above them
  is the private QUIC `/iroh-relay/1`, not RFC 6455 WebSocket over an HTTP
  upgrade with TLS.
- **M5 — address lookup, as pure values.** `src/discovery/item.zig`,
  `resolve.zig`, `dns.zig`, and `dial_source.zig`, which asks every resolver,
  merges with `item.merge`, takes `item.winner` and dials what the merge
  picked. It fetches nothing itself; the answers arrive as values. `dns.zig`
  builds the TXT query only: there is no A/AAAA path, and `error.Truncated`
  is the RFC 1035 TC bit, not an empty answer.
- **M6 — net report and NAT classification.** `src/net/report.zig`, and
  `probe_run.zig`, which executes a probe `Step` against an injected transport
  and folds what it measured. Every transport it is given in this tree is a
  test fake.
- **M7 — the transport seam.** `src/base/ula.zig` (the synthetic-ULA
  construction, vector-pinned), `src/transport/addr_map.zig` (the memoised
  allocation, entropy injected), and `src/transport/socket.zig` (the
  `sendmsg`/`recvmsg` layer with the GSO/GRO/ECN model and the capability
  probe).
- **M8 — the QUIC substrate.** `vendor/quic/`, no socket, no clock, no global
  entropy, no libc, guarded by `test/vendored_invariants.zig`. See
  [`DECISIONS/0001-transport-substrate.md`](docs/DECISIONS/0001-transport-substrate.md)
  for the execution record and what it cost.
- **M9 — dispatch, the endpoint, and the dial path.**
  `src/router/router.zig`, `src/endpoint/`, `src/transport/dial.zig`, and
  `src/discovery/lookup_io.zig` for the retrieval seam the dial named and
  stopped at. `src/discovery/lookup_live.zig` is that seam crossed for real — a
  query on a `transport/socket.zig` datagram and the answer off it — and its
  only callers are its own tests. See **Next** for what is still missing.
- **M10 — the holepunch gate, and the join that feeds it.**
  `src/net/holepunch.zig` and `holepunch_run.zig`. The gate is pure; the punch
  itself is absent.
- **M11 — gossip state machines and blob framing.** `src/gossip/`,
  `src/blobs/protocol.zig`. No production gossip codec, no Bao verifier, store,
  provider or getter.
- **A program.** `src/node/` — owns sockets, drives its own loop, performs
  every `Action` the endpoint owes a caller, runs the relay, and winds down in
  the router's order. `zig build run-ozai-node`.
- **Proof over a real wire.** `test/loopback_test.zig` (handshake, identity from
  the DER encoding, streams, ECN), `test/protocol_loopback_test.zig` (four
  endpoints converging on one membership), `test/blobs_transfer_test.zig`
  (bytes, ranges, framing, EOF), and `test/two_process_test.zig` (two processes,
  independent teardown, both directions).
- **State-driven process tests.** `ozai-node --progress` exposes live counters,
  and `test/two_process_test.zig` observes handshakes, delivery and departure
  before it stops a child. Run durations are watchdogs, not readiness
  conditions. Parent observations retain their 60000 ms ceilings; children
  now get a 240000 ms fallback watchdog so those observations can finish
  before child expiry. Every passing test explicitly stops its children.
  The refusal guard remains short: a rejected command line never becomes a
  node to observe. Closed output pipes are not polled again, and premature
  EOF fails the observation rather than spinning until its deadline.
- **A relay reached by URL across real sockets.** `test/relay_wire_test.zig`
  and `test/two_process_test.zig` cover delivery and independent shutdown.
- **The relay's outbound frame bound.** `relay/frame.zig` owns the text bound
  and rejects an oversized frame before writing it. The node checks its frame
  room against that bound at comptime.

- **Production randomness.** Repaired: `ozai.node_lifecycle.create` draws 32 bytes from
  `io.randomSecure` into an owned `Csprng` (ChaCha) and zeroes the seed buffer
  with `std.crypto.secureZero`. `ozai-node` dropped `--seed` and no longer takes
  a caller-chosen generator seed. Explicit `std.Random` injection remains for
  deterministic test simulation.
- **Protected driver wind-down.** Repaired: `src/node/main.zig` wraps execution
  with an `errdefer` that calls `ozai.node_runtime.windDown(io, node, last)`,
  where `last` is the last instant a pass stamped, null until the first pass.
  Wind-down preserves the original driver error and releases the descriptor.
- **Connection ID reaping on completion.** The egress owner removes offered IDs
  when connections finish. Sequential churn does not grow that map without bound.
- **Wave 1 API cutover.** Canonical transport namespaces own connection,
  configuration, error, stream, datagram, and Retry APIs.
  `ozai.node_config.Config.protocols` registers one handler per ALPN.
  `ozai.node_protocol` owns handler and connection contracts.
  Node operations are free functions in their owning modules, not `Node` methods.
  Mixed-peer runtime receipts exist for both role orders; the full gate result
  against the current bytes is pending, so this bullet is not a Wave 1
  acceptance.
- **Actual mixed-peer proof, both role orders.** `install/bin/ozai-interop-peer`
  against the iroh 1.3.0 partner: seven live exchanges on the freshly built
  native binary `59b6a3ef…` against the partner `748f0fca…`. Three are payload
  runs — exits 0/0, exact peer IDs authenticated at both ends, one negotiated
  ALPN, and all six distinct payloads verified by both ends — bidi
  `0102030405`/`fafbfdfefe`, unidirectional `a1b2c3d4`/`10203040`, datagram
  `decafbad`/`11223344`; both role orders, plus one `--require-retry` run with a
  real Retry observed (`1 replies`). Four are typed refusals and are expected to
  fail: the two wrong-peer runs answer `error.BadCertificate` with TLS alert 42,
  and the two ALPN-mismatch runs answer `error.NoApplicationProtocol` with
  alert 120, each at exits 1/1 with nothing verified. Identities are by **role**,
  not by implementation: LISTENER secret seed `0x11` is `d04ab232…`, DIALER
  secret seed `0x22` is `a09aa5f4…`, and the native peer holds each role in a
  different receipt. The dial-side ALPN refusal is proved by
  `resume-w1-live-dial-alpn-mismatch-interpretation.json` — the raw receipt is
  preserved and nothing was rerun, because the throwaway checker that wrote it
  wrongly demanded a Rust literal; the typed proof is alert 120 from the partner
  plus the native read of `CONNECTION_CLOSE error_code=0x178`, both out of the
  bytes that receipt already carries. The receipts, binary digests and commands
  are in [`README.md`](README.md#current-wave-1-2026-10-05). That is mixed-peer
  evidence, not acceptance: the full gate result against the current bytes is
  pending.
- **Relayed inner QUIC is not routed.** `drain` hands `Egress.to` straight to
  UDP, and the node already names the missing mapping. The private-carrier
  datagram exchange establishes no end-to-end QUIC session through a relay.

## Next

Everything below is reachable on this node. The one thing that is not is at the
bottom of this file.

- **Wave 1 acceptance.** RFC 7250 certificate-type negotiation is implemented,
  and the actual native/Rust exchange succeeds in both role orders with typed
  negative cases in both. Current observed evidence: the Debug install of
  `ozai`, `ozai-node` and `ozai-interop-peer` is exit 0 at 7/7 steps
  (`resume-w1-native-debug-build.log`); the focused vendored TLS decode is 1/1
  after the certificate-type oracle repair — `resume-w1-tls-focused-before.log`
  is 1/1 failing at `test/tls_wire/messages.zig:333` in `certificateTypeShapes`,
  and `resume-w1-tls-focused-after.log` is 1/1 passing — and the cause was the
  oracle's one exclusive shape column forcing RFC 7250's offer and selection
  into a single verdict, not a `u16` production overflow: both production
  decoders were already correct. The QUIC wire-decode corpus replay is 1/1 under
  the `quic wire decode` filter; an earlier command that ran zero tests is not
  evidence. **A green focused run is not a green gate.** Wave 1 is not accepted.
  Outstanding, by name: **the full gate result against the current bytes is
  pending.** The required source lint fixes have landed; the earlier red lint
  and static figures belong to older bytes, describe those runs rather than this
  tree, and are kept under history in the gate record of
  [`README.md`](README.md#gate-record). A pending gate is not recorded as a
  failed one. The zbc disposition ledger is at a merge fixed point at 32 source
  proofs and 59 records (`scripts/gate_zbc_dispositions.zig` `sha256
  fb5f97f989ed8f11ba76d78a5c9e2c5fd780c94a78d9156aad682ae7f1ed4399`, byte-
  idempotent on re-emission, helper suffix preserved, dead relay-serve row
  retired to the split-moved tests module). The `docs/PLAN.md` module
  requirement is measured at 31 files, 28 production and 3 test-only, largest
  223 (`src/node/relay_state.zig`), zero violations at the 250-line limit. The
  vendored TLS client-auth flight is repaired end to end: the inverted empty-
  Certificate condition, the silent keyless client answered with an empty list,
  and the mislabelled `.optional` pin sub-case are all landed, and
  `zig build quic-test` is 564/564 green. Waves 2–4 remain unimplemented and
  unaccepted; the gossip-codec and substrate-citation blockers recorded for two
  of their phases are withdrawn as blockers — scouts reached the primary
  upstream APIs, authentic producers are being built against them and the
  citations are being re-anchored — and that withdrawal is not a result.

- **The four gate inputs nothing supplies.** `src/net/holepunch_run.zig` takes
  seven. Three have a producer there: the local set and the
  varies-by-destination verdict from `observeReport`, and the peer's candidate
  addresses from `observePeer`. The four that do not are the connection to
  punch on, what the QUIC stack said about a round, whether a path carried
  traffic, and the socket's interface addresses. Each needs a producer or an
  explicit admission that it is out of scope.
- **Retry acceptance.** Upstream already provides `require_retry` and
  `retry_threshold`. No vendor patch is needed to enable Retry.
  The first-party filter drops spent tokens only when the destination connection ID is not owned.
  An owned ID can carry later Initial packets from the same split ClientHello.
  It must not consume another accept slot or trigger another Retry.
  Verify the integrated admission path before claiming current acceptance.
- **No production driver performs a live lookup.** `lookup_live.zig` proves the
  seam against real sockets and the only callers of its `Datagram` are its own
  tests; `src/node/` never reaches for it, and every `net/probe_run.Transport`
  in the tree is a test fake for the same reason. A node today dials the peers
  its command line names. What a caller does with a live `Datagram` — merge the
  answers into the fan-in, or feed them to a probe run — is the missing half,
  and it needs a decision rather than a seam, because after it the answers come
  from the network instead of from a parameter.

- **Allocation-fault coverage debt: two existing map seams.**
  `transport/addr_map.zig` lacks fail-N coverage for `insert`'s reverse-map
  allocation rollback and `GetError.OutOfMemory`. Neither allocation path
  changed in this repair. Add the sweep before the next map allocation or
  storage-layout change; do not grow this two-seam debt.

## Open

- **Authenticated resumption and 0-RTT.** `session_ticket` and `ticket_key`
  carry them and the certificate patch did not discharge them. The core's
  pinned-client resumption currently requests a fresh client certificate
  *after* PSK selection and fails closed through `serverIdentityEstablished`:
  a recorded RFC 8446 deviation and an added compatibility limitation, not a
  live identity bypass. The replacement is an RFC-compatible authenticated
  design, or a full-handshake fallback while a pin is required. It must never
  drop the certificate request and accept an unbound ticket, and it lands only
  after a session store with proven ownership exists.
- **Interop.** Self-interoperation is not mixed-stack acceptance. Two
  requirements are separate, and only the native partner leg is recorded: the
  actual native/Rust exchange succeeds in both role orders against iroh 1.3.0,
  over the fixture ALPN `/ozai/w1-fixture`. Upstream's full matrix still needs
  `docker`, `quic-network-simulator`, and an unpublished submodule runner.
  `docker`, `quic-network-simulator`, and `podman` are absent here.
  The native partner leg, pinned to iroh 1.3.0, needs none of them.
  Rustc and Cargo 1.98.1 work with the configured root.
  The earlier "no default toolchain" error came from an incorrect inherited `RUSTUP_HOME`.
- **Willow and docs stay excluded**, not deferred. `iroh-docs` is signed-entry
  range-based reconciliation, not a Loro-backed implementation, and
  `iroh-willow`'s Rust generation is not the current Willow spec's default
  group choice. Neither enters this project without a later user decision.

## Standing constraints

- Wire compatibility is a golden-vector test, never a comment. A claim with no
  captured bytes attached does not go in.
- The foreign checkouts under `~/projects/github-n0-computer-iroh*` are
  read-only. Never edit them, never commit them, never add agent rules to them.
  **They are not present on this node** — every vector in this tree was
  captured from GitHub primary source with `gh api` and pinned by SHA.
- The house `zig-gate`, `cross-test` and lint binaries live in `~/.local/bin`
  and are version-pinned; they are not taken from `devenv` `packages`, and
  `zig` is not either. This repository's gate is `scripts/gate.zig`, reached
  through `devenv shell -- gate`, which names its compiler explicitly instead
  of resolving one through the `anyzig` shim.
- `vendor/quic` is upstream code. It is excluded on purpose from the gate
  commands that read the tree as text — `ziglint`, `zlint`, `zbc`, `zwanzig` —
  by being left out of `scripts/gate_scope.zig`'s first-party list, so the
  list never has to be kept in step with the driver's sections. `fmt` and
  `ast-check` see the whole tree, because the vendored code is compiled and
  checked like everything else. `test/vendored_invariants.zig` is what pays
  that exclusion back: it fails if a socket, a clock, a global entropy source
  or a libc call returns to the vendored tree.
- Cross-validation separates the Linux socket/process suite in `cross-test.profile.sh`
  from pure project modules in `cross-test.portable.profile.sh`.
  **Historical audit counts:** 503 tests in 32 pure modules, run natively in Debug and ReleaseSafe.
  Those 32 included the earlier 29, the QUIC bridge, the dial path, and the discovery driver.
  Portable tests overlap package tests. Never add their totals.
  The last 108-target survey recorded 53 executed, 37 build-only, and 18 SDK failures.
  It used the older 29-module, 438-test root, not the current source.
  The historical vendored core count was 560 tests in the separate `zig build quic-test` step.
  It was not part of that portable matrix.
  Current cross-platform verification remains pending.
  Core path addresses stay pure values; kernel conversion
  stays in the socket seam. Emulation budgets do not replace payload, order or
  virtual-time checks. Exact executed/build-only/failed counts, toolchain
  limits, native coverage and accepted cold regions are in
  [`README.md`](README.md); a build-only row is never a test pass. The portable
  entry point is explicit: update its imports and `refAllDecls` list when
  adding a pure module — the QUIC bridge, the dial path and the discovery
  driver are wired in for that reason — importing the live root or guessing
  purity would invalidate its non-Linux scope. Foreign GNU runs use private
  compatible loaders, the loader prefix passed per invocation as
  `QEMU_LD_PREFIX`; shared tools and global temporary storage remain
  untouched. The native-partner interop leg is recorded in both directions;
  upstream's full matrix and 0-RTT remain open.
