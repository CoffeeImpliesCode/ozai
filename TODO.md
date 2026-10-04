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

- **Production randomness.** Repaired: `Node.create` draws 32 bytes from
  `io.randomSecure` into an owned `Csprng` (ChaCha) and zeroes the seed buffer
  with `std.crypto.secureZero`. `ozai-node` dropped `--seed` and no longer takes
  a caller-chosen generator seed. Explicit `std.Random` injection remains for
  deterministic test simulation.
- **Protected driver wind-down.** Repaired: `src/node/main.zig` wraps execution
  with an `errdefer` invoking `node.windDown(io, last)`, preserving original
  driver errors while ensuring graceful closure and descriptor release.
- **Connection ID reaping on completion.** Repaired: `src/node/node.zig`'s
  `expire()` calls `_ = self.offered.remove(conn.id())` when connections finish,
  ensuring bounded sequential connection churn without unbounded map growth.
- **No RFC 7250 negotiation.** The vendored TLS writes 44-byte Ed25519 SPKI
  certificates but negotiates no client/server certificate type, and
  upstream's raw-key resolver and verifier require that negotiation. Repair
  the ClientHello offers and the TLS 1.3 EncryptedExtensions selections — not
  ServerHello, not CertificateRequest — with fail-closed parsing and captured
  wire vectors, then prove both directions against a live Rust peer.
- **Relayed inner QUIC is not routed.** `drain` hands `Egress.to` straight to
  UDP, and the node already names the missing mapping. The private-carrier
  datagram exchange establishes no end-to-end QUIC session through a relay.

## Next

Everything below is reachable on this node. The one thing that is not is at the
bottom of this file.

- **The four gate inputs nothing supplies.** `src/net/holepunch_run.zig` takes
  seven. Three have a producer there: the local set and the
  varies-by-destination verdict from `observeReport`, and the peer's candidate
  addresses from `observePeer`. The four that do not are the connection to
  punch on, what the QUIC stack said about a round, whether a path carried
  traffic, and the socket's interface addresses. Each needs a producer or an
  explicit admission that it is out of scope.
- **The retry token's hook lives in `vendor/quic/`.** A retry token has nowhere
  to go, so the action was removed rather than left unperformable:
  `Action.send_token` does not exist, and the router's `send_retry` verdict —
  still produced, still reachable — now resolves to `.refuse`, which is what
  upstream does when `incoming.retry()` returns an error
  (`protocol.rs:583-586`). What is missing is in the vendored core: no hook
  runs before `acceptConnection`, so a peer that asks for a Retry is refused
  rather than answered. Closing that is a vendor patch and needs a
  `VENDORED.md` entry.
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
- **Interop.** No Rust iroh exchange has run, and self-interoperation proves
  nothing about one. Two things are separable. Upstream's full matrix needs
  `docker`, `quic-network-simulator` (both absent, `podman` too) and a runner
  that is a submodule outside the published package, so it is not reproducible
  from this repository and needs a node that has the toolchain. The first
  native partner leg, locked to iroh 1.3.0, needs none of those: Rustc and
  Cargo 1.98.1 work with the configured root, and the earlier "no default
  toolchain" answer came from a wrong inherited `RUSTUP_HOME` rather than a
  missing install.
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
- Cross-validation separates the full Linux socket/process suite in
  `cross-test.profile.sh` from 503 tests in 32 pure project modules across all
  108 pinned compiler libc ABI targets in `cross-test.portable.profile.sh`.
  The 32 are the previous 29 plus the QUIC bridge, the dial path and the
  discovery driver, pure for the same reason as the rest; the three
  socket-owning live roots stay out. 503/503 is what the expanded root measures
  natively in Debug and ReleaseSafe, and those tests are also reached from the
  package roots, so the portable total is never added to the package suite's.
  The last 108-target portable survey — 53 run, 37 build-only, 18 SDK
  failures — predates those three modules and describes the older 29-module,
  438-test root, so it has to be rerun before its counts describe this one.
  The vendored sans-IO core, 560 tests, is a separate step
  (`zig build quic-test`) and is not part of that portable matrix; its canonical
  cross row is likewise still being measured, and the earlier one predates the
  pure-address and fixture corrections.
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
  untouched. Interop and 0-RTT remain open.
