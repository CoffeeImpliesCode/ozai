# TODO

The plan is in [`docs/PLAN.md`](docs/PLAN.md); this is only the near-term
checklist, so that the next agent does not have to re-read the plan to find out
what "next" means.

## Done

- **M1 — identity and addressing.** `src/base/`. Pinned against iroh's
  published vectors.
- **M2 — wire codecs.** `src/wire/postcard.zig`, `src/blobs/range_spec.zig`,
  and seven decoder fuzz targets.
- **M3 — tickets and discovery records.** `src/ticket/`, `src/discovery/pkarr.zig`.
- **M4 — relay wire protocol.** `src/relay/frame.zig`, `client.zig`, `server.zig`.
- **M5 — address lookup.** `src/discovery/item.zig`, `resolve.zig`, `dns.zig`,
  and `dial_source.zig`, which asks every resolver, merges with `item.merge`,
  takes `item.winner` and dials what the merge picked. It fetches nothing
  itself; the answers arrive as values.
- **M6 — net report and NAT classification.** `src/net/report.zig`, and
  `probe_run.zig`, which executes a probe `Step` against an injected transport
  and folds what it measured.
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
  `src/net/holepunch.zig` and `holepunch_run.zig`.
- **M11 — gossip and blobs.** `src/gossip/`, `src/blobs/protocol.zig`.
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

## Next

The gate work below is reachable on this node. The largest unwired body of work
is not on this list; it is counted once in
[`README.md`](README.md#what-is-built-and-tested-but-not-yet-reachable-from-a-node).

- **Three of the seven gate inputs, not four.** `src/net/holepunch_run.zig`
  takes seven. Three have a producer there: the local set and the
  varies-by-destination verdict from `observeReport`, and the peer's candidate
  addresses from `observePeer`. `src/net/interface.zig` closed a fourth — "the
  socket's interface addresses", which `holepunch_run.zig`'s own table used to
  call a gap — by enumerating interfaces with `getifaddrs` and comparing two
  reads. **Three remain open**: the connection to punch on, what the QUIC
  stack said about a round (`qnt` is not in the vendored core), and whether a
  path carried traffic (there is no multipath layer). Each needs a producer or
  an explicit admission that it is out of scope.
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

## Open, and not yet closable here

- **0-RTT.** `session_ticket` and `ticket_key` carry it and the certificate
  patch did not discharge it. `0001` records it as open.
- **Interop.** The opt-in process/socket smoke now proves a TLS handshake and
  application-stream exchange with strict `noq` 1.3.0 and stock iroh 1.3.0.
  It covers four client/server routes and passes in Debug and ReleaseSafe.
  `README.md` records the command and the proof boundary.
  The full upstream matrix remains open and is still not reproducible from this
  repository: its runner is a git submodule outside the published package.
  This node has `tshark`, but lacks `docker` and
  `quic-network-simulator`. The matrix still needs a node with that toolchain.
  Mixed blob/gossip/relay protocol interoperability, NAT and node-level 0-RTT
  also remain open.
- **Willow and docs** stay out of scope, as the plan says.

## Standing constraints

- Wire compatibility is a golden-vector test, never a comment. A claim with no
  captured bytes attached does not go in.
- The foreign checkouts under `~/projects/github-n0-computer-iroh*` are
  read-only. Never edit them, never commit them, never add agent rules to them.
  **They are not present on this node** — every vector in this tree was
  captured from GitHub primary source with `gh api` and pinned by SHA.
- `zig-gate` binaries live in `~/.local/bin` and are version-pinned. They are
  not taken from `devenv` `packages`, and `zig` is not either.
- `vendor/quic` is upstream code and is excluded on purpose from every gate
  section that reads the tree as text — `fmt`, `ast-check`, `ziglint`,
  `zlint`, `zbc`, `zwanzig` — by the one `GATE_EXCLUDE` pattern, so the list
  never has to be kept in step with the driver's sections.
  `test/vendored_invariants.zig` is what pays that exclusion back: it fails if
  a socket, a clock, a global entropy source or a libc call returns to the
  vendored tree.
- Cross-validation separates the full Linux socket/process suite in
  `cross-test.profile.sh` from the pure project root in
  `cross-test.portable.profile.sh`, across all 108 pinned compiler libc ABI
  targets. **Counted 2026-10-06 from `src/portable_test.zig`: 100 pure project
  modules, not 32.** The method is one `grep -o '@import("[^"]*")'` over that
  file excluding `std`, deduplicated: 100 unique project imports and 100
  matching `refAllDecls` calls, no duplicates. The root's own closure is
  larger again — 236 files reachable by `@import` from it, carrying 1001
  top-level `test` blocks by static count. The 32-module, 463-test figure in
  this file was a snapshot of an earlier expansion and no longer describes
  the tree. The **executed** test count for this root is not stated here: it
  needs `zig build test-portable`, which this entry does not record, and a
  static `test`-block count is not an executed count. The last 108-target
  portable survey — 53 run, 37 build-only, 18 SDK failures — predates even the
  32-module root and has to be rerun before its counts describe this one. The
  vendored sans-IO core, 467 tests, uses the same matrix with `--step
  quic-test`; its canonical row is likewise still being measured, and the
  earlier one predates the pure-address and fixture corrections. Core path
  addresses stay pure values; kernel conversion stays in the socket seam.
  Emulation budgets do not replace payload, order or virtual-time checks.
  Exact executed/build-only/failed counts, toolchain
  limits, native coverage and accepted cold regions are in
  [`README.md`](README.md); a build-only row is never a test pass. The portable
  entry point is explicit: update its imports and `refAllDecls` list when
  adding a pure module — the QUIC bridge, the dial path and the discovery
  driver are wired in for that reason — importing the live root or guessing
  purity would invalidate its non-Linux scope. Foreign GNU runs use private
  compatible loaders, the loader prefix passed per invocation as
  `QEMU_LD_PREFIX`; shared tools and global temporary storage remain
  untouched. Interop and 0-RTT remain open.
