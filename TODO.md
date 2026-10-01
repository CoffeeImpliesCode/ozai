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
  conditions, and the ceilings are the ones that file actually uses: every
  child in it gets `--for 30000`, and every parent wait gets 60000 ms, with
  one exception. The serving relay that carries a datagram for a peer besides
  gets a single pass, because a refused command line never becomes a node to
  bound, and a long watchdog there would only put the failure further behind.
  Sixty nominal passes at the node's 250 ms poll interval with a 2× slack
  allowance is the first number, and the second is twice that again, covering
  the final report and the reap. No test on the passing path waits for either.
- **A relay reached by URL across real sockets.** `test/relay_wire_test.zig`
  and `test/two_process_test.zig` cover delivery and independent shutdown.
- **The relay's outbound frame bound.** `relay/frame.zig` owns the text bound
  and rejects an oversized frame before writing it. The node checks its frame
  room against that bound at comptime.

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

## Open, and not yet closable here

- **0-RTT.** `session_ticket` and `ticket_key` carry it and the certificate
  patch did not discharge it. `0001` records it as open.
- **Interop.** The requirement that this stack talks to more than one
  implementation is undischarged, and there are two independent blockers.
  Upstream's matrix is not reproducible from this repository — its runner is
  a submodule outside the published package — so it has to be
  re-established against this fork. And it cannot be run on this node at
  all: `docker` and `quic-network-simulator` are both absent (`podman`
  too), while `tshark` is present. So the matrix needs a node that has the
  toolchain, and until one does, nothing here has spoken to an
  implementation that is not its own test suite.
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
- The recorded run executes coverage and both `cross-test.profile.sh` rows:
  instrumented tests, native GNU tests and native musl tests each pass 543/543.
  Coverage source-line zeros are not automatically unexecuted branches;
  accepted cold-region decisions and the missing `devenv` sandbox are in
  [`README.md`](README.md). Interop and 0-RTT remain open.
