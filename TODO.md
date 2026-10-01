# TODO

The plan is in [`docs/PLAN.md`](docs/PLAN.md); this is only the near-term
checklist, so that the next agent does not have to re-read the plan to find out
what "next" means.

## Done

- **M1 — identity and addressing.** `src/base/`. Pinned against iroh's
  published vectors.
- **M2 — wire codecs.** `src/wire/postcard.zig`, `src/blobs/range_spec.zig`,
  and a fuzz harness that runs at every decoder boundary.
- **M3 — tickets and discovery records.** `src/ticket/`, `src/discovery/pkarr.zig`.
- **M4 — relay wire protocol.** `src/relay/frame.zig`, `client.zig`, `server.zig`.
- **M5 — address lookup.** `src/discovery/item.zig`, `resolve.zig`, `dns.zig`,
  and `dial_source.zig`, which asks every resolver, merges with `item.merge`,
  takes `item.winner` and dials what the network said.
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
  [`DECISIONS/0001-transport-substrate.md`](DECISIONS/0001-transport-substrate.md)
  for the execution record and what it cost.
- **M9 — dispatch, the endpoint, and the dial path.**
  `src/router/router.zig`, `src/endpoint/`, `src/transport/dial.zig`, and
  `src/discovery/lookup_io.zig` for the retrieval seam the dial named and
  stopped at.
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

## Next

Everything below is reachable on this node. The one thing that is not is at the
bottom of this file.

- **A relay reachable over a real network.** The relay runs inside one process
  and is driven by `src/node/`, but nothing has yet put a relay on one side and a
  client on the other across an actual socket pair. That is the shortest path to
  proving the two-queue invariant and the admit-once guard against traffic
  rather than against a loopback pair that already trusts itself.
- **The gate inputs probes cannot supply.** `src/net/holepunch_run.zig` names
  them: a probe can give the local set and the varies-by-destination verdict,
  and cannot give the peer's candidate addresses, the connection, what the QUIC
  stack said, a path's status, or the socket's interface addresses. Each needs a
  producer or an explicit admission that it is out of scope.
- **`send_token` is recorded, not performed.** The endpoint's action for a retry
  token has nowhere to go: the vendored core exposes no per-attempt retry hook.
  Either the core grows one — which is a vendor patch and needs a
  `VENDORED.md` entry — or the action is removed as unperformable. **Leaving an
  action named but unreachable is the kind of thing this project's own rules
  call dead weight.**
- **The relay's outbound frame bound.** `.close`'s denial frame carries a
  peer-controlled reason string with no bound, and `relay_out` is sized so a
  frame longer than `room - varint_max` cannot be written. Decide what a relay
  may send: bounded reason, or reserved worst-case room.

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
- `vendor/quic` is upstream code and is excluded from `fmt`, `zlint` and `zbc`
  on purpose. `test/vendored_invariants.zig` is what pays that exclusion back:
  it fails if a socket, a clock, a global entropy source or a libc call returns
  to the vendored tree.
