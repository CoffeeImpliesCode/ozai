# TODO

The plan is in [`docs/PLAN.md`](docs/PLAN.md); this is only the near-term
checklist, so that the next agent does not have to re-read the plan to find out
what "next" means.

## Done

- **M1 — identity and addressing.** `src/base/`. Pinned against iroh's
  published vectors.
- **M7, pure half — the synthetic-ULA construction and its inverse.**
  `src/base/ula.zig`, vector-pinned to iroh `1.3.0`. The allocation of an
  address to a key is `src/transport/addr_map.zig`; the socket is not built.
- **M2 — wire codecs.** `src/wire/postcard.zig`, `src/blobs/range_spec.zig`,
  and a fuzz harness that runs at every decoder boundary.
- **M3 — tickets and discovery records.** `src/ticket/`, `src/discovery/pkarr.zig`.
- **M4 — relay wire protocol.** `src/relay/frame.zig`, `client.zig`, `server.zig`.
- **M5 — address lookup.** `src/discovery/item.zig`, `resolve.zig`, `dns.zig`.
- **M6 — net report and NAT classification.** `src/net/report.zig`.
- **M8 — the QUIC substrate.** `vendor/quic/`, 33 files, no socket, no clock,
  no global entropy, no libc. See
  [`DECISIONS/0001-transport-substrate.md`](DECISIONS/0001-transport-substrate.md)
  for the execution record and what it cost.
- **M9 — dispatch half.** `src/router/router.zig`.
- **M10 — the holepunch gate.** `src/net/holepunch.zig`.
- **M11 — gossip and blobs.** `src/gossip/`, `src/blobs/protocol.zig`.

## Next

- **M9, remaining half — the endpoint itself.** `src/endpoint/`: the accept
  loop over a live connection, `IncomingFilter` in the run rather than in the
  router, and graceful close. The router's dispatch table and the shutdown
  ordering are done; what is left needs a connection that actually exists.
- **Wire `ozai.transport` to the vendored core.** M8's last step is not
  finished: the module is declared, compiled and tested, and
  `src/transport/quic_bridge.zig` is the work in flight that makes something
  under `src/` import it.

## Open, and not yet closable here

- **0-RTT.** `session_ticket` and `ticket_key` carry it and the certificate
  patch did not discharge it. `0001` records it as open.
- **Interop.** The requirement that this stack talks to more than one
  implementation is undischarged. Upstream's matrix cannot be reproduced from
  this repository — its runner is a submodule outside the published package —
  so it has to be re-established against this fork or not at all.
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
