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
- **M9 — dispatch, and the endpoint over it.** `src/router/router.zig`,
  `src/endpoint/endpoint.zig`, `src/endpoint/incoming_filter.zig`. The filter
  is a vtable. The accept loop is a function of `(state, event)` and takes no
  `Io` at all: the two operations that need a runtime — spawning a task and
  cancelling one — are named as `Action`s and performed by the caller with
  the `Io` it already holds for the socket.
- **M10 — the holepunch gate.** `src/net/holepunch.zig`.
- **M11 — gossip and blobs.** `src/gossip/`, `src/blobs/protocol.zig`.

## Next

The stack accepts a QUIC connection and cannot originate one, and nothing
under `src/` owns a socket. Both halves are next, and neither is visible from
the module list.

- **A dial path.** There is none anywhere under `src/`. `quic_bridge.zig`
  owns a `quic.ConnectionManager`, which only ever runs a server, so the
  bridge is accept-side: `recv` (`:555`) takes a datagram the core did not
  have and hands back an `Ingress`, and `Conn.drain` (`:279`) hands back
  `batch.Send` values. Nothing originates a connection. The client half that
  does exist is a test helper — `Client` (`quic_bridge.zig:854`) builds a
  peer end with `quic.connection.connectInto` (`:888`) and is reachable only
  from test blocks. Promoting it is the first act, and one field decides
  whether it works: `TlsConfig.expect_peer_node_id` is client-only, so the
  pin a dialler needs is not the pin an acceptor enforces
  (`ClientAuth.expect_node_id`), and the translation has to set the right one
  on each side rather than the one that looks like a pin.
- **A socket.** `batch.zig` models what a socket is to be asked for —
  `Capability`, `Send`, `Runs`, `Recv`, `Cmsg`, `Refused`, `Report` — and
  stops before the `sendmsg` thin on purpose. Its module doc says "There is
  no socket here", and `Capability`'s own doc says the probe "needs a
  socket, so it is not here". So no one has asked the kernel what it can do:
  every batch falls back a segment at a time, and no `EIO` or `EINVAL` ever
  comes back to demote a `Capability`. What closes this is one file that
  opens a UDP socket, answers the two probes into a `Capability`, applies
  `socketOptions(family, coalesce)`, turns each run of a `Send` into one
  `sendmsg` carrying the `Cmsg`s `cmsg` already built, and reports a refusal
  as the `Refused` that `report` already turns into a `Report`.

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
