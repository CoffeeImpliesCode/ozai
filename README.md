# ozai

Dial a node by its id, not its address.

ozai is a from-scratch Zig 0.16 reimplementation of the [iroh] P2P stack — the
part that makes a device reachable by a 32-byte public key across hostile
networks, and the protocols built on top of it. It is not a binding, a
translation, or a wrapper. Where iroh's shape fits Zig, ozai keeps it; where it
does not, ozai says so and diverges on the record.

[iroh]: https://github.com/n0-computer/iroh

## Status

**Milestone 1 — identity and addressing. Complete.**

Implemented, tested, and interoperable with iroh's own published vectors:

| Module | What it is |
|---|---|
| `src/base/base32.zig` | The two base32 alphabets the wire formats need: z-base-32 (pkarr labels) and hex-extended base32 (the DNS/TLS label). |
| `src/base/key.zig` | `NodeId`, `SecretKey`, `Signature`. Ed25519, deterministic signing, lexicographic ordering, hex / z32 / local-TLS-name encodings. |
| `src/base/addr.zig` | `RelayUrl`, `IpAddress`, `SocketAddr`, `CustomAddr`, `TransportAddr`, `NodeAddr`. A sorted, duplicate-free address set, which is what makes a ticket a stable identifier. |
| `src/base/ula.zig` | The synthetic-ULA map: the /64 prefix, the mapped port, and the classification of an address arriving off the wire. Pinned to upstream bytes; the allocation of an address to a key is not here. |

That last one is the pure half of M7, landed early because it is a value and
touches no socket; the transport seam around it is still plan. Everything above
that is plan, not code. Read [`docs/PLAN.md`](docs/PLAN.md)
for the milestone order and the reasoning, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module tree and the
invariants a port must not break.

There is deliberately no socket code yet. The transport substrate was the one
decision in this project that cannot be reversed cheaply, so it was made first
and written down:
[`docs/DECISIONS/0001-transport-substrate.md`](docs/DECISIONS/0001-transport-substrate.md)
records what it was decided on, what it costs, and what would make it be
revisited.

## Build

```sh
direnv allow          # once
zig build             # static library
zig build test        # unit + integration tests
zig build run-ozai-node-id
devenv shell -- gate  # fmt, build, test, ast-check, zlint, zbc
```

`zig build run-ozai-node-id` prints this machine's node id in every form ozai
puts on the wire, and signs the rendered address to prove the text form is
faithful to the value.

`devenv shell -- gate` needs the pinned toolchain in `~/.local/bin`; outside
devenv, run `zig-gate` from there directly for the same gate.

## Layout

```
src/root.zig            public surface
src/base/               identity and addressing — pure, no I/O
src/examples/           runnable proofs
test/                   integration tests, outside src/ so they are reachable
docs/                   plan, architecture, decision records
```

`src/base` never touches a socket, a clock, or an allocator it was not handed.
That is not a style preference: it is what lets a state machine be driven by a
test instead of by a network.

## Reference material

The Rust stack is checked out read-only beside this project and is never edited,
committed, or given agent rules:

| Checkout | Crate |
|---|---|
| `~/projects/github-n0-computer-iroh` | `iroh`, `iroh-base`, `iroh-relay`, `iroh-dns`, `iroh-dns-server` |
| `~/projects/github-n0-computer-iroh-blobs` | `iroh-blobs` |
| `~/projects/github-n0-computer-iroh-gossip` | `iroh-gossip` |
| `~/projects/github-n0-computer-iroh-tickets` | `iroh-tickets` |
| `~/projects/github-n0-computer-iroh-willow` | `iroh-willow` |
| `~/projects/github-n0-computer-iroh-docs` | `iroh-docs` |
| `~/projects/github-n0-computer-iroh-util` | `iroh-util` |
| `~/projects/github-lalinsky-zio` | the async substrate candidate |

## Rules for working here

[`AGENTS.md`](AGENTS.md) is binding. The parts that matter most: thread
`io: std.Io` explicitly, keep network logic pure over bytes, and treat any claim
of iroh interoperability as a golden-vector test rather than a comment.
