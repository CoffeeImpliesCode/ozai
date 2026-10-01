# ozai

Dial a node by its id, not its address.

ozai is a from-scratch Zig 0.16 reimplementation of the [iroh] P2P stack — the
part that makes a device reachable by a 32-byte public key across hostile
networks, and the protocols built on top of it. It is not a binding, a
translation, or a wrapper. Where iroh's shape fits Zig, ozai keeps it; where it
does not, ozai says so and diverges on the record.

[iroh]: https://github.com/n0-computer/iroh

## Status

**Milestones 1–11 are built.** `test/loopback_test.zig` verifies peer identity
from the certificate, moves bytes both ways, and carries ECN over a real socket.
`test/relay_wire_test.zig` and `test/two_process_test.zig` exercise relay
forwarding, payload delivery, and independent shutdown on loopback.

External iroh interoperability and 0-RTT remain open. The gossip state machines
run, but the node does not yet encode their messages on the wire.

Verified on this node: the direct `zig-gate` passes all nine sections over the
56-file non-vendored Zig tree, with zero lint/static-analysis findings.
Debug and ReleaseSafe each pass 543/543 tests; the full GNU and musl rows
also pass 543/543, with no build-only or missing-runner result. All seven
decoder fuzz targets completed another 10 000 mutations without a crash.
The actual CLI delivered exact payloads over IPv4 and IPv6. Under one-CPU
load, all 30 process scenarios and 30 immediate-banner SIGTERM runs passed.

The instrumented suite passes 543/543 with its matching node children.
Progress measures 35/35 source lines; the CLI measures 172/310. These are PC
line counts, not branch coverage. Accepted cold regions: unsupported-session
ABI panics (0/16), exceptional kernel interruptions/refusals not forced by
these runs, and compile-time/elided or fixture rows without owning counters.
CLI refusal guards were separately smoke-tested; no duplicate tests were
added to inflate counters. The two pre-existing map allocation-fault gaps
are recorded with their trigger in [`TODO.md`](TODO.md).

The local `devenv` launcher still cannot enter its missing shared sandbox at
`/tmp/devenv-sbox`. The direct gate command below passed; no
global temporary storage or launcher was repaired.

| Module | What it is |
|---|---|
| `src/base/` | `NodeId`, `SecretKey`, `Signature`, `RelayUrl`, `IpAddress`, `SocketAddr`, `CustomAddr`, `TransportAddr`, `NodeAddr`, and the two base32 alphabets. A sorted, duplicate-free address set, which is what makes a ticket a stable identifier. |
| `src/wire/`, `src/blobs/` | The postcard codec, `RangeSpec`, and the blobs protocol. |
| `src/ticket/`, `src/discovery/` | Both ticket kinds, the pkarr signed packet, the item model, the resolvers, and the fan-in that runs them and dials the address the merge picks. |
| `src/relay/` | The relay frame codec and both relay state machines. |
| `src/net/` | The net report fold, the NAT classifier, and the holepunch gate. |
| `src/transport/` | The synthetic-ULA allocation, the GSO/GRO/ECN seam and its socket, the bridge to the QUIC core, and the dial path. |
| `src/router/`, `src/endpoint/` | ALPN dispatch, the accept loop, and the incoming filter. |
| `src/gossip/` | HyParView, PlumTree, and a deterministic in-process simulator. |
| `vendor/quic/` | The sans-IO QUIC core, 33 files, pinned by commit. No socket, no clock, no global entropy, no libc. |

Every wire format is pinned to bytes captured from the Rust implementation at a
named commit. A claim with no captured bytes attached does not go in.

Read [`docs/PLAN.md`](docs/PLAN.md) for the milestone order and the reasoning,
and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module tree, the
invariants a port must not break, and every point where ozai deliberately
differs from upstream in one place.

The transport substrate was the one decision in this project that could not be
reversed cheaply, so it was made first and written down.
[`docs/DECISIONS/0001-transport-substrate.md`](docs/DECISIONS/0001-transport-substrate.md)
records what it was decided on, what it actually cost, and what would make it be
revisited. `vendor/quic/VENDORED.md` records what was taken from it, what was
left behind, and every patch ozai applies.

## Build

```sh
direnv allow          # once
zig build             # static library + the node binary, both installed
zig build test        # unit + integration tests
zig build run-ozai-node-id
devenv shell -- gate  # fmt, build, test, ast-check, ziglint, zlint, zbc, zwanzig, cross-test
devenv shell -- gate-strict  # same gate without zbc, plus coverage
```

`zig build run-ozai-node-id` prints this machine's node id in every form ozai
puts on the wire, and signs the rendered address to prove the text form is
faithful to the value.

`zig build run-ozai-node -- --progress --for 30000` emits live counter changes
after completed passes. Each `progress:` line is flushed immediately. Supervisors
can wait for a connection, delivery, or departure before sending SIGTERM.
Without `--progress`, the node prints only its banner and final report.
The SIGINT/SIGTERM handlers are installed before the listening banner is published.

`devenv shell -- gate` needs the pinned toolchain in `~/.local/bin` and the
shared devenv sandbox it wraps; both `nix` and the wrapper resolve to that one
sandbox. Where it is absent, run the driver with the exclusions spelled out by
hand, because `GATE_EXCLUDE` is what makes it the same gate, `.envrc` does not
set it, and the driver takes no other source for it:

```sh
GATE_EXCLUDE='^[.]/vendor/ /[.]zig-cache/ /zig-out/ /zig-cache/ /zig-global-cache/' zig-gate
```

A bare `zig-gate` is not that configuration. With those exclusions it is the
whole of `scripts.gate.exec` bar the version cross-check, which is one `zig
version` against `.minimum_zig_version`.

The driver runs the sections in the order above and prints one line for each:
`OK`, or a count beside the tool's exit status. Any section that finds
something marks the whole run failed — `zbc` is the one exception, advisory
unless `ZBC_STRICT=1` — and the driver ends on `GATE FAILED` and exit 1. The
section output names each failure; the exit status reports overall failure, not
a standing claim that the tree is clean.

`gate-strict` is that gate with exactly two changes: `--no-zbc` drops the `zbc`
section and nothing else, so fmt, build, test, ast-check, ziglint, zlint,
zwanzig and cross-test all still run, and `--cov` adds coverage on top, which
is advisory until `ZIG_COV_FAIL_UNDER` is set. It is a design pass that a
failing zbc advisory cannot block, not a cheaper gate.

`GATE_EXCLUDE` names what is not this project's source: `vendor/quic`, plus
`.zig-cache/`, `zig-out/`, `zig-cache/` and `zig-global-cache/`. It overrides
the driver's built-in default rather than adding to it, which is why the
default's patterns are spelled out here. `vendor/quic` is excluded on purpose
and pays that back through `zig build quic-test`; the cache roots are there
because a lint section reports whatever the file list hands it, and build
output is not a defect.

`cross-test.profile.sh` selects Linux `x86_64` with GNU libc and musl.
Both rows built and ran the full 543-test suite with their matching node
artifacts. This proves the two native libc ABIs, not foreign architectures.

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

Reference checkouts use the paths below when available. They are read-only:
never edit them, commit them, or add agent rules. The iroh checkouts are absent
on this node; the vectors cite GitHub primary sources pinned by commit.

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
