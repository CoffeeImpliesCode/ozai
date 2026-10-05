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

External iroh interoperability and node-level 0-RTT remain open. The gossip
state machines run, and the gossip wire codec is built and tested
(`src/gossip/codec.zig` and the six modules under `src/gossip/codec/`, with a
fuzz target), but the node does not yet call it: a `send_message` the layer
asks for is counted and its peer named, and nothing is encoded onto the wire.

### Current native gate record

Direct invocations of the pinned Zig 0.16.0 compiler on native x86-64 Linux.
The gate entry point does not run in this environment and was not used: its
`anyzig` shim re-downloads the pinned toolchain and fails to extract it, which
[`0004`](docs/DECISIONS/0004-vendored-core-contracts.md) records. No global
tool, sandbox or launcher was repaired, and nothing in the table below is a
cross-platform, iroh-interoperability or performance result.

| Section | Command | Result |
|---|---|---|
| Build, Debug | `zig build -Doptimize=Debug` | exit 0; 5/5 build steps |
| Build, ReleaseSafe | `zig build -Doptimize=ReleaseSafe` | exit 0; 5/5 build steps |
| Tests, Debug | `zig build test quic-test -Doptimize=Debug` | exit 0; 22/22 steps; 1159/1159 tests |
| Tests, ReleaseSafe | `zig build test quic-test -Doptimize=ReleaseSafe` | exit 0; 22/22 steps; 1159/1159 tests |
| Format | `zig fmt --check .` | exit 0, no output |
| Syntax | `zig ast-check`: 74 Zig files, 3 rechecks, 5 final-comment rechecks; manifest parsed separately | 82 source checks + 1 manifest parse, all exit 0 |
| Lint | `zlint -c zlint.json -f json -S` | exit 0; 0 errors; 24 vendored warnings |
| Static analysis | `zwanzig --threads 2` over 42 non-vendored changed files, 21 rules | exit 0; No issues found |
| Fuzz | `zig build fuzz --fuzz=10000` | exit 0; 21/21 steps; 10/10 targets, at least 10 000 new runs each, no crash |

**1159/1159 tests over 22 build steps** is the current figure, the same in both
modes. It is **599 package tests — 562 in the main test root plus 37 across
seven smaller integration and gate steps — and 560 in the separately built
vendored core** (`zig build quic-test`). No step reported a leak under the
test allocator.

The lint run is **0 errors and 24 warnings**, and every warning is under
`vendor/quic`: 16 `avoid-as` findings and 8 `suppressed-errors` findings on
bounded or deliberately best-effort core paths. No non-vendored finding was
reported. They are not described as zero lint findings.

`-S` is a valid invocation, and the file list went over stdin in the shape it
asks for: 74 changed Zig paths, one per line. An earlier retained run that
answered `WriteFailed` handed the same list as one JSON array, so a single line
of 2267 bytes overran the tool's fixed 1024-byte line reader; the same command
with one path from that list exits 0 and reports that file's own four
findings. Those runs are trace history for a caller that sent the wrong shape,
and they are lint evidence in neither direction.

Each of the ten decoder fuzz targets advanced by at least 10 000 new runs;
the largest advance is 10 213. The targets are the ten rows of `build.zig`'s
`fuzz_targets` table, one per decoder: `base32`, `range-spec`,
`endpoint-ticket`, `blob-ticket`, `pkarr`, `relay-frame`, `postcard`, `bao`,
`gossip-codec` and `ws-frame`. The `Runs:` counters those reports print are
cumulative across the retained corpus and earlier runs, so a counter is not
this invocation's work and the per-target advance is what the bound covers.

### The actual CLI

Six real `ozai-node` processes — a relay, a receiver and a sender in each of
Debug and ReleaseSafe — carried exactly the 21-byte payload
`api-cutover-live-wire` through the relay in both modes. Each sender reports
`relay out: sent 1`, each relay reports `forwarded 1`, and each receiver's
inbox holds one datagram of `bytes 21`, hex
`6170692d6375746f7665722d6c6976652d77697265`, from that sender's node id. All
six exited 0 after SIGTERM, each reporting `shutdown: closed` and a closed
socket. Their seeds were 401, 402 and 403: the CLI's fixed default is a replay
aid, not independent entropy for several processes.

### The out-of-tree consumer

Six programs built against the registered package modules: contract, TLS,
decoder, cancellation, core-wire and package-state consumers. All six passed
in Debug and ReleaseSafe, **18/18 build steps** in each mode. The two added
consumers exercise ownership, state transitions and decoded wire values,
not source text or counter percentages.

The 18 build steps, six programs and 50 000 decoder cases per mode are
separate counts from the native 1159/1159 suite. None is added to that suite.

What each program observed, the same in both modes:

- A const view of 1122 bytes over a fixed buffer stream. An allocation refusal
  that retained 62 bytes and drained them on one retry, with the second drain
  empty. A `Join` copied after it had observed a report, still answering about
  its own recorded candidate. A client Initial of 1200 bytes that parses as an
  Initial.
- A pinned full handshake. ChaCha resumption with v1 early keys after a v2
  negotiation. A v2 ticket sealed under the version that connection ended on.
  A ticket whose issuing version did not match, falling back to a full
  handshake. v2 early payload decrypted under the negotiated keys. The
  handshake's own first flight went out as 296 bytes at Initial level.
- A seeded sweep of 50 000 bounded transport-parameter, frame, DER,
  ClientHello and ServerHello cases per mode, driven from seed `0xdec0de` and
  one fixed clock, so a run is a function of its seed and nothing else. Fixed
  vectors on top of it: 127 DER refusals, each read through both of the routes
  a caller has; 27 `version_information` refusals; 2 `version_information`
  accepts, one of them a ten-entry list whose ninth and tenth entries validate
  and are then dropped; and a zero-budget CRYPTO pop that returned no frame,
  moved no cursor, kept its queued bytes and produced the expected frame once a
  4-byte budget was given. The refusal switches carry no `else` prong, so they
  are exhaustive over the decoders' declared error sets at compile time.
- Eight concurrent cancellation fires collapsing into one producer stop, with
  the pending timeout answered `Canceled`.
- A 45-byte unidirectional STREAM decrypted from a 74-byte datagram, with the
  exact stream id, offset, FIN and 45-byte flow-credit debit. An empty loss
  result that claims, releases and reuses its owner. One valid preferred
  address and six exact refusals. A queued close decoded at Initial and
  Handshake levels in one 1200-byte datagram, retained for the higher level
  without consuming congestion credit.
- Duplicate custom-address spellings collapse by value; owned payloads survive
  overwriting and freeing the input. Populated membership/topic quit disconnects
  the right peers and leaves both gossip layers inert. Three shuffle reply
  situations preserve origin and peer identities. A 160-entry registry survives
  six churn rounds with correct connections, queued bytes and packet borrows.

Three earlier attempts at that same run failed in the consumer's own source,
not in this package: an `else` prong left on an error switch this cutover had
made exhaustive, an array repeat written with a runtime length, and
`Connection.connectInto` written as a struct member where the registered
function is `quic.connection.connectInto`. The instrumented Debug run also had
to link the fuzz runner's seven `runner_*` symbols; the bridge for them is the
package's own shipped `test/coverage_abi.zig`, attached to each consumer root,
and it panics if anything reaches it. That is a harness arrangement and not a
claim that those symbols are a production surface. Those receipts are kept as
trace history for the fixes above, not as a current blocker.

A declared-source archive also passed through `zig fetch` and the native
hash-cached dependency route. All six programs passed again in Debug and
ReleaseSafe, with 18/18 steps in each mode. At archive creation, the extracted
dependency matched all 74 changed Zig files and 16 required shipped files byte
for byte. These include the rules, lint config, both cross-test profiles, and
architecture/decision records; later proof-only receipt wording is not that snapshot.

Fetching the working directory itself returned `error.IllegalFileTypeInPackage`.
The archive follows `build.zig.zon.paths` and excludes local environment and
cache artifacts. No user environment file was removed to make the fetch pass.

### Current coverage measurement

One instrumented run measured this source. `zig build test quic-test
-Doptimize=Debug -Dcoverage=true -Dcoverage-rt=<zig-cov-rt.o>` exited 0 at
22/22 steps and 1159/1159 tests — 599 package tests with their matching
`ozai-node` children, and 560 in the separately built vendored core, which ran
again as an instrumented artifact through the out-of-tree consumer harness's
`coverage-core` step, exit 0, 3/3 steps, 560/560. This is not a repository step.
Forty-one fresh raw counter files from 15 binaries merged into 15 normalized
PC tables with saturating counts. The six instrumented consumers are included.
`zig-cov report --format=json` exited 0 and wrote the report.

The report combines **instrumented block counters and inferred source-line
attribution**. It expands executed block addresses through DWARF line tables,
then applies a conservative source-conditional filter. Line hits count retained
attributions, not statement executions. Zero can mean withheld attribution,
even when a separate runtime observation proves that the body ran.

The report spans 79 entries: 76 repository files and 3 libc startup assembly
files. It reports **20 142 / 36 814 attributed source lines (54.71 %)** and
**30 502 / 75 108 instrumented blocks (40.61 %)**. The repository-only line
figure is 20 130 / 36 789 (54.72 %). Function counters are absent.
These are not branch or path measurements.

For added or replaced nonblank, non-comment lines in 74 changed Zig files,
1 946 have positive attribution, 2 338 have zero attribution, and 1 827 have
no report row. An absent row does not prove that the compiler emitted no code.
The pinned compiler's AST places 2 084 zero rows inside test declarations.
The remaining 254 contain 111 private test-helper rows and 143 production rows.
This classification separates fixtures from code. It does not turn zero rows
into branch coverage. Raw counters, exact AST spans and logs remain outside
the repository.

All 143 production zero rows have a per-function disposition in the retained
measurement evidence. Runtime checks independently confirm drain retry, gossip
quit/shuffle, registry churn, empty loss ownership, unidirectional send, close
coalescing, preferred-address decoding and ticket resumption. Zero attribution
is accepted for their field stores, continuations and reporter-filtered bodies;
the exact compiler/filter cause is not inferred.

Unforced combinations remain explicit: successful Retry ODCID installation;
duplicate peer reset tokens; HelloRetryRequest certificate-policy reinstall;
late constructor/stream cleanup and individual packet-mode error catches;
scratch control-frame encoding failures and alternate quota/no-room exits;
and the connection-level refusal of a peer CID limit below two. The codec
consumer's ability to encode one is not proof of that last TLS-driven refusal.
These are accepted coverage limits, not unresolved scoped API defects.
Reopen a listed combination when its state, validator, cleanup or packet mode
changes. Unsupported fuzz-runner ABI calls and actual kernel segmentation
refusal were not forced; injected socket refusals are not kernel evidence.


### What this record does not cover

The cross-platform survey and its toolchain limits are reported by
`cross-test` below and by
[`0004`](docs/DECISIONS/0004-vendored-core-contracts.md). No iroh
interoperability, no performance number and no node-level authenticated
0-RTT is claimed.

### What is built and tested but not yet reachable from a node

This is the tree's largest gap and it is a wiring gap, not a correctness one.
**165 of the 281 modules the build compiles are not reachable from
`ozai-node`** — 153 production modules and 12 `_test.zig` files. They carry
tests, several carry fuzz targets, and none of it can run in a live node
because nothing in `src/node/` imports it.

The count is taken by crossing the tree module by module from
`src/node/main.zig` and the three `src/node/` files it imports at top level,
treating `src/root.zig` as what it is — a facade of `pub const` re-exports that
would otherwise make every module in the tree look reachable. Only the
re-export names the binary actually references drag a module in. Liveness is
per module rather than per call path, so a module reached by an untaken branch
counts as reachable and the figure above is a **lower bound** on what is
unwired.

By directory, the 153 production modules are: `src/discovery/` 35,
`src/net/` 37, `src/relay/` 23, `src/blobs/` 19, `src/node/` 9,
`src/transport/` 7, `src/gossip/codec/` 6, `src/gossip/` 5, `src/crypto/` 4,
`src/ticket/` 4, `src/gossip/plumtree/` 2, `src/root.zig` itself, and
`src/router/qad_route.zig`. The largest groups are discovery, NAT traversal
and hole punching, blobs, and the gossip codec. `TODO.md`'s *Next* list
names parts of this — the gate inputs, the live lookup seam — but it is a
list of what to do next, not a register of what is unwired, and it does not
account for all 165.

### Earlier records, kept as dated history

Before the matrix expansion the direct nine-section gate passed over the
56-file non-vendored Zig tree, with zero lint/static-analysis findings.
Native Debug, ReleaseSafe, GNU and musl each passed 543/543 tests. All seven
decoder fuzz targets completed another 10 000 mutations without a crash.
The actual CLI delivered exact payloads over IPv4 and IPv6. Under one-CPU
load, all 30 process scenarios and 30 immediate-banner SIGTERM runs passed.
The wider cross-platform survey and its limits are recorded below.

An earlier full native run on the cutover tree passed in Debug and
ReleaseSafe: **1102/1102 tests** over 22 build steps (**577 package, 525
vendored core**), `zig fmt --check .` at exit 0, 72 changed Zig files at exit
0, 0 lint errors with 23 vendored advisories, zwanzig over 41 non-vendored
changed files, and the same 15/15-step, 7/7-target fuzz bound. Out-of-tree
consumers exercised allocation refusal and retry, copied `Join` storage, real
TLS resumption and version fallback, and concurrent cancellation. Those
figures are reproducible history, not a statement about the source as it now
stands; the record above replaces them.

That instrumented baseline passed 543/543 with its matching node children.
Progress reported 35/35 source lines; the CLI reported 172/310. These are
source-line attribution counts, not statement-execution counts. They do not
measure branches or paths.

Zero attribution alone does not show that a body was untested. Inlining,
elision, fixture rows and the reporter's conditional filter can affect it.
That run accepted unsupported-session ABI panics (0/16), kernel interruptions
and refusals it did not force, and compile-time or fixture attribution gaps.
CLI refusal guards were separately smoke-tested; no duplicate tests were added
to inflate counters. Two pre-existing map allocation-fault gaps and their
triggers are in [`TODO.md`](TODO.md). These historical lists apply only to
their named runs. The current measurement is under
[*Current coverage measurement*](#current-coverage-measurement).

After the portability fixes, `zig-gate --no-cross --cov` passed all nine local
sections with zero lint/static findings. Native Debug and ReleaseSafe passed
543/543 and the separate vendored core passed 467/467 in both modes. In that
run the portable root was the 29-module, 438-test root and passed 438/438 in
both modes. That run predates every later expansion of that root: it is
**100 modules** as of 2026-10-06 (counted from `src/portable_test.zig`, method
under *Cross-platform tests* above), and neither its coverage nor its
ReleaseSafe figures are recorded here.

The instrumented full suite measured 49.0% of PC source lines (12896/26307)
and 41.5% of blocks (21237/51116); those are whole-run figures that include
unchanged vendored code, not a per-root breakdown, and the QUIC root's own
ratio below is a separate measurement that is not added to them. The accepted
cold regions above are not claims that every changed branch is covered.

Retained coverage counters hit the changed varint shift, relay hash, native-int
GRO decoder, blob-provider slice conversions, relay payload encoder and process
EOF checks. Accepted changed-file gaps: compile-time ABI flags and fixture values
without owning PCs; the duplicated expected-slice conversion in the blob test
(its `covers` predicate and the full 32-bit suite exercise the same bytes);
and spawn-error diagnostics, exercised separately with a missing executor.
No branch-coverage claim is made from these PC source-line counters.

A separate instrumented run over the unchanged QUIC test root measured 9004 of
14315 PC source lines (62.9%) and 4874 of 8439 blocks (57.76%), including
unchanged vendor paths. That root sits inside the whole-run figures above; its
own ratio is reported on its own and the two are not added together. A
runtime-fed address CLI smoke exercised 121 path, IP-only and token-identity
comparisons and all 18 of 18 instrumented address blocks, and checked the
canonical IPv6 bytes. Every FIFO implementation PC was hit. Accepted new-file
PC-line gaps are inlined byte-copy, endian and switch attribution and constant
fixture rows. These counters are not exhaustive QUIC branch coverage, and no
duplicate permanent tests were added to raise them.

| Module | What it is |
|---|---|
| `src/base/` | `NodeId`, `SecretKey`, `Signature`, `RelayUrl`, `IpAddress`, `SocketAddr`, `CustomAddr`, `TransportAddr`, `NodeAddr`, and the two base32 alphabets. A sorted, duplicate-free address set, which is what makes a ticket a stable identifier. |
| `src/wire/`, `src/blobs/` | The postcard codec, `RangeSpec`, and the blobs protocol. |
| `src/ticket/`, `src/discovery/` | Both ticket kinds, the pkarr signed packet, the item model, the resolvers, and the fan-in that runs them and dials the address the merge picks. |
| `src/relay/` | The relay frame codec and both relay state machines. |
| `src/net/` | The net report fold, the NAT classifier, and the holepunch gate. |
| `src/transport/` | The synthetic-ULA allocation, the GSO/GRO/ECN seam and its socket, the bridge to the QUIC core, and the dial path. |
| `src/router/`, `src/endpoint/` | ALPN dispatch, the accept loop, and the incoming filter. |
| `src/gossip/` | HyParView, PlumTree, the gossip wire codec (`codec.zig` plus `codec/`), and a deterministic in-process simulator. The codec is built and tested but the node does not call it yet. |
| `vendor/quic/` | The sans-IO QUIC core, 33 files, pinned by commit. No socket, no clock, no global entropy, no libc. |

Pinned to bytes captured from the Rust implementation at a named commit:
`src/wire/postcard.zig` (postcard at `872b9082`), `src/relay/frame_vectors.zig`
(the two upstream snapshot tests at `187f59e8`, which pin
`frame_decode`/`frame_encode`/`frame_types`/`frame_writer`/
`frame_roundtrip`), `src/base/ula.zig` (`187f59e8`), `src/blobs/
range_spec.zig` and `src/ticket/blob_ticket.zig` (`e82cbdcb`), and
`src/ticket/endpoint_ticket.zig` (`cec7f1e1`). BLAKE3 is a real pin of a
different kind — published upstream vectors rather than iroh's bytes, in
`src/gossip/plumtree/blake3_vectors.zig` and
`src/crypto/blake3_subtree_vectors.zig`.

Five formats in this tree declare that **no** captured upstream bytes exist
for them, and each says so in its own module doc rather than here: the gossip
codec (`src/gossip/codec.zig`), QUIC address discovery (`src/net/qad.zig`),
QUIC NAT traversal (`src/net/qnt.zig`), the WebSocket frame layer
(`src/relay/ws_frame.zig`, whose vectors are RFC 6455's own worked examples),
and the host-answer records (`src/discovery/host_answer.zig`, constructed
rather than captured). Where such a module has a golden vector, the vector is
derived from a written specification and is pinned as a *declared* table, not
as evidence about a peer. The rule is unchanged: a claim with no captured
bytes attached does not go in.

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
zig build test-portable # socket-free protocol and state-machine tests
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

### Consume as a package

The package registers two modules: `ozai` and `quic`. `ozai` imports the same
QUIC core internally. It does not export an `ozai.quic` alias.

Add an `ozai` dependency to `build.zig.zon`. Use its registered modules in
your build:

```zig
const dep = b.dependency("ozai", .{
    .target = target,
    .optimize = optimize,
});
const app = b.addExecutable(.{
    .name = "app",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    }),
});
app.root_module.addImport("ozai", dep.module("ozai"));
app.root_module.addImport("quic", dep.module("quic"));
```

The Linux socket and node drivers require libc. Pure codecs and state machines
do not. Import `quic` when your source names the core's types.
Fetched packages include the module sources, vendored license, README and
architecture and decision documents. Build checks resolve paths from the package
root, not the consuming application's working directory.

Runtime owners (`Socket`, `Bridge`, `Dialer` and `Node`) need serialized access
and exactly-once teardown as documented on their types. Zig does not make their
reachable fields private or prevent shallow copies. Inspect those fields only
while their owner is alive; direct construction or mutation outside a documented
API can violate the invariants. Borrowed views do not keep an owner alive.

The Linux socket driver uses libc syscalls and raw `poll`; passing `std.Io`
provides cancellation checks, not a substitute network backend. Runtime
cancellation alone does not wake that poll. Use the documented stop operation
or a finite timeout. `Stop.request` requests exit but does not join or dispose;
wait for `Node.run` before releasing its stop value. A backend-routed driver
would win when consumers need alternate networking or immediate cancellation;
that requires a separate adapter for GSO/GRO/ECN, not a claim about this driver.

### Contract changes

An API audit on 2026-10-03 repaired nine reproduced defects and settled the
ownership, default, callback and range contracts of the published surface.
[`DECISIONS/0003`](docs/DECISIONS/0003-api-contract-cutover.md) records each
change, what a consumer pays for it, and the alternative that was rejected.
The ones that change a call site:

| Change | What a consumer does |
|---|---|
| `BlobTicket.new` takes the address list | drop `address.deinit` and call `ticket.deinit` |
| `discovery.Published` carries an allocator | add `.alloc` to every literal |
| `PkarrPublisher.init()` | pass no allocator |
| `DnsAddressLookup.init` | pass answers and cancellation only |
| `holepunch.decide` takes `Candidates`; `holepunch.settle` takes no local set | pass the set at the gate, not at settlement |
| `pkarr` encoders answer `EncodeError` | `try` where a `[]const u8` was returned |
| `Conn.drain` can return a short prefix | loop until the answer is empty |
| `Bridge.create` can answer `error.Canceled` | handle it apart from `error.EntropyUnavailable` |

The contracts that settle behaviour without changing a signature are recorded
as decisions rather than in that table: which of two equal discovery items wins
a merge, what `Bridge.recv`'s `error.OutOfMemory` does and does not permit, what
a segmentation refusal or a dropped ECN codepoint reports, what a socket stop
leaves behind, and what a gossip snapshot has to do with a timer the caller has
already fired. Each states the constraint, the consumer cost and the setting in
which the rejected alternative would win.

### Cross-platform tests

`cross-test.profile.sh` runs the full Linux socket/process suite, including the
node artifact built for each target. Its default matrix is
**16 little-endian musl rows plus native x86_64 GNU**, not every Linux ABI.
Foreign GNU runs require compatible guest runtimes and are separate from
that self-contained gate. `cross-test.portable.profile.sh` surveys all 108
libc ABI targets listed by the pinned Zig 0.16 compiler. It uses
`src/portable_test.zig`: **100 pure modules** as of 2026-10-06, counted as the
unique non-`std` `@import` specifiers in that file, each with a matching
`refAllDecls` and no duplicates. It does **not** claim a non-Linux node
backend. An earlier figure of 32 modules is history and no longer describes
the file.

The tree as it stood before the 2026-10-03 contract cutover executed
**543/543 on all 26 live Linux ABI targets** in one
complete invocation: the 17 default rows plus nine foreign GNU rows.
The extra GNU rows are AArch64, ARM soft/hard-float, LoongArch64, MIPS32
hard-float, MIPS64 n64, PPC64LE, RISC-V64 and x86. The invocation exited 0,
with no failed, partial or build-only row. These are native or QEMU user-mode
runs, not non-Linux backends or native execution on foreign hardware.

Earlier expanded invocations were interrupted by a shared-harness rewrite
and incompatible private MIPS loader links. Their failed exits remain in the
retained evidence; recovered rows and then the complete current matrix passed.
No shared-tool repair was made.

```sh
cross-test --profile cross-test.profile.sh --build-jobs 1
cross-test --profile cross-test.portable.profile.sh --jobs 6 --build-jobs 1
```

The most recent complete 108-row portable survey ran against the earlier
29-module, 438-test root. It executed **438/438 on 53 targets**,
including 32-bit, big-endian, GNU/musl ABI variants and WASI. Another
**37 targets compiled but had no available runner**; they are not test passes.
**18 targets failed in Zig/LLVM**, so that survey exits 1:

| Targets | Observed toolchain limit |
|---|---|
| ARC; C-SKY (both ABIs); m68k (three OS/ABI rows) | Binary/backend unavailable or compiler runtime cannot be built. |
| LoongArch64 GNU soft-float | LLVM instruction-selection abort, also in ReleaseSafe. |
| MIPS64 n32 (four rows); x86_64 x32 (two rows) | `std.os.linux` pointer/register-width errors and missing `llseek`. |
| SPARC v8 Linux/NetBSD | LLVM cannot lower f128 calls, also in ReleaseSafe. |
| SPARC64 NetBSD/OpenBSD; x86 FreeBSD | Missing or unsupported `std.debug.cpu_context` definitions. |

Those failing rows remain in the survey rather than being silently dropped.
They are toolchain-side outcomes, and the 53/37/18 split above belongs to the
29-module, 438-test root. It is not a survey of the current source: that root
has since grown to **100 modules** (2026-10-06), and this file records no
execute, build-only or SDK-failure split across the 108 rows for it, because
the full survey has not been rerun against it. A 463/463 Debug run for the
intermediate 32-module expansion is recorded history and does not describe the
root as it now stands.

The live gate excludes n32 and x32 because the pinned standard library does
not compile for them, and Hexagon because its full Debug build crashes the
compiler. In that survey, Hexagon still executed the portable Debug suite.
ReleaseSafe is not a fallback: a standard-library-only Ed25519 probe under
Hexagon/QEMU derives `e13b9579…` instead of the captured `197f6b23…` public key
for seed `[42; 32]`; native ReleaseSafe produces the correct key.

QEMU user emulation is not a native-kernel proof: independent C probes on
QEMU 10.0.12 reject valid four-byte IPv4 `IP_TOS` control messages on
big-endian AArch64 and s390x.
An AArch64 big-endian GSO probe also receives an unsplit 42-byte payload without
GRO metadata; native execution reports the expected integer stride of 14.
The project retains the kernel ABI and its ECN/GSO checks rather than
swapping bytes for the emulator.

Foreign GNU live tests need a compatible guest loader and libc. With a
private runtime tree, a single-target run is:

```sh
QEMU_LD_PREFIX="$runtime_root/aarch64-linux-gnu" \
CROSS_LIBC_RUNTIMES="$runtime_root" \
cross-test --profile cross-test.portable.profile.sh --step test \
  --targets aarch64-linux-gnu --jobs 1 --build-jobs 1 \
  --timeout 900 --build-timeout 2700
```

`QEMU_LD_PREFIX` is required with the current shared harness: it reads
`Compile.is_linking_libc` before `make()` computes that value and omits QEMU's
loader prefix. No shared-tool or system-runtime patch is part of this change.
WASI execution in the recorded survey used a private Wasmtime 49.0.1.

The process fixture forwards the harness's selected executor to its matching
node children; it does not assume the host supports foreign ELF or native
32-bit execution. Outside the harness, pass
`-Dtest-node-executor=/path/to/qemu-TARGET` when that executor is needed.

The adapter reads the shared harness's `CROSS_TEST_RUNNER_KIND=exec` and
`CROSS_TEST_RUNNER` metadata at build time. An explicit
`-Dtest-node-executor=...` takes precedence over that selected executable.
Outside the harness, no executor is selected unless the option is provided.

The vendored sans-IO core can be surveyed separately with the same ABI matrix:

```sh
cross-test --profile cross-test.portable.profile.sh --step quic-test \
  --jobs 2 --build-jobs 1 --timeout 900 --build-timeout 2700
```

Its path addresses are pure values, not kernel-layout storage. Retry and
NEW_TOKEN bind the full IPv6 address, port and scope to canonical bytes.
The simulated lossy-link FIFO reclaims consumed records on the next push;
it no longer shifts the entire queue on each receive. The unchanged 16 MiB
upload passed under native execution, SPARC64 and big-endian MIPS64 QEMU,
with the original 6 MiB window, byte checks and 60-second virtual deadline.

The other little-endian Linux rows either hit the compiler limits in the
table, need a foreign GNU runtime, or are Hexagon. This host has compatible
GNU loaders for AArch64, ARM soft/hard-float, LoongArch64, MIPS32 hard-float,
MIPS64 n64, PPC64LE, RISC-V64 and x86. It has no compatible RISC-V32 or MIPS32
soft-float GNU runtime. Big-endian Linux rows remain in the pure survey;
their live ECN/GSO checks are not accepted as native-kernel proof under QEMU.

The full live profile uses two concurrent target builds, a 2700-second build
ceiling and a 900-second test ceiling. Its 4200 × 1500-byte burst still crosses
the receive window, retains its 16384-pass bound, and requires every datagram
in order. An isolated GNU AArch64 burst passed; compiling and running it took
146 seconds under QEMU. More target workers increased contention, not coverage.

Process observations still have a 60000 ms ceiling. Their children have a
240000 ms fallback watchdog so a child cannot expire before its parent finishes
observing delivery and retirement. Passing tests stop their children explicitly;
closed output pipes are removed from polling, and premature EOF fails the wait.

## Layout

```
src/root.zig            public surface
src/base/               identity, addressing and an explicit entropy edge
src/examples/           runnable proofs
test/                   integration tests, outside src/ so they are reachable
docs/                   plan, architecture, decision records
```

`src/base` never touches a socket, a clock, or an allocator it was not handed.
That is not a style preference: it is what lets a state machine be driven by a
test instead of by a network. The one seam is `SecretKey.generate`, which takes
the caller's `std.Io` for entropy, never stores it and never reaches for a
global source; every other value in the module is a plain value with an `Io`
parameter at most on the call that needs one.

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
