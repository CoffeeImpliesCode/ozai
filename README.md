# ozai

Dial a node by its id, not its address.

ozai is a from-scratch Zig 0.16.0 implementation of the [iroh] P2P stack — the
part that makes a device reachable by a 32-byte public key across hostile
networks, and the protocols built on top of it. It is not a binding, a
translation, or a wrapper. Where iroh's shape fits Zig, ozai keeps it; where it
does not, ozai says so and diverges on the record.

[iroh]: https://github.com/n0-computer/iroh

## Status

**Milestones 1–11 shipped primitives, not finished protocols.** Several
production drivers are absent, so this is neither feature-complete nor
release-ready. `test/loopback_test.zig` verifies peer identity from the
certificate, moves bytes both ways, and carries ECN over a real socket;
`test/relay_wire_test.zig` and `test/two_process_test.zig` exercise relay
forwarding, payload delivery, and independent shutdown on loopback. That is
self-interoperation over one private carrier.

| Gap | State |
|---|---|
| Production randomness | Repaired in Wave 0: `Node.create` draws a 32-byte secret seed from `io.randomSecure` into a `Csprng` (ChaCha) and erases the temporary with `secureZero`. `ozai-node` dropped `--seed`; no caller-chosen generator seed remains in production paths. |
| iroh interoperability | No Rust exchange has run. The vendored TLS writes 44-byte Ed25519 SPKI certificates but negotiates no RFC 7250 certificate type, so a real peer is expected to refuse the handshake before the certificate is accepted. |
| Standard relay carrier | The carrier in tree is the private QUIC `/iroh-relay/1`, not RFC 6455 WebSocket over an HTTP upgrade with TLS. No exporter authentication, ping driver, reconnect or access policy. |
| Relay routing | Relayed inner QUIC is not routed: `drain` hands `Egress.to` straight to UDP. |
| Blobs | Request framing and range algebra only. No Bao tree, proof or root verifier, store, provider or getter, so no getter verifies content. |
| Gossip | Pure state machines with captured Rust neighbour, convergence and broadcast expectations. No production codec and no peer-ID connection index; the test-only encoder inverts the `DeliveryScope` tags, and `plumtree.max_content` is 1024 against upstream's 4096. |
| Discovery | TXT and pkarr codecs plus pure resolvers. No A/AAAA path, no TCP retry on the TC bit, no live pkarr HTTP transport and no node caller; `lookup_live.zig` has only its own tests as callers. |
| Probes | Every probe transport in the tree is a test fake. |
| Holepunching | The gate and its error classification are pure and tested. Three of the seven inputs have producers, four do not, and no action can start a real QNT round. |
| Resumption and 0-RTT | The core requests a client certificate after PSK selection and fails closed. That is a recorded RFC 8446 deviation, not an identity bypass; the standards-compatible replacement is Wave 4. |

The ordered plan, the owners and the acceptance for what remains are in
[`docs/PLAN.md`](docs/PLAN.md); the near-term checklist is
[`TODO.md`](TODO.md).

### Gate record

Two records, kept apart because they measure different trees.

**The audit snapshot** is a read-only audit of commit `8b8bcd96`, run against
the pinned Zig 0.16.0 compiler directly on native x86-64 Linux. It did not use
the house `zig-gate` wrapper: that wrapper resolves its toolchain through the
`anyzig` shim, which re-downloads the pinned release and fails to extract it
here, which [`0004`](docs/DECISIONS/0004-vendored-core-contracts.md) records.
No global tool, sandbox or launcher was repaired to work around it.

| Section | Command | Result |
|---|---|---|
| Build, Debug | `zig build -Doptimize=Debug` | exit 0; 5/5 build steps |
| Build, ReleaseSafe | `zig build -Doptimize=ReleaseSafe` | exit 0; 5/5 build steps |
| Tests, Debug | `zig build test quic-test -Doptimize=Debug` | exit 0; 22/22 steps; 1159/1159 tests |
| Tests, ReleaseSafe | `zig build test quic-test -Doptimize=ReleaseSafe` | exit 0; 22/22 steps; 1159/1159 tests |
| Portable root | `zig build test-portable`, Debug and ReleaseSafe | 503/503 each. It overlaps the package tests and adds no unique test |
| Format | `zig fmt --check .` | exit 0, no output |
| Syntax | `zig ast-check` over all 90 Zig files | 90/90 exit 0 |
| Lint | `zlint -c zlint.json -f json -S`, the same 90 files | exit 0; 0 errors; 24 vendored warnings |
| Static analysis | `zwanzig`, 57 non-vendored files, 21 rules | exit 0; no issues |
| Lint | `ziglint`, 57 non-vendored files | exit 1; four findings — `node.zig:4798` Z004, `socket.zig:1138/1195/1235` Z023 |
| Static analysis | `zbc`, 57 non-vendored files | exit 1; 25 flags, each individually classified as a source-proven false positive or a justified panic; 1764 unresolved import lookups still limit the analysis |
| Fuzz | `zig build fuzz --fuzz=10000` | exit 0; 15/15 steps; seven targets, each advancing at least 10 000 runs |

**1159/1159 tests over 22 build steps** is the suite figure and it is the same
in both modes: 599 package tests across the package roots, plus 560 from the
separately built vendored core (`zig build quic-test`). The portable root's 503
overlap those package tests and are counted separately, never added to them. No
step reported a leak under the test allocator.

The lint run is **0 errors and 24 warnings**, and every warning is under
`vendor/quic`: 16 `avoid-as` findings and 8 `suppressed-errors` findings on
bounded or deliberately best-effort core paths. No non-vendored finding was
reported. They are not described as zero lint findings.

`ziglint` and `zbc` both exit 1, and neither is a pass. `zlint`'s `-S` takes
the file list over stdin, one path per line; an earlier retained run handed the
same list as one JSON array, and a single line of 2267 bytes overran the tool's
fixed 1024-byte line reader and answered `WriteFailed`. Those runs are trace
history for a caller that sent the wrong shape, and they are lint evidence in
neither direction.

Each of the seven fuzz targets in that snapshot advanced by at least 10 000 new
runs; the largest advance is 10 213. The `Runs:` counters those reports print are
cumulative across the retained corpus and earlier runs, so a counter is not one
invocation's work and the per-target advance is what the bound covers.

**The working tree**, measured through the repository's own gate, which is the
same driver CI runs (`.github/workflows/gates.yml`, one job per group):

| Command | Result |
|---|---|
| `zig run scripts/gate.zig -- --group {compiler,fmt,ast,refdecls,compile-all,build,test,portable,fuzz,lint,static}` | **exit 0; 160 recorded steps over 139 source files** |
| `zig build test -Doptimize=Debug` | 24/24 steps; 681/681 tests |
| `zig build test -Doptimize=ReleaseSafe` | 24/24 steps; 681/681 tests |
| `zig build test -Dcoverage=true` + `zig-cov report --format=summary` | 681/681; 47.0% lines (14 596/31 026), 41.7% blocks; **no file under `src/` at 0%** |

`lint:zlint` and `lint:ziglint` pass with no findings, `lint:zwanzig` reports
none, and `static:zbc-triage` accepts **50 findings, 0 rejected, 0 dispositions
unused** — each one individually dispositioned with the source lines it rests
on, in `scripts/gate_zbc_dispositions.zig`, keyed by file, line, column and rule
and pinned to a whole-file digest so a disposition cannot outlive the code it
describes. `zbc` itself still exits 1 over those 50 findings; that step is
non-binding by design and the triage beside it is the verdict.

`static:zbc` also reports **2 493 unresolved import lookups**, and the gate says
so rather than rounding it away: `zbc` writes that count to stderr and not into
its report, so this run's import coverage is unproven and the record does not
claim otherwise.

The `fuzz` group runs **12 decoder targets**, each past 10 000 new mutations in
one pass. Its step captures the run's output, because a run step that fails
under `--fuzz=N` does **not** reach `zig build`'s own exit status: the fuzzer
reports the crashing input and the build still exits 0. Without that capture the
group would record a decoder crash as a pass.

Two defects this audit found were in the vendored core rather than in this
project, and both are recorded in `vendor/quic/VENDORED.md`: a `PADDING` frame
that reported itself as zero octets wide, so a packet payload beginning `40 00`
looped forever (§9), and the ServerHello `key_share` bound being taken against
the extension block rather than the extension itself.

### The CLI, in the audit snapshot

Three `ozai-node` processes in each of Debug and ReleaseSafe — a relay, a
receiver and a sender — delivered the exact 24-byte payload
`audit-private-relay-wire`, hex
`61756469742d707269766174652d72656c61792d77697265`, through the relay. All six
processes exited 0 and reported a closed shutdown.

That exchange rides the private QUIC carrier `/iroh-relay/1`. It is not a
standard iroh relay exchange, not a gossip exchange and not a verified blob
transfer, and it discharges none of the carrier parity requirements above.

An earlier tree carried the 21-byte payload `api-cutover-live-wire` the same
way, with seeds 401, 402 and 403: the CLI's fixed default is a replay aid, not
independent entropy for several processes.

### The out-of-tree consumer

Six programs built in an earlier run against the registered package modules —
contract, TLS, decoder, cancellation, core-wire and package-state consumers. All
six passed in Debug and ReleaseSafe, **18/18 build steps** in each mode. The two
added consumers exercise ownership, state transitions and decoded wire values,
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

### Coverage measurement

**Not re-measured.** The figures below are the retained earlier record, and the
source has changed since they were taken.

One instrumented run measured the tree it ran on. `zig build test quic-test
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

For added or replaced nonblank, non-comment lines in the 74 files that record
counted as changed,
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
0-RTT is claimed, and no Rust iroh exchange has been run at all. The
cross-platform counts below belong to an older root; no current
cross-platform survey has been executed, and a build-only row is not a pass.

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
[*Coverage measurement*](#coverage-measurement).

After the portability fixes, `zig-gate --no-cross --cov` passed all nine local
sections with zero lint/static findings. Native Debug and ReleaseSafe passed
543/543 and the separate vendored core passed 467/467 in both modes. In that
run the portable root was the 29-module, 438-test root and passed 438/438 in
both modes; that run predates the expansion of that root to 32 modules and
463 tests, whose coverage and ReleaseSafe figures are not recorded here. The
instrumented full suite measured 49.0% of PC source lines (12896/26307) and
41.5% of blocks (21237/51116); those are whole-run figures that include
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
zig build test        # package unit + integration tests
zig build quic-test   # the vendored core's own suite, built separately
zig build test-portable # socket-free protocol and state-machine tests
zig build compile-all # every test root, compiled and not run
zig build verdict-test # the expected-log runner's verdict regressions
zig build fuzz --fuzz=10000 # the decoder fuzz targets, bounded
zig build run-ozai-node-id
devenv shell -- gate  # the whole gate, both safety modes, with receipts
devenv shell -- gate-design # every group except the static-analysis one
```

`test`, `quic-test` and `test-portable` are three separate roots and three
separate counts. The portable root's tests are also reached from the package
roots, so its total is never added to theirs. `zig build verdict-test` runs the
expected-log runner's own verdict regressions, which the `test` step runs too;
its two fixture executables are compiled and deliberately never run.

`zig build run-ozai-node-id` prints this machine's node id in every form ozai
puts on the wire, and signs the rendered address to prove the text form is
faithful to the value.

`zig build run-ozai-node -- --progress --for 30000` emits live counter changes
after completed passes. Each `progress:` line is flushed immediately. Supervisors
can wait for a connection, delivery, or departure before sending SIGTERM.
Without `--progress`, the node prints only its banner and final report.
The SIGINT/SIGTERM handlers are installed before the listening banner is published.

### The gate

`devenv shell -- gate` runs this repository's own driver, `scripts/gate.zig`.
The compiler is data, not a wrapper decision: `--zig PATH` if the caller named
one, else `OZAIGATE_ZIG`, else whatever `zig` resolves to. The driver installs
nothing, replaces nothing and touches no global wrapper; it cross-checks that
compiler's reported version against `.minimum_zig_version` in `build.zig.zon`
before it runs anything, and the receipt names and hashes the file it resolved.

```sh
zig run scripts/gate.zig -- --scratch DIR [--zig PATH] [--group NAME]... \
  [--fuzz-runs N] [--receipts PATH] [--prefix DIR] [--list]
```

The groups are `compiler`, `fmt`, `ast`, `refdecls`, `compile-all`, `build`,
`test`, `portable`, `fuzz`, `lint` and `static`. Every group runs unless the
arguments name a subset, and one run reports every group rather than stopping at
the first failure, because the receipt is the evidence. `refdecls` checks that
each named sweep root still carries its `refAllDecls`, because a root that
dropped it still compiles, still runs and still exits 0. `test` is the package
suite plus the vendored core; `portable` is the socket-free root that overlaps
`test` and is labelled separately for exactly that reason; `fuzz` is bounded by
`--fuzz-runs`. Receipts land in `<scratch>/receipts.json` and carry the
compiler, every command, the file list each scoped command was given, the
digests of all three, and the values of the cache and scratch variables the run
inherited. Nothing a gate run writes is inside the repository.

A required tool that is not installed is recorded `not_available` and fails the
run: an absent linter is not a clean tree, and no flag turns it into one.
`zlint` and `ziglint` are required; `zwanzig` is optional, so its absence is
recorded absent and is not a pass, and its findings bind when it ran; `zippy`
and the sanitizers have no configured invocation in this repository and are
recorded `not_configured`. `zbc` is required, but its exit status is not its
verdict: it exits 1 over findings that are each individually classified, so the
triage binds instead, and a diagnostic outside the classified set fails the
gate.

The driver refuses before it spawns a child. `--scratch` is required and names
the approved local root; `--prefix` and `--receipts` are honoured only inside
it and default to `<scratch>/build` and `<scratch>/receipts.json`. An unset
`TMPDIR`, `TMP`, `TEMP`, `ZIG_GLOBAL_CACHE_DIR` or `ZIG_LOCAL_CACHE_DIR` is a
refusal rather than a warning, and so is a scratch root inside this repository,
outside the approved root, under `/tmp` or `/var/tmp`, or on a network mount —
`nfs`, `nfs4`, `nfsd`, `9p`, `cifs`, `smb3`, `smbfs`, `sshfs` or `ceph`. Where
the machine exports `HOST_SCRATCH_ROOT`, nothing the run writes may sit outside
it. The devenv scripts pass `${OZAIGATE_SCRATCH:-$TMPDIR/gate}`, which is
`$TMPDIR/gate` under this project's environment, and CI gives each matrix leg
`$RUNNER_TEMP/ozai-gate/<group>/scratch`.

`gate-design` is that gate with exactly one change: the `static` group is left
out, so `zbc` does not run and its triage does not bind. It is a design pass in
which a static-analysis finding cannot block — not cheaper, and not stricter
than the gate it drops a group from, which is why it is not called `strict`.
Coverage is not part of either script; the instrumented run is still `zig-cov
test` with `-Dcoverage-rt`.

The vendored tree is compiled and tested like everything else and is excluded
only from the *text* linters. `scripts/gate_scope.zig` walks the working
directory once and hands every scoped command the same list, so "which files" is
an answer the receipt carries rather than one each tool re-derives: `zlint` gets
every `.zig` file, `ziglint`, `zwanzig` and `zbc` get the same list without
`vendor/`. The exclusion is paid back by `zig build quic-test` and by
`test/vendored_invariants.zig`, which fails if a socket, a clock, a global
entropy source or a libc call returns to the vendored tree.

CI is `.github/workflows/gates.yml`: one job per group over the same driver, and
a scheduled bounded-fuzz job. The file names the groups and nothing else, so a
CI job cannot drift from the documented gate.

`cross-test` is not part of this gate. It is a portability survey over foreign
targets driven by `cross-test.profile.sh`, and it stays the separate documented
command below.

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
`src/portable_test.zig`: **32 pure modules**, including
the socket-free endpoint and the socket-free `discovery/dial_source.zig`,
`transport/quic_bridge.zig` and `transport/dial.zig`. It does **not** claim a
non-Linux node backend.

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
29-module, 438-test root. It is not a survey of the 32-module root: that root
has been run natively at 503/503 in Debug and ReleaseSafe in the audit snapshot,
and its executed, build-only and SDK-failure split across the 108 rows is not
recorded here, because no survey has been run against it.

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
scripts/                the gate driver and its receipt, scope and triage
.github/workflows/      the same gate as CI, one job per group
docs/                   plan, architecture, decision records
```

`src/base` never touches a socket, a clock, or an allocator it was not handed.
That is not a style preference: it is what lets a state machine be driven by a
test instead of by a network. The one seam is `SecretKey.generate`, which takes
the caller's `std.Io` for entropy, never stores it and never reads an ambient
source; every other value in the module is a plain value with an `Io` parameter
at most on the call that needs one. That is an ownership claim, not a strength
claim: the draw is `Io.random`, which the standard library documents as seeded by
`Io.randomSecure` *or by a less secure mechanism when that fails*.

The node's runtime generator is a different seam, and it is the open safety
item. `Node.create` initializes `std.Random.DefaultPrng` from a `u64` the caller
passes, and `ozai-node` passes the fixed public constant `0x6f7a_69` by default;
that generator supplies the TLS ephemeral scalars, the relay admission
challenges and the QUIC connection-id and path-validation draws. Identity keys
do not come from it, so it is a predictable-key defect and not a demonstrated
identity bypass. Replacing it is the first repair in
[`docs/PLAN.md`](docs/PLAN.md).

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
