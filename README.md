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

The full upstream iroh matrix and node-level authenticated 0-RTT remain open.
Historical controlled-NAT receipts cover both endpoint-A roles.
Historical relay receipts cover exact 34-byte application payloads, pinned peers and both authenticated inner-QUIC roles.
Current source repairs require fresh consumer acceptance.
Bao, gossip, relay and controlled NAT retain separate proof boundaries.

The node executes the gossip codec through its incoming and outgoing QUIC stream routes.
The current call-site map below replaces the older unwired-codec claim.

The historical live `test-gossip-interop` Debug run passed 7/7.
Stock Rust and Node exercised both roles with the exact 32-byte topic, broadcast payload and application acknowledgment.
Both wrong-pin routes rejected the peer.
The deliberate pin rejection produced an expected `UnknownIssuer` warning.
This is separate from the 15 pinned upstream gossip codec captures.
Those captures prove enum and encoding agreement, not a captured 4,096-byte payload boundary.
The 4,096/4,097 boundary tests use hand-built declarations.
They test the source-derived strict write limit and inclusive read limit separately.

The historical live `test-blobs-interop` Debug run passed 5/5 tests over 6/6 steps.
Two grouped tests exercised six actual Rust/Node transfers, with each implementation as getter and provider.
The cases cover the 49,189-byte whole blob, cross-group chunks `15:18` and partial-tail chunks `47:49`.
The ranges returned exactly 3,072 and 1,061 bytes.
The verified root is `978923a54590809177bc22cccb4aeef32fe1e9d82e40df31ce3ac1eaa2360009`.
The oracle source is pinned iroh-blobs `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`.
Its response captures contain 49,389, 3,656 and 1,453 bytes.
The live checks retain exact output equality, verified completion and EOF.
Rust provider accounting includes the one-byte GET tag that upstream reads before the request body.

The Node provider passes its remaining request budget to stream drain.
An oversized contiguous run is rejected before allocation or consumption.
Already accepted request bytes remain intact, and the unread run remains available.

### Current public consumer contracts

Blob transfer decisions are pure state transitions.
`Decoded.claimed_size` is an unauthenticated response header, not a verified length.
`verified_size` requires a matching expected size or authenticated terminal data.
A nonterminal proof authenticates selected bytes, not the total-size claim.
The getter uses a finite Bao allowance and tightens it after the header.
The claimed size can reduce that allowance. It cannot grant verification.
Known-size allowance is the eight-byte header plus the exact Bao plan.
Unknown-size allowance uses `4 * (max_depth + 1)` bounded items of block-plus-pair bytes.
Empty or overflowing plans refuse instead of allocating an unbounded response.
Missing data and provider refusal end only the affected stream.
Other provider errors still propagate. Node serves GET only, not GetMany, Observe or Push.
`BlobSet` and `BlobClaim` remain standalone, outside the Node transfer adapter.

Node wipes its owned `config.secret` and optional `config.relay.client.secret` on release and construction rollback.
Bridge, Dialer and relay client cleanup wipe their separate owned key copies.
These wipes do not erase caller-held originals, borrowed keys or independent `toBytes()` copies.

Gossip receive accepts actual encoded messages up to and including 4,096 bytes.
Gossip send requires fewer than 4,096 bytes, including the actual scope, round and TTL encoding.
Local broadcast and public receive preflight size before startup timers, output, cache or statistics change.
Rejected input does not leave an unowned maintenance timer. A valid later input can start maintenance.
An accepted message with an oversized derived round still permits valid delivery and tree-control work.
It does not promise an unwritable eager, lazy or cached message.
Refill declines an oversized derived Neighbor before random selection, pending state, output or timers.
Valid receive, departure and timeout cleanup still completes. Direct sender requests retain `MessageTooLarge`.
Node stream assemblies belong to a peer and survive another connection for that peer closing.

Relay TCP has separate client, server, HTTP, forwarding, execution, listener, native-path and WebSocket processor modules.
Consumers use `tcp_client.Client` and `tcp_server.Server`, not an obsolete carrier or public `Listener` shim.
Execution contexts are borrowed and must outlive their TCP owners and concurrent stop calls.

DNS TCP fallback retains one pending connection across finite cancellation slices.
UDP and TCP share one request budget. Resolver stop remains distinguishable as `Canceled`.
`Answer.records` owns copied TXT bytes. Each stream owns its parsed item and copied custom-address data.
Borrowed `RecordSet.bytes` must outlive every stream. Parent answer teardown follows the synchronous stream walk.
Retrieval cancellation is operation-local and leaves a live Resolver usable for a later query.
Explicit global Resolver cancellation remains terminal.
The public regression covers reuse after UDP wait, pending TCP fallback and partial TCP fallback cancellation.
All three real native UDP follow-up queries passed in Debug and ReleaseSafe (`bg317`).
The Node's synchronous lookup does not expose that cancellation handle.

Child construction returns either a ready owner or the exact failed owner with its start error.
A failed post-spawn capture does not imply that the child has exited.
Cleanup deadlines and errors retain the owner and process identity.
Callers keep that storage until cleanup proves reap, then deinitialize it.
No signal is authorized without exact process identity through process I/O.
Public gate and CLI boundaries expose finite explicit error sets.
Child pump and wait errors remain typed, not unrestricted error reflection.

Assembly allocation failure publishes no usable output prefix and closes the QUIC connection.
Path abandonment is different. It requeues reliable bytes and FIN onto a surviving path and retains ACK history.
The sequence/last-local native cancellation model remains standalone. It is not wired into Node cancellation.

The Rust peer requires actual blob EOF, the final real application acknowledgment, optional IP and repeated topics.
These source contracts do not extend historical wire receipts or establish current final acceptance.

### Integration snapshot, 2026-10-08

The earlier schema-2 measurements and default-gate receipts describe their captured source only.
The current repairs invalidate those receipts for current-source acceptance.
Fresh schema-3 capture, exact cold-tuple decisions, strict replay and the full default gate remain pending.
No current all-source count, coverage percentage or all-seven-issues completion claim is made.

Main observed these results after the repairs:

| Scope | Observed result | Boundary |
|---|---|---|
| Vendored QUIC (`bg288`) | Debug and ReleaseSafe each passed 671/671 tests. | This is not the complete default gate. |
| Gate policy (`bg298`) | Debug and ReleaseSafe each passed 116/116 tests. | This is not a fresh coverage capture or final replay. |
| Pinned Rust peer (`bg293`) | 30/30 tests and the release build passed. | This does not prove every mixed Rust/Node route. |
| Normal-root integration (`bg317`) | Debug and ReleaseSafe each passed 28/28 steps and 2538/2538 tests. Exit 0 in 257.27 seconds. | Each mode includes library 1317/1317, portable 1041/1041 and child helpers 35/35. Fresh capture, full default gate and live smokes have not run. |
| Current consumer regressions (`bg317`) | All 38 migrated gossip cases and the three Resolver cancellation-reuse paths passed in both modes. | The same run covers owned-key rollback/release wipes, blob proof/budget/refusal, TCP rollback and WebSocket decisions, native standalone cancellation, and child identity/retained-owner cleanup. It is not a wire-interoperability receipt. |

Earlier mixed-peer receipts cover pinned TLS identities, exact blob/range output, gossip broadcasts, and both relay endpoint roles.
Those receipts remain historical after the current source repairs.
Configured controlled-NAT receipts prove relay-to-direct behavior, not learned candidates or mixed Rust/Zig endpoint NAT.
The full upstream matrix and Node-level authenticated 0-RTT remain open.
Standalone models and explicit issue admissions do not receive production execution or coverage credit.

The [issue checklist](TODO.md#issue-16-checklist-disposition) keeps every named requirement and its proof boundary.
The strict workflow below describes the required current capture and replay, not an observed final pass.


### Strict coverage snapshot workflow

The default gate always runs the configured full checks before it validates retained coverage.
It builds and tests current source without instrumentation in both Debug and ReleaseSafe.
The test scope includes `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy`.
Configured format, syntax, ziglint, zlint, native ZBC, Zwanzig and cross-target checks remain required.
Missing cross-target runners retain build-only status. They do not count as runtime passes.
The default then performs full current-source validation of the required retained measurement.
It does not start a new instrumented measurement.

The legacy `refdecls` and `compile-all` names describe declaration checks, not separate driver sections.
`test` runs the `src/root.zig` declaration sweep.
`test-portable` runs the socket-free `src/portable_test.zig` sweeps.
`quic-test` runs `vendor/quic/src/test_all.zig`, including core declaration sweeps and explicit internal/test-only imports.
`test-gate-policy` runs the gate-module sweeps in `scripts/project_gate.zig`.
These executed roots reconcile the Compile-all requirement in `AGENTS.md` with the driver.
`invariants` adds vendored source-contract checks. It does not replace core runtime tests.
No new gate abstraction or declaration-only coverage credit applies.

```sh
source ~/.local/lib/host-scratch.sh
devenv shell -- gate
```

Use `measure` for an explicit fresh capture:

```sh
source ~/.local/lib/host-scratch.sh
export TMPDIR="$HOST_SCRATCH_ROOT/scratch" TMP="$HOST_SCRATCH_ROOT/scratch" TEMP="$HOST_SCRATCH_ROOT/scratch"
export ZIG_LOCAL_CACHE_DIR="$HOST_SCRATCH_ROOT/scratch/zig-local"
export ZIG_GLOBAL_CACHE_DIR="$HOST_SCRATCH_ROOT/scratch/zig-global"
export ZIG=/absolute/path/to/zig-0.16.0/zig
export OZAI_COVERAGE_RT="$HOME/tools/zcov/zig-out/lib/zig-cov-rt.o"
"$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  scripts/project_gate.zig -- measure
```

Use only the helper's approved host-local root for temporary files, caches and retained evidence.
Do not use the repository, NFS, `/tmp` or `/var/tmp` for these files.
`OZAI_COVERAGE_RT` is a prerequisite for `measure`. Set it to the installed runtime object if its path differs.
Default snapshot replay does not require a fresh instrumentation runtime.
The devenv `gate` wrapper selects the default command. Use the direct driver for `measure` and `validate`.

This command builds and tests current source without instrumentation in both modes.
It then captures fresh instrumented coverage for the same five test targets in both modes.
Retain the resulting `measurement.json`, compiled artifacts, raw files and reports.
Regenerate the exact cold-tuple decisions and counters in `docs/COVERAGE-LEDGER.md` for that capture.
Use one `ozai-coverage-v2` machine fence. Both the machine ledger and Measurement use schema 3.
The fence requires `measurement: {path, sha256}`.
Set `path` to the exact nonempty manifest path.
Set `sha256` to the captured file's 64-hex-character SHA-256.
The validator checks that file hash before it trusts the manifest.

Replay the selected manifest explicitly:

```sh
"$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  scripts/project_gate.zig -- validate /absolute/scratch/path/to/current/measurement.json
```

`validate <path>` requires the fence reference to match that exact path and SHA-256.
Default validation reads the same required reference and uses the same full replay.
Replay checks current source, compiler identity, scope, modes and all source, artifact, raw and report hashes.
Capture binds the original absolute instrumentation-runtime object path and its SHA-256.
Replay rehashes that retained object, independent of a fresh `OZAI_COVERAGE_RT` environment value.
All source-inventory paths remain represented, including absent roots and test sources.
Cold DWARF rows can outnumber mapped PCs. That difference does not indicate report corruption.
It checks raw-file completeness, exact-PC projection, ordered report rows and all counters.
It preserves the full positive DWARF numeric-row universe and direct-PC hit attribution.
It compares stored `Measurement.cold_items` with every replay-generated tuple by field content.
The identity fields are `mode`, `path`, `source_sha256`, `line` and `unit`.
Duplicate, omitted, stale or extra cold tuples fail. Changed tuple metadata also fails.
Ledger decisions must match the exact cold tuples. Covered or stale extra decisions do not qualify.
Reported project-unmapped and source-unowned totals and hits must match exactly.
Coverage documents remain bounded to 64 MiB.

Missing or changed references, manifests, artifacts or decisions fail the default gate.
Source, compiler or scope drift also fails it until a fresh capture and exact fence replace the snapshot.
There is no advisory result, opt-out, skipped coverage check, schema fallback, tolerance or retry-to-green.
Rust interop, relay role smokes and controlled-NAT receipts retain their separate scopes and admissions.
They do not replace this coverage replay or acquire coverage credit from it.


Earlier counts below describe their own snapshots, not this integration.
[`TODO.md`](TODO.md#issue-16-checklist-disposition) maps the orchestration checklist to executable routes and explicit admissions.

### RFC 7250 live TLS and stream proof

The opt-in process/socket suite passed 5/5 tests over 4/4 steps in Debug and
ReleaseSafe. One test checks the peer banner and ALPN contract. Four tests cover
these client/server routes:

- Zig client to strict `noq` 1.3.0 server
- Zig client to stock iroh 1.3.0 server
- strict `noq` 1.3.0 client to Zig server
- stock iroh 1.3.0 client to Zig server

All four routes negotiated `ozai` and exchanged the exact 17-byte
`ozai-to-iroh-peer` and `iroh-peer-to-ozai` payloads on one bidirectional
stream. The direct `noq` path checks the peer pin during TLS. Stock iroh keeps
its upstream verifier and resolver unchanged. The harness checks the observed
raw SPKI against the expected pin after the handshake and before application
bytes.

This proof covers the TLS handshake and one application stream only. It does
not cover the full upstream matrix, mixed blob/gossip/relay protocols, NAT or
0-RTT.

The fresh expanded standalone Rust interop run passed 8/8 over 4/4 steps in Debug.
It covers four direct TLS profiles in both roles.
The harness now sleeps one host millisecond after each `peer.pump`.
This lets Rust's Tokio runtime run between Zig's virtual-time rounds.
The explicit virtual clock and 4,000-round limit remain unchanged.
The earlier 6/8 run timed out on two stock-iroh routes without that scheduler wait.
This harness change does not add a wall-clock dependency to the protocol.
It does not change production TLS, pins, resumption or native extension defaults.

Source `~/.local/lib/host-scratch.sh` first. It selects an approved absolute
scratch root and sets the Zig caches. Do not use `/tmp` or `/var/tmp`. Set
`ZIG` to the direct Zig 0.16.0 executable. `Cargo.toml` pins `iroh` and `noq`
to 1.3.0. `Cargo.lock` pins their dependency graph.

Disk-backed Zig tests use the independent `test_scratch` module, not
`std.testing.tmpDir`. They require `HOST_SCRATCH_ROOT` and validate its ownership,
physical approved mount and absence of symlink redirection with the same policy
as the gate. Each test gets an exclusively created private directory under
`$HOST_SCRATCH_ROOT/scratch/ozai-test-*`; missing or unapproved roots fail instead
of falling back to the repository or `/tmp`. Fixture reads keep the repository
working directory. For direct `zig test` commands, add `--dep test_scratch` before
the consuming `-M` module and add `-Mtest_scratch=scripts/test_scratch.zig`.

Before scratch cleanup, tests must close their file and directory handles and
join or stop child processes that used the private directory. They must not
share its path with unrelated processes. Cleanup rechecks the approved mount,
directory identity and private parent permissions, then rejects foreign-owned
entries, symlinks, hard links, special files, nested mounts and live descriptors
or mappings in the test process. It never scans unrelated PIDs or sends signals. If a check
fails, cleanup retains the directory and prints its exact path and reason.

```sh
source ~/.local/lib/host-scratch.sh
export TMPDIR="$HOST_SCRATCH_ROOT/tmp/ozai-rpk-tmp"
export CARGO_HOME="$HOST_SCRATCH_ROOT/cache/cargo-home"
export CARGO_TARGET_DIR="$HOST_SCRATCH_ROOT/scratch/ozai-rpk-rust-target"
export ZIG=/absolute/path/to/zig-0.16.0/zig
mkdir -p "$TMPDIR" "$CARGO_HOME" "$CARGO_TARGET_DIR" \
  "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

cargo test --locked --release --manifest-path interop/iroh-peer/Cargo.toml
cargo build --locked --release --manifest-path interop/iroh-peer/Cargo.toml
"$ZIG" build test quic-test test-rust-interop -Doptimize=Debug \
  -Diroh-peer="$CARGO_TARGET_DIR/release/ozai-iroh-peer"
"$ZIG" build test quic-test test-rust-interop -Doptimize=ReleaseSafe \
  -Diroh-peer="$CARGO_TARGET_DIR/release/ozai-iroh-peer"
```

Cargo tests passed 12/12, and the release build had no warnings. Combined
Debug and ReleaseSafe runs passed 26/26 steps and 1751/1751 tests in each mode.
The totals were 1180 package tests, 566 vendored-core tests and five interop
tests. The opt-in `test-rust-interop` target requires `-Diroh-peer`. The normal
`test` step does not require Rust.

### Historical native gate record (before the RFC 7250 patch)

These direct native x86-64 Linux invocations record an earlier snapshot.
They predate the RFC 7250 patch and the live interop proof. Their test counts
are not current. The gate entry point did not run here because its `anyzig`
shim re-downloads the pinned toolchain and fails to extract it. See
[`0004`](docs/DECISIONS/0004-vendored-core-contracts.md) for that limitation.
No global tool, sandbox or launcher was repaired. These are not cross-platform
or performance results.

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

**1159/1159 tests over 22 build steps** were the counts for that earlier
snapshot, the same in both modes. The split was **599 package tests — 562 in
the main test root plus 37 across seven smaller integration and gate steps —
and 560 in the separately built vendored core** (`zig build quic-test`). No
step reported a leak under the test allocator.

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
separate counts from the historical 1159/1159 native suite. None is added to it.

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

### Earlier whole-tree coverage measurement (2026-10-06)

The instrumented run below measured the earlier source snapshot. It predates
the RFC 7250 patch. `zig build test quic-test
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

**The 2026-10-06 gate-7 measurement and its per-path dispositions are in
[`docs/COVERAGE-LEDGER.md`](docs/COVERAGE-LEDGER.md).** It re-ran the
instrumented suite in Debug and ReleaseSafe over the tree measured that day.
It reports 19/19 steps and 1171/1171 tests in both, and dispositions every
production line that was cold in both modes as test, refactor, or
accepted-with-a-reason. It describes that dated snapshot. The block above is
an earlier record from a different tree.

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
[`0004`](docs/DECISIONS/0004-vendored-core-contracts.md).

This coverage record does not measure iroh interoperability, performance or
node-level authenticated 0-RTT. The separate TLS and stream smoke above proves
only its listed routes. The full matrix remains open.

### What is built and tested but not yet reachable from a node

#### Historical reachability measurements

The earlier module-import survey found 165 of 281 compiled modules unreachable from `ozai-node`.
It classified 153 production modules and 12 test files as unreachable.
The 2026-10-06 coverage survey later recorded 168 of 285 modules under `src/`.
Both counts describe historical source snapshots, not current production call paths.
Neither count measures whether a branch executes.
No new reachability count replaces them here.
Their retained dispositions are in [`docs/COVERAGE-LEDGER.md`](docs/COVERAGE-LEDGER.md).

#### Current production routes and standalone models

| Subsystem | Production call chain | Remaining admission |
|---|---|---|
| Gossip codec | `Node.step` → `node_gossip.receive/gossip`. Outbound: `feedGossip` → `node_gossip_wire.send` → `gossip.codec.encode` → QUIC unidirectional stream. Inbound decode feeds the node handler. | Live stock Rust/Node both-role exchange and wrong-pin rejection passed in the 7/7 Debug run. |
| DNS, PKARR, TLS | `Node.step` → `node_discovery.pass` → `node_discovery_wire.ask`/`publish` → `dns_live.Retrieval.ask`, `pkarr_live.resolve` or `pkarr_live.publish`. PKARR uses `tls_client.Client.open` over TCP. | Discovery is opt-in. Defaults perform no lookup or publication. Configured Node API routes support PKARR, but the CLI does not enable its relay/resolve configuration. No Node-level PKARR network proof is recorded. Signed-provenance tests do not prove live publication. |
| TCP | `tls_client` uses `transport/tcp`. `tcp_client.Client.init` connects the relay stream. | Standalone TCP tests alone do not prove these consumers. |
| WebSocket, HTTP upgrade, relay | Outbound: `node_transport.send` → `State.sendMapped` → `Client.send` → `Session.relay`. Inbound: `takeRelay` → runtime poll/receive → TCP client → WebSocket/relay decode → `Bridge.recv`. | `tcp_client` and `tcp_server` use separate HTTP, forwarding, execution, listener, native-path and WebSocket processor modules. The carrier lifetime is separate from inner QUIC. No compatibility `Listener` remains. |
| Observed address, reporter, QAD, QNT | `node_build` passes opt-in `address_discovery_role` to bridge and dial configurations. The vendor negotiates native roles and processes observed-address frames. | No node consumer turns `Conn.observedAddress` into candidates or publications. `observed_reporter` and Number-Time `qnt.zig` remain standalone. |
| Path selection, table, revalidation, probe | `Node.step` → `node_native.pass` → native candidate/path snapshots → `path_action.planSelect` → `multipath.applyAction` → `Conn.selectPath`. | Generic `path_table`, `path_select`, `path_revalidate`, and `path_probe` remain standalone. No production caller mirrors native counters into their table. |

Discovery evidence has two separate scopes.
The UDP truncation-to-TCP and direct TCP test passed 5/5.
The identity-only DNS-to-QUIC test separately passed 5/5.
Neither result proves an always-active default discovery service.

Native Noq supports observed-address roles, NAT traversal frames and multipath wire frames.
The core admits configured physical candidates and retains only path IDs 0 and 1 for the connection lifetime.
The eight entries in `transport/multipath.Table` retain historical address pairs, not eight live transport paths.
Pinned Rust-generated `*.bin` files prove encoder/decoder agreement, not live address learning.
Configured `traversal.local_candidates` come from the caller.
The Zig node has no strict X.509 QAD client or mapping-learning consumer.
Rust's standalone QAD certificate service is a different route.

The remaining standalone models include Number-Time QNT, observed-report folding, generic path policy and the generic holepunch gate.
Native Noq NAT traversal does not use the Number-Time QNT codec.
Native terminal state does not feed generic `holepunch.Outcome`.
Accepted physical-source 1-RTT packet evidence does not prove per-path application bytes.
Node ticket capture, storage, reconnect offer, early-send limits and replay policy remain unwired.

##### Explicit standalone-subsystem admissions for issue #2

Issue #2 permits a named admission instead of a production route and real-route test.
The following modules remain standalone under that option.
Their module tests do not prove Node execution or give production coverage credit.
Each admission ends when a production consumer requires the named behavior.

| Subsystem | Explicit admission and proof boundary |
|---|---|
| Blob GetMany, Observe and Push | Their codecs and local policies exist, but the Node provider accepts only EOF-framed GET. Other requests return `WrongRequest`. Whole/range GET interop does not prove these variants. |
| BlobTicket and EndpointTicket production use | The codecs have no Node ticket caller. BlobTicket returns explicit `Loss` data for projection losses, but no production caller logs it. The planned logging route remains absent. |
| `node/topic_table` | This standalone table does not drive Node gossip. Production gossip uses configured topics and its own connection-stream map. |
| Peer `ticket_cache` and `ticket_lifecycle` | No Node route consumes these EndpointTicket policies. This is separate from the missing TLS resumption ticket integration. |
| `net/interface` | The local interface reader does not supply Node traversal candidates. The native route uses caller-configured candidates. |
| `statistics` and `statistics_report` | The subject-statistics policies have no Node consumer. Flat `node_stats` runtime counters do not exercise them. |
| `net/ecn_feedback` | The per-path feedback policy has no Node consumer. Production socket/core ECN transport does not prove this policy. |
| `connection_budget`, `lane_budget` and `shutdown_budget` | Node does not enforce these standalone policies. Existing connection capacity and shutdown behavior are separate runtime mechanisms. |
| Relay access policy and KeyMaterialAuth | The tested carrier uses challenge authentication. The separate `access_policy`/`server_handshake` model and HTTP KeyMaterialAuth credential path do not drive that carrier. No broader authorization proof is claimed. |


The mixed-protocol checks and controlled NAT acceptance use separate opt-in targets:

```sh
"$ZIG" build test-blobs-interop test-gossip-interop -Doptimize=Debug \
  -Diroh-peer="$CARGO_TARGET_DIR/release/ozai-iroh-peer"
source ~/.local/lib/host-scratch.sh
ORIGINAL_NETNS=$(readlink /proc/self/ns/net)
ORIGINAL_USERNS=$(readlink /proc/self/ns/user)
"$ZIG" build test-native-interop -- --node-peer "$NODE_PEER" \
  --rust-relay "$RUST_RELAY" --evidence-dir "$EVIDENCE_DIR" \
  --original-netns "$ORIGINAL_NETNS" --original-userns "$ORIGINAL_USERNS" \
  --endpoint-a-role both --for-ms 45000
```

The controlled NAT proof passed on 2026-10-07 in both endpoint-A roles. Two
independent Node/Noq processes ran behind separate Linux source-NAT routers,
with a stock Rust 1.3 relay server. Both exchanged the exact 33-byte payload
first over authenticated relay, then over direct UDP on stable connection ID 1;
both peer pins matched and both endpoint processes exited zero. This is not a
mixed Rust/Zig endpoint NAT proof. Bao, gossip and mixed Rust relay carrier
checks retain their separate live evidence.
The historical acceptance directory is
`/tmp/scratch/ozai-nat-final-8weQQz`.


Set `NODE_PEER` to the absolute path of `ozai-relay-fixture`, `RUST_RELAY` to the
absolute path of `ozai-iroh-peer`, and `EVIDENCE_DIR` to an existing caller-owned,
canonical directory under `/tmp/scratch/`.
Capture the original namespace identities before the build target enters its private
user and network namespaces. The fixture opens no host-network sockets.
No QAD listener, certificate, PEM file or private-key file is used by this NAT run.

Endpoint A binds `10.78.1.2:4444` with seed `5a` repeated 32 times and configured
WAN candidate `10.77.0.2:4444`. Endpoint B binds `10.78.2.2:4444` with seed `6c`
repeated 32 times and configured candidate `10.77.0.3:4444`.
Both pins are derived from the same deterministic Ed25519 seed construction used
by the Node fixture, rather than copied from another implementation's identity.
The candidates match the routers' actual port-preserving source-SNAT endpoints;
they are configured, not learned by QAD. No static DNAT rule is installed.
Established conntrack state reverse-translates peer replies.

By default both roles run: A server/B client, then A client/B server.
`--endpoint-a-role server` or `client` selects one execution.
Only the QUIC client initiates traversal; the server advertises and responds.
Each execution requires authenticated relay-first and direct-phase exact application
bytes on the same stable connection and pinned identity at each endpoint, one
dial/accept pair, both peer exits zero, and positive physical forwarding and translated
counters after the relay evidence opens the initially blocked UDP gate.

| Endpoint A role | Blocked packets | Direct packets | Translated packets |
|---|---:|---:|---:|
| server | 8 | 26 | 2 |
| client | 8 | 19 | 2 |

The rows above belong to the 2026-10-07 proof.
The fresh 2026-10-08 current-source NAT run followed a 7/7-step ReleaseSafe fixture build.
It exited 0 in 3.26 seconds and retained evidence at
`/tmp/scratch/ozai-nat-current-liHnnQ`.
Two independent Node/Noq peers used a stock Rust relay and distinct private source-NAT routers.
Both endpoint-A roles completed authenticated relay fallback then direct traffic with stable connection ID 1 at each endpoint.
Each checked exact 33-byte payloads and expected pins. Both peer exits were 0.
Cleanup terminated the owned relay and reaped the namespace keepers.
WAN candidates remained configured, not learned. This is not mixed Rust/Zig endpoint NAT proof.

| Current endpoint A role | Blocked packets | Direct packets | Translated packets |
|---|---:|---:|---:|
| server | 7 | 19 | 2 |
| client | 8 | 20 | 2 |


The bridge counter records dropped probes before opening and physically forwarded
candidate frames afterward. The translated counter records first SNAT packets
across both routers. The phase deadline is at most 45 seconds. Evidence preserves
each process's output, exit status, command, topology counters and cleanup record.
This does not close the separate Zig mapping-learning or strict X.509 QAD admissions.

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
to inflate counters. That dated run recorded two map allocation-fault gaps;
`src/transport/addr_map.zig` now sweeps reverse- and forward-insertion OOM,
rollback and recovery. The historical coverage lists apply only to their
named runs. The earlier whole-tree measurement is under
[*Earlier whole-tree coverage measurement*](#earlier-whole-tree-coverage-measurement-2026-10-06).

After the portability fixes, `zig-gate --no-cross --cov` passed all nine local
sections with zero lint/static findings. Native Debug and ReleaseSafe passed
543/543 and the separate vendored core passed 467/467 in both modes. In that
run the portable root was the 29-module, 438-test root and passed 438/438 in
both modes. That run predates every later expansion of that root: it is
**101 modules** as of 2026-10-07 (counted from `src/portable_test.zig`, method
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
| `src/gossip/` | HyParView, PlumTree, the gossip wire codec (`codec.zig` plus `codec/`), and a deterministic in-process simulator. The node encodes and decodes the codec through real QUIC stream routes. |
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

Four formats retain declared rather than captured upstream-byte vectors:
QUIC address discovery (`src/net/qad.zig`), Number-Time QUIC NAT traversal (`src/net/qnt.zig`),
the WebSocket layer (`src/relay/ws_frame.zig`) and host-answer records (`src/discovery/host_answer.zig`).
WebSocket vectors use RFC 6455 examples. Host-answer records are local constructions.
These declared tables are not evidence about an upstream peer.
Gossip now has pinned upstream serializer/state-machine outputs at `iroh-gossip` commit `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`.
The retained provenance and byte-for-byte tests are separate from live socket proofs and hand-built boundary vectors.
They are not packet captures.

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
devenv shell -- gate  # configured checks, both safety modes and strict retained coverage replay
devenv shell -- gate-strict  # exact alias of gate
```

`zig build run-ozai-node-id` prints this machine's node id in every form ozai
puts on the wire, and signs the rendered address to prove the text form is
faithful to the value.

`zig build run-ozai-node -- --progress --for 30000` emits live counter changes
after completed passes. Each `progress:` line is flushed immediately. Supervisors
can wait for a connection, delivery, or departure before sending SIGTERM.
Without `--progress`, the node prints only its banner and final report.
The SIGINT/SIGTERM handlers are installed before the listening banner is published.

Both entry points run the same project-owned, fail-closed gate.
It validates the pinned Zig version and runs strict ZBC and all remaining configured `zig-gate` sections.
It then builds and tests current source without instrumentation in Debug and ReleaseSafe.
Finally, it fully replays the required current-source retained coverage snapshot.
The schema-3 machine fence must name the exact manifest path and captured SHA-256.
Default does not start a new instrumented measurement. `gate-strict` is an exact alias.

The ZBC stage uses the declared Nix libc loader and matching libraries for the
installed ELF. Native, line-scoped exceptions require source and tool hashes
in `.zbc-source-exceptions.json`. A hash change invalidates the exception record.
The gate rejects wildcard and file-wide controls. ZBC must analyze the full
selected inventory and report no active findings. Tool errors and incomplete
summaries fail the gate.

The remaining `zig-gate` sections are fmt, build, test, ast-check, ziglint, zlint, zwanzig and cross-test.
Default also runs current uninstrumented `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy` in both safety modes.
There is no separate section named `refdecls` or `compile-all`.
Declaration checks run through the registered `std.testing.refAllDecls` tests.

The retained manifest, artifacts and raw counter files stay under an owned host-scratch evidence root.
The schema-3 ledger requires one `ozai-coverage-v2` fence with `measurement: {path, sha256}`.
The validator checks the exact manifest path and file SHA-256 before it trusts the manifest.
Full replay checks current source/compiler identity, scope, both modes, artifact/raw/report hashes, complete raw inputs, exact report rows and counters.
Stored cold tuples and ledger decisions must match the replay-generated tuples exactly.
The line denominator includes the full generated DWARF numeric-row universe, not only rows observed by instrumented PCs.
Positive GNU-PC mappings provide hits. Other numeric rows remain cold.
These are line hits, not branch or path coverage.
Only the explicit `measure` command captures fresh instrumented coverage in both modes.
After capture, regenerate the exact current fence, decisions and counters.
The normal `gate` command always requires full retained replay and fails closed on source/compiler/evidence drift.
See the [strict snapshot workflow](#strict-coverage-snapshot-workflow) for concrete refresh and replay commands.

The raw audit merges repeated binary/PC counters and checks them against the
report's project block totals. Known-project PCs with no source line contribute
to project block totals, not inferred line coverage. PCs with unresolved source
ownership remain separate and do not enter the project denominator. Both
categories require exact per-mode counts and written ledger reasons.
External DWARF paths do not enter the project source inventory.

`zig build fuzz --fuzz=1` runs the bounded decoder targets in ReleaseSafe.
The gossip oracle uses the production four-byte big-endian frame prefix.
It checks semantic values, borrowed slices and canonical encode/decode behavior.

`GATE_EXCLUDE` is set by the project gate to exclude `vendor/quic`,
`.zig-cache/`, `zig-out/`, `zig-cache/`, `zig-global-cache/` and
`zig-pkg/` from the configured source scan. The vendored core is still built
and tested by `quic-test` in Debug and ReleaseSafe on every default invocation.

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
**15 little-endian musl rows plus native x86_64 GNU**, not every Linux ABI.
Foreign GNU runs require compatible guest runtimes and are separate from
that self-contained gate. `cross-test.portable.profile.sh` surveys all 108
libc ABI targets listed by the pinned Zig 0.16 compiler. It uses
`src/portable_test.zig`: **101 pure modules** as of 2026-10-07, counted as the
unique non-`std` `@import` specifiers in that file, each with a matching
`refAllDecls` and no duplicates. It does **not** claim a non-Linux node
backend. An earlier figure of 32 modules is history and no longer describes
the file.

The default profile excludes LoongArch64 `muslf32`: pinned LLVM reports its
`lp64f` ABI as unstandardized. Canonical `musl` and soft-float `muslsf` remain.

The portable root excludes the disk-backed `blobs/observe.zig` and
`blobs/push.zig` suites. Their eight observe tests and seven push tests remain
collected by the full live `src/root.zig` suite, alongside the store, provider,
resume and node blob tests. The memory-only getter suite remains portable.
All 38 existing disk-backed temporary-directory call sites use approved
external host scratch; none was deleted or changed into a skipped test. This
collection boundary does not exempt those branches from the full live gate
or its coverage measurement.

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
has since grown to **101 modules** (2026-10-07), and this file records no
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
