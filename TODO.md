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
  stopped at. `src/discovery/lookup_live.zig` crosses the real-socket seam.
  `dns_live` consumes its `retryStream` for TCP fallback.
  `Node.step` drives opt-in live discovery through `node_discovery.pass`.
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

The current production call-site map is in
[`README.md`](README.md#current-production-routes-and-standalone-models).
Its reachability counts are history, not a current wiring inventory.

- **Issue #16: production inputs and standalone gate are distinct.**
  `node_holepunch.prepare` selects the smallest authenticated client connection ID.
  `node_native.pass` restricts client initiation to that recorded ID.
  Server reciprocal address handling remains eligible. Servers do not initiate.
  The actual negotiated two-client regression passed within a 7/7 focused run.
  It covers both table orders and reciprocal server advertisements.
  Removing the five-line client gate made that run fail on nonselected initiation.
  The generic `Join.selectConnection` and attempt planner remain standalone.
  `node_native.pass` calls native `addTraversalAddress` and `initiateTraversal`.
  The vendor sends Noq REACH_ADDRESS frames and exposes native traversal state.
  Native terminal state does not feed generic `holepunch.Outcome`.
  Number-Time `qnt.zig` is a different, standalone protocol.
  `prepare`/`received` compare the same connection's `total_packets_received` around each datagram.
  Only accepted 1-RTT short-header traffic from a physical IP records `.open`.
  Synthetic relay sources do not qualify.
  This proves accepted source traffic, not application bytes or a selected path ID.
  Native per-path byte counters do not feed the generic path table or gate.
  The connection input is produced; no Noq-to-QNT round adapter or per-path
  application-byte producer exists. The generic gate stays out of scope until
  those inputs have production sources.
- **Retry now has a preallocation route.**
  The manager handles Retry before it allocates a connection.
  `IncomingFilter.InitialPolicy` reaches that route through Bridge.
  A real normal-stack socket exchange recorded one unvalidated and one validated Initial.
  At the Retry response, `allocated_after_retry` was zero.
  The validated Initial then established one connection and exchanged exact application bytes.
  The vendor patch record separates this result from wire-vector evidence.
  That socket result is retained evidence, not a permanent executable test target.
  Manager and Bridge regressions cover the preallocation route in process.
- **Discovery has opt-in production consumers.**
  `Node.step` calls `node_discovery.pass`, which performs configured DNS and PKARR work.
  DNS truncation-to-TCP and direct TCP passed a separate 5/5 test.
  Identity-only DNS-to-QUIC separately passed 5/5.
  Default configuration performs no lookup or publication.
  The generic probe transport and observed-report models do not establish native mapping learning.

## Issue #16 checklist disposition

This maps every named item in [issue #16](https://github.com/CoffeeImpliesCode/ozai/issues/16).
Executable routes, retained live evidence and explicit admissions have different scopes.
The [integration snapshot](README.md#integration-snapshot-2026-10-08) records current normal-root integration and separate focused receipts.
Earlier schema-2 capture, replay and default-gate receipts are historical after the current repairs.
Fresh schema-3 capture, exact dispositions, strict replay, the full default gate and independent review remain pending.
No row below claims current final acceptance or new wire-interoperability proof.
Historical consumer receipts retain their original scope. They do not validate the repaired source.

The [current public consumer contracts](README.md#current-public-consumer-contracts) describe the source repairs.
They cover finite blob/Bao budgets, claimed-size truth, stream-local refusal and owned-secret cleanup.
They also cover gossip admission/timer/refill order, peer-owned assemblies, DNS cancellation and retained child lifetime.
QUIC assembly refusal remains terminal. Path abandonment instead preserves reliable retransmission and ACK metadata.
The native sequence/last-local cancellation model remains standalone, not a Node route.
Current consumer regressions passed in Debug and ReleaseSafe (`bg317`), including all 38 migrated gossip cases and three Resolver cancellation-reuse paths.
Each mode passed 28/28 steps and 2538/2538 tests, including library 1317, portable 1041 and child helpers 35.
Fresh schema-3 capture, final replay, full default gate and live smokes have not run.
These source repairs do not narrow any named issue requirement or extend historical wire proof.


| Issue item | Executable symbol or explicit admission | Proof and boundary |
|---|---|---|
| #1: RFC 7250 negotiation | Vendored `buildClientHello` writes both certificate-type offers. `buildEncryptedExtensionsFromEncoded` writes both selections. `parseEncryptedExtensions` and ClientHello parsing validate them. `serverBuildCertificateRequest` gates the client-auth request. | RFC 7250 parser/builder regressions live in `vendor/quic/src/quic/tls13.zig`. `test-rust-interop` exercises strict Noq and stock iroh client/server roles with pinned identities and exact stream bytes. The last complete integration passed 16/16 transport tests in both modes. `buildCertificateRequest` is a client-auth builder, not a certificate-type-extension writer. This is not the full upstream matrix. |
| #2: DNS/PKARR/TLS discovery | `Node.step` → `node_discovery.pass` → `node_discovery_wire.ask`/`publish` → `dns_live.Retrieval.ask`, `pkarr_live.resolve` or `pkarr_live.publish`, over `tls_client.Client.open`. | `node_discovery_lookup_test` proves identity-only DNS-to-QUIC. `dns_live` tests UDP truncation-to-TCP and direct TCP separately. Defaults perform no lookup or publication. PKARR is available through configured Node API routes. The CLI does not set a PKARR relay or `resolve_pkarr`, and no Node-level PKARR network test is recorded. Signed-provenance tests do not prove live publication. This is an explicit remaining admission under #2. |
| #2: TCP and relay carrier | `tls_client` uses `transport/tcp`. `tcp_client.Client.init` opens relay TCP. `State.sendMapped` → `Client.send` → `Session.relay` carries outbound inner QUIC. `takeRelay` returns decoded input to `Bridge.recv`. | Historical mixed-role receipts checked exact 34-byte payloads, pinned identities and remote application close code 0. Current split-module consumer acceptance remains separate from standalone TCP proof. |
| #2: QAD/QNT and `path_*` | Native `Conn.observedRoles`/`observedAddress`, `node_native.pass`, `path_action.planSelect`, `multipath.applyAction` and `Conn.selectPath` implement native extensions and selection. | No production mapping-learning consumer exists. Generic `observed_reporter`, Number-Time QNT, `path_table`, `path_select`, `path_revalidate` and `path_probe` remain standalone. This is an explicit admission, not coverage credit. |
| #6: mixed blobs | Node blob provider/getter routes and Rust `/iroh-bytes/4` use pinned iroh-blobs `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`. | Both directions verify Bao and exact whole/range output. The last complete integration passed 13/13 blob interop tests in both modes. |
| #6: mixed gossip | `feedGossip` → `node_gossip_wire.send` → `gossip.codec.encode`. Incoming QUIC streams decode through the node handler. | The last complete integration passed 15/15 gossip interop tests in both modes. Socket broadcasts in both roles and wrong-pin rejection are separate from pinned Rust codec vectors. |
| #6: mixed relay | The TCP carrier and inner QUIC routes above use Rust/Node peers in both roles. `node_close.closeConnections` flushes buffered close output before endpoint shutdown through `relay_runtime.flush`. | All four actual live role smokes passed in both modes within the fresh 48/48-step, 3068/3068-test integration. Rust relay regressions passed 4/4, including exact real-carrier bytes and inexact-payload rejection. Native endpoint callers observed remote application close code 0. Output-only partial writes and `WouldBlock` retain owner/bytes for idempotent close retry. A carrier handshake alone does not prove authenticated inner QUIC. |
| #6: controlled NAT | `node_native.pass` drives configured candidates through native traversal on the existing connection. `test-native-interop` drives independent Node/Noq endpoint processes and a Rust relay behind separate source-NAT routers. | Fresh 2026-10-08 evidence `/tmp/scratch/ozai-nat-current-liHnnQ` proves fallback then direct, both endpoint-A roles, exact 33-byte payloads, expected pins, stable connection ID 1 at each endpoint and peer exits 0/0. The ReleaseSafe fixture build passed 7/7 steps. NAT exited 0 in 3.26 seconds, with owned relay terminated and keepers reaped. Candidates are configured, not learned. Endpoints are not mixed Rust/Zig. The older `ozai-nat-final-8weQQz` receipt remains historical. |
| #8: determine core resumption | Vendored `serverTicketKey`, `serverSendTicket`, `parseNewSessionTicket`, `resumableTicket` and `tryProcessPsk` implement issuance, capture and resumption. | The 2026-10-07 core probe passed 6/6 in both modes at `d853694c`, including fresh server-side client pin enforcement. The resumed client has no fresh server-certificate proof. [Decision 0002](docs/DECISIONS/0002-async-substrate.md#issue-8-resumption-evidence-2026-10-07) records the answer. Node configuration, key retention, capture/store/offer, reconnect, early-send limits and replay policy remain absent. Issue #8 asks for the determination, not a Node 0-RTT implementation. |
| #11: dated measured coverage ledger | The schema-3 Measurement and `ozai-coverage-v2` fence bind the exact manifest path/SHA and original absolute runtime object path/SHA. | Fresh current-source capture and exact all-cold decisions remain pending. Replay must rehash the original runtime object independently of fresh `OZAI_COVERAGE_RT`. Historical schema-2 receipts do not close current acceptance. |
| #15: default gate and group reconciliation | Default runs configured full checks and uninstrumented Debug/ReleaseSafe builds and tests, then full retained replay. Declaration sweeps run within named test roots. | Current full default-gate acceptance remains pending. Focused policy suites passed 116/116 in each mode (`bg298`). This does not replace capture, replay or the full gate. |
| Holepunch: connection to punch on | `node_holepunch.prepare` selects the smallest authenticated client connection ID. `node_native.pass` restricts client initiation to that ID. | `node_native` test `"native driver initiates only minimum authenticated client ID in either table order"` covers both table orders and reciprocal server advertisements. Removing the gate produced nonselected initiation. Servers respond and advertise, without initiating. |
| Holepunch: QNT round | Native `addTraversalAddress`/`initiateTraversal` emit Noq traversal frames and expose native traversal state. | No Noq-to-Number-Time-QNT adapter exists. Native terminal state does not produce generic `holepunch.Outcome`. The generic round input is explicitly out of scope. |
| Holepunch: path-traffic signal | `node_holepunch.prepare`/`received` compare the same connection's `total_packets_received` around each datagram. | `node_holepunch` tests accepted same-connection traffic, publicly decryptable long-header rejection and synthetic relay rejection. Only accepted physical-IP-source 1-RTT traffic records `.open`. No per-path application-byte producer exists for the generic gate. That input is explicitly out of scope. |
| Retry before allocation and vendor record | `incoming_filter.InitialPolicy` reaches `Bridge.Config.initial_policy` and `decideInitial`. `ConnectionManager.recvDatagram` executes policy and `retryInitial` before `acceptConnection`. | Manager test `"Initial policy sends real Retry before allocation and accepts its echo once"` and Bridge test `"project Initial policy retries before accepting and preserves validation"` cover the route. Retained live socket evidence recorded one unvalidated and one validated Initial, `allocated_after_retry = 0`, then exact application bytes. `vendor/quic/VENDORED.md` section 11 records the patch. The socket receipt is not a permanent test target. Postaccept Retry remains an invalid refusal. |
| `addr_map` reverse rollback and fail-N | `MappedAddrs.get` routes allocation through `MappedAddrs.insert`. Its `errdefer by_addr.fetchRemove(addr)` removes the reverse entry if forward insertion fails. `sweepGetAllocationFailures` drives fail-N and recovery. | Tests `"allocation failures leave no reverse mapping and recovery allocates the same candidate"` and `"allocation failures preserve existing mappings through growth and recovery"` exercise both OOM insertions, rollback, retained entries and recovery. Fresh library suites passed 1236/1236 in both modes. |

The admission authority is explicit:

- Issue #16 says: "Each needs a producer or explicit out-of-scope admission."
  This applies to the three holepunch inputs, including the absent generic QNT and path-traffic producers.
- Issue #2 permits:
  > Record an explicit admission, the way `src/net/holepunch_target.zig:28-33` already does — "an ozai construction with no upstream byte sequence behind it; the tests here pin it, not a vector".

  This permits the named standalone-subsystem admissions below and the limited PKARR live proof.
  It does not waive the required mixed-peer live proofs.
- Issue #8 requires: "Determine whether the vendored core actually issues and accepts a session ticket on a path a client can resume."
  Its required determination is recorded. Node-level authenticated 0-RTT remains open.

### Issue #2 named standalone admissions

These admissions use issue #2's explicit alternative to production wiring and a real-route test.
They are scope admissions, not completed features or production coverage credit.

| Subsystem | Explicit admission |
|---|---|
| Blob GetMany, Observe and Push | Node serves only EOF-framed GET. It rejects these other variants with `WrongRequest`; no Node route or mixed-peer proof exists. |
| BlobTicket/EndpointTicket Node use and loss logging | The codecs remain standalone. BlobTicket returns `Loss`, but no production caller logs it. The plan's logging route remains absent. |
| `node/topic_table` | Node gossip uses configured topics and a separate connection-stream map, not this table. |
| Peer `ticket_cache`/`ticket_lifecycle` | EndpointTicket policy integration is absent. This is separate from TLS resumption/0-RTT tickets. |
| `net/interface` | No Node candidate producer uses the interface reader. Native traversal candidates remain caller-configured. |
| `statistics`/`statistics_report` | Subject-statistics models have no Node consumer. Flat runtime `node_stats` counters are not their producer. |
| `net/ecn_feedback` | The standalone per-path feedback policy has no Node consumer. Socket/core ECN transport is a separate implemented route. |
| Connection/lane/shutdown budgets | Node does not enforce these standalone policy modules. Existing runtime capacity and shutdown paths do not prove them. |
| Relay access-policy and KeyMaterialAuth paths | Challenge-authenticated carrier proofs do not cover the separate pure server/access policy or HTTP credential path. Their production integration is absent. |

An admission ends when a production consumer requires that behavior.
The [README route map](README.md#explicit-standalone-subsystem-admissions-for-issue-2) states the proof boundaries.


### Issue #15 strict gate workflow

Issue #15 permits a dated, source-bound ledger with on-demand regeneration.
Run `devenv shell -- gate` for configured full checks followed by strict retained replay.
Both modes always run `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy` without instrumentation.
The legacy `refdecls`/`compile-all` names map to declaration sweeps within the executed test roots, not separate driver sections.
`test`, `test-portable`, `quic-test` and `test-gate-policy` run those roots. `invariants` adds vendored source-contract checks.
Before direct commands, use the [README host-scratch setup](README.md#strict-coverage-snapshot-workflow).
It exports `TMPDIR`, `TMP`, `TEMP` and both Zig caches under the approved host-local root.
`measure` requires `OZAI_COVERAGE_RT`. Default retained replay does not require a fresh instrumentation runtime.
Use `"$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" scripts/project_gate.zig -- measure`.
This runs fresh instrumented capture and current uninstrumented builds/tests in both modes.
Update the exact schema-3 fence reference, cold decisions and counters for that capture.
Use `"$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" scripts/project_gate.zig -- validate /absolute/scratch/path/to/current/measurement.json`.
This command performs full explicit replay.
The supplied path and file SHA-256 must match the required machine reference.
Source, compiler, scope, artifact, raw-file, report or cold-decision drift fails closed.
Replay rehashes the original captured runtime object at its absolute path, not a fresh environment-selected object.
All source-inventory paths require representation, including absent roots and tests.
Every cold tuple requires an exact disposition. Cold DWARF rows can outnumber mapped PCs.
Stored cold tuples must match replay by content, with no missing, duplicate, stale or extra entries.
There is no advisory mode, opt-out, skip, schema fallback, tolerance or retry-to-green.
The [README workflow](README.md#strict-coverage-snapshot-workflow) states the commands and exact integrity checks.

The checklist retains all 48 primary criteria and their implementation or explicitly permitted admission.
Current acceptance and independent review remain pending. No final all-seven-issues completion claim is made.

## Open, and not yet closable here

- **Issue #8: core resumption works. Node-level authenticated 0-RTT remains open.**
  The core issues and accepts tickets under a stable `TicketKey`.
  It checks the PSK binder and retains fresh client certificate authentication
  on resumed connections. The selected core probe passed 6/6 tests, including
  the root test, in Debug and ReleaseSafe on 2026-10-07 at baseline `d853694c`.
  This is not a Node smoke or a full production 0-RTT feature.
  Bridge/Dialer omit resumption configuration. Node lacks a stable server key,
  ticket capture/store/offer, and a reconnect path.
  Ticket borrows must outlive the connection, including its handshake.
  Concurrent connections need separate stable copies or an equivalent lifetime guarantee.
  Resumption asserts the remembered server identity without a
  fresh server certificate proof. Early application send limits and replay
  policy remain unwired. Pure store and policy modules do not close these gaps.
  [Transport decision item 1](docs/DECISIONS/0001-transport-substrate.md#still-open-after-m8)
  records the commands, proof boundary, and key-rotation fallback limitation.
- **Interop.** The opt-in process/socket smoke now proves a TLS handshake and
  application-stream exchange with strict `noq` 1.3.0 and stock iroh 1.3.0.
  It covers four client/server routes and passes in Debug and ReleaseSafe.
  `README.md` records the command and the proof boundary.
  The full upstream matrix remains open and is still not reproducible from this
  repository: its runner is a git submodule outside the published package.
  This node has `tshark`, but lacks `docker` and
  `quic-network-simulator`. The matrix still needs a node with that toolchain.
  Four additional relay role routes passed with exact application bytes and peer pins.
  Live stock Rust/Node gossip passed 7/7 in Debug, including both roles and both wrong-pin rejections.
  Live Rust/Node Bao passed 5/5 tests over 6/6 steps in Debug.
  It covers six actual transfers: whole, cross-group range and partial tail in both roles.
  The historical controlled NAT proof passed on 2026-10-07 in both endpoint-A roles.
  Historical 2026-10-08 controlled-NAT proof passed at `ozai-nat-current-liHnnQ`.
  Both prove relay-to-direct on stable ID 1, exact 33-byte payloads, expected pins and zero peer exits.
  Configured source-SNAT candidates do not prove live mapping learning.
  Captured Noq vectors remain wire-only. `README.md` records separate dated counters and cleanup evidence.
  Node-level 0-RTT also remains open.
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
