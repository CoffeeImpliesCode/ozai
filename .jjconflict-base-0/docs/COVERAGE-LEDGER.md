# Coverage disposition ledger — gate 7 of `AGENTS.md` §4

Dated 2026-10-06. `zig-cov` on the pinned Zig 0.16.0, over the tree as it
stands at change `ywxmplllrxmt` (`9a7e0acd`).

`AGENTS.md` §4 gate 7 asks for one thing: every uncovered path is **test**,
**refactor**, or **accepted with a written reason**, and "not reachable" is not
a reason. This file is that record. It lives in `docs/` because `docs/` is the
only directory in this repository that is tracked, already linked from
`README.md`, and read as evidence rather than as build output — the alternative
was another loose file in the repository root next to the stale `*.zcov` dumps
this run removed.

**A change landed after the measurement.** While this ledger was being written,
`src/node/node_gossip_wire.zig` was added and `src/node/node.zig` and
`src/node/node_gossip.zig` were changed, wiring the gossip codec into the node.
That work is **not** in either run. It discharges the `refactor` disposition on
`src/node/node_gossip.zig` and `src/gossip/hyparview/topic.zig` in §5, and it is
what would give `src/gossip/codec.zig` its first attributed row (§7). Re-run
§1 and re-disposition those two modules before this ledger is used as the gate
record; the other 116 modules are untouched by that change.

## 1. The runs

Both runs instrument every artifact `build.zig` lists in its `-Dcoverage`
block: the seven test roots, the vendored-invariants root is *not* in that list
and therefore is not measured, and the `ozai-node` child the process tests
drive.

```
$ export TMPDIR=/tmp/scratch          # host-scratch cache root
$ zig-cov test --project=. -Doptimize=Debug --summary all \
      --format=json --output=$TMPDIR/cov/debug.json
$ zig-cov test --project=. -Doptimize=ReleaseSafe --summary all \
      --format=json --output=$TMPDIR/cov/release.json
```

`zig-cov`'s way of running that, printed by the tool verbatim:
```
zig-cov: running: ~/.local/bin/zig build test -Dcoverage=true -Dcoverage-rt=~/tools/zcov/zig-out/bin/../lib/zig-cov-rt.o -Doptimize=Debug
```
Exit 0 both times. Each run left 34 raw `coverage-<pid>.zcov` counter files in
its own `TMPDIR/zig-cov-<pid>/`, which is where the previous 24 loose files in
the repository root came from.

### The runs executed the whole suite

Both step tables:

```
Build Summary: 19/19 steps succeeded; 1171/1171 tests passed     # Debug
Build Summary: 19/19 steps succeeded; 1171/1171 tests passed     # ReleaseSafe
```

19/19 steps and 1171/1171 tests, matching the suite size this tree is known
to carry in both modes. The first Debug run was repeated with `--summary all`
precisely so the step table would be printed rather than inferred: without it
the build runner prints nothing on success, and an aborted binary would have
looked the same as a complete one.

Per-root Debug counts: `run test 1134 pass`, then 3, 2, 5, 6, 10, 4, 7 — 1171
in the seven instrumented test roots. `ozai-node` is built by the options step
and driven by the process tests inside the 10 and the 7.

### What these two runs do not measure

- **`src/portable_test.zig`** — the socket-free root behind `zig build
  test-portable`, 1002 tests. It is not part of the `test` step and was not
  measured here.
- **`vendor/quic/`** — the vendored core runs behind `--step quic-test`, which
  is not part of the `test` step. `zig-cov test` passes `zig build test` only.
- **The ten fuzz targets** behind `zig build fuzz`.
- **`test/vendored_invariants.zig`** — a step of `test`, but absent from
  `build.zig`'s coverage list, so it ran uninstrumented.

Every number below is therefore a statement about the `test` step alone.

## 2. The unit being dispositioned

`zig-cov` reports instrumented **block** counters and **inferred source-line**
attribution: it expands executed block addresses through the DWARF line table
and then applies a source-conditional filter. It does not measure paths and it
does not measure branches, and a zero can mean the filter withheld the
attribution rather than that the body never ran.

Two consequences shape this ledger:

1. **The two modes disagree wildly.** Whole-tree lines are 20 299/41 797
   (48.57 %) in Debug and 30 288/36 127 (83.84 %) in ReleaseSafe. ReleaseSafe
   inlines, so a body that has no PC of its own in Debug has one in
   ReleaseSafe. Neither number is a path measurement and adding them is
   meaningless. The two Debug runs also differ from each other by one line and
   24 blocks, because the process tests schedule against a real kernel; a
   coverage figure from this tree is not reproducible to the digit, and the
   ledger below is unaffected because it keeps only rows cold in both modes.

2. **Only rows cold in *both* modes are dispositioned here.** A row cold in
   Debug and hot in ReleaseSafe, or the reverse, is attribution churn, not a
   judgment call. This is what the density rule in §4 is asking for: a
   disposition that survives the mode change is a real gap.

The operational unit, stated once and used everywhere below:

> An **uncovered path** is a source line in the production (non-test) code of a
> newly added module that carries no retained attribution in the Debug run *and*
> none in the ReleaseSafe run.

Comment lines and blank lines are excluded from the count. They appear in the
report as cold rows (291 of them tree-wide) and are DWARF artifacts, not code.

## 3. The numbers

- **244** `src/*.zig` modules were added since `7a655810c6e3` (the commit before
  the wave-2 module-size split), by `jj diff -r 7a655810c6e3..@ --summary`.
- **226** of them carry attributed rows. **18** carry none — see §7.
- **893** production code lines are uncovered in both modes, spread over
  **118** of the 244 modules.
- Of those 893: **454** lines in **58** modules that production code calls, and
  **439** lines in **60** modules that nothing outside a test calls.
- **108** added modules have zero uncovered production lines. That is a
  statement about attribution, not about proof.

Whole tree, for scale: Debug 20 299/41 797 lines (48.57 %) and 26 961/61 924
blocks (43.54 %); ReleaseSafe 30 288/36 127 (83.84 %) and 26 319/55 855
(47.12 %).

## 4. The unwired modules: why they are not counted as covered

143 of the 244 added modules are never imported by production code. They are
built by `zig build test`, they carry tests, several carry fuzz targets, and
their measured coverage is high **because their own tests are the only thing
running them**. A coverage number over that set measures the test suite, not a
program.

`README.md` §*What is built and tested but not yet reachable from a node*
already records this gap; this run reproduces the count independently. The
method is a module-by-module crossing from `src/node/main.zig` with two
filters: `test` blocks are stripped before reading `@import`, and
`src/root.zig` is treated as the facade of `pub const` re-exports it is, so
only the re-export names the binary actually writes drag a module in. Result:
117 of 285 `src` modules wired, 168 unwired. Of the added set: 83 wired,
143 unwired.

**Every one of the 439 lines in §6 is dispositioned `refactor` — wire it —
and none of it is credited as covered.** The specific reason is the same for
the class and is not "unreachable": no file under `src/node/` names these
modules, so no code path of `ozai-node` contains them, and their counters come
entirely from test blocks. Until a `src/node/` caller exists, their coverage
proves the tests run and nothing about a running program. `README.md`
already carries the per-directory register; `TODO.md` §*Next* names the
missing producers for the hole-punch gate inputs, the live lookup seam, and
the 0-RTT hook.

The same rule applies inside the wired set. `src/node/node_gossip.zig` and
`src/gossip/hyparview/topic.zig` *are* wired, and their message arms are still
cold, because `src/node/main.zig`'s own module doc says the node "does not
gossip on the wire" and counts what membership asked to send instead. Those
rows are `refactor` for that reason, not `accept`.

## 5. Ledger A — wired added modules

58 modules, 454 both-mode uncovered production lines. Disposition is one of
**test** (add the narrowest test that forces it), **refactor** (change the
code), **accept** (accepted, with the reason stated).

`test` is the default. It is used wherever this tree holds no evidence that
the body ran; a disposition of `test` never flatters the number.

### `src/node/cli_options.zig` — 25 — **test**

`parse`'s refusal arms (a flag with no value, `NotASeed`, the four
`cli_values.reject` returns, the usage dump) and `contradictions`' ALPN-along-
with-peers conflict. `zig build test` drives the CLI only through argument
lists that all parse, so no rejection arm is entered. The earlier "CLI refusal
guards were separately smoke-tested" note in `README.md` §*Earlier records*
describes a run that is not a step of this build. Add one process test that
spawns `ozai-node` per malformed flag and asserts the refusal and its exit
code.

### `src/gossip/hyparview/topic.zig` — 23 — **refactor**

`handle`'s `.swarm`/`.gossip` receive arms, the `.quit` arm, and the
`appendMembership`/`appendPayload` action rows. The module is wired through
`node_gossip`, but the node does not put a gossip message on the wire — it
counts it. The state machine is driven by the in-process simulator, not by
`ozai-node`. Wire the codec into `src/node/` and these become node paths; until
then a simulator counter is not evidence about the node.

### `src/node/cli_report.zig` — 21 — **test**

`report`'s opening `text.print` and `reportRelay`'s `.off` and per-role print
rows. No test asserts anything about the final CLI summary, so the suite has no
reason to reach it. Add an assertion on the report the node prints at close —
the same shape as the `relay:…`/`ip:…` assertions already in
`test/integration_test.zig`.

### `src/node/node_build.zig` — 20 — **test**

`create`'s `errdefer` rollback chain, the `.DialedConnectionsLive` panic arm,
`error.NoSpaceLeft`, `start`'s `dials_refused` arm, and `deinit`'s `.abandoned`
log. These are the allocation- and dial-failure paths; nothing forces a
failing allocation inside `Node.create`. Note separately that `create` spans
lines 105-234 — 130 lines, over the 50-line ceiling in `AGENTS.md` §9 — and a
130-line constructor is itself the reason its interior attribution is coarse.
Split it before writing the fail-N sweep; the sweep will be unreadable
otherwise.

### `src/router/conn_dispatch.zig` — 18 — **test**

`dispatchStep`'s four state arms and every `.filtered`/`.failed`/
`.out_of_order` arm of the five `*Step` functions. These are the router's
out-of-order protocol refusals; the suite drives the happy path and the
handshake-failure path and nothing else. Add a state-machine test per
rejected event.

### `src/node/node_gossip.zig` — 17 — **refactor**

`feedGossip`'s `send_message`/`schedule_timer`/`emit_event` arms,
`noteNamed`'s ring shift, and `peerGone`. Same reason as `topic.zig`: the node
runs the membership state machine and throws the resulting actions away.

### `src/transport/socket_msg.zig` — 17 — **test**

The `errno` translation arms of `sendmsg` (`.MSGSIZE`, `.DESTADDRREQ`,
`.ACCES`, `.HOSTUNREACH`, `.NETUNREACH`, `.CONNREFUSED`, `.NOMEM`) and
`recvmsg`'s `ControlTruncated`. Forcing these needs a socket that returns a
chosen `errno`, and `test/` has no such seam — the same shape of debt as
`TODO.md`'s two allocation-fault seams, one layer down. Add a socket
interface seam that a test can fail on demand, then a case per arm.

### `src/transport/dial_client.zig` — 16 — **test**

`open`'s `CoreRefused` arm and its allocation rollback, and
`toCoreAddress`'s `.v4`/`.v6` arms. The conversion arms are cold in both modes
even though the suite dials over IPv4 loopback: the dialled address reaches the
core through `bridge_peer.zig`, not through `Dialer.toCoreAddress`, so this
duplicate conversion has no caller that runs. Either delete it or test it.

### `src/gossip/hyparview/sim_park.zig` — 15 — **test**

`parkMessage`/`parkSwarm`/`parkData` arms for `.join`, `.shuffle`,
`.shuffle_reply` and their payloads. The park/unpark round trip is only
exercised for the message kinds the simulator's own scenarios produce.

### `src/relay/frame_encode.zig` — 15 — **test**

`encodedLen`'s `.client_auth`, `.server_denies_auth`, the three datagram-frame
arms, `.endpoint_gone`, `.health` and `.restarting`, with the matching `encode`
rows. The pinned vectors round-trip the frames the suite exchanges; the
relay-auth and restarting frames are written only when a node is a relay client
against a live relay, which `test/relay_wire_test.zig` does not stage. Add one
encode/decode fixed-point case per frame variant — §2 of `AGENTS.md` asks for
exactly that sweep.

### `src/gossip/hyparview/sim_run.zig` — 14 — **test**

`tick`'s kill collection and timer-expiry park, `park`/`parkEvent` payload
copies, and `runDuration`'s closing tick.

### `src/node/node_relay_client.zig` — 14 — **test**

`converseMessage`'s status-frame arms (`.established`, displaced, ping),
`retain`, `converseOpen`'s dial-refused arm, and `converse`'s truncated-stream
counter.

### `src/router/shutdown.zig` — 14 — **test**

`step`'s `.serving`, `.draining_handlers`, `.cancelling_accepts` and
`.closing_endpoint` sub-switches. The shutdown order is exercised on the path
`test/two_process_test.zig` observes; the other three orderings are not.

### `src/node/node_accept.zig` — 13 — **test**

`perform`'s filtered, refusal and ignore verdicts, `runTask`'s accepting
callback, `drive`'s retry feed, and `namedBefore`.

### `src/gossip/hyparview/state_shuffle.zig` — 12 — **test**

`onShuffle`'s two message-size branches and `handleShuffleTimer`'s TTL
assignment.

### `src/transport/bridge_conn.zig` — 12 — **test**

`drain`'s `CoreRefused` arm and the recv-buffer drain, `open`/`write`'s
`CoreRefused` arms, and `closed`. The core-refusal arms are reachable — the
instrumented run logs "quic bridge: the core refused to open a stream:
OutOfMemory" — but the counter lands on the log line, not on the arm, so the
`error.CoreRefused` return itself is unproven.

### `src/node/node_relay_serve.zig` — 11 — **test**

`serveRegister`'s admit-refused and queue-full arms, `serveAdmit`'s deferred
stream, `serveAction`'s write and stream-close arms.

### `src/transport/socket_open.zig` — 11 — **test**

`setOption`/`trySetFlag`/`probeSegmentation`/`requireCongestionOption`'s
`errno` and `OptionError` translation arms. Same missing seam as
`socket_msg.zig`.

### `src/node/node_relay_forward.zig` — 9 — **test**

`forward`'s queue-full and oversized-payload arms and `serveMessage`'s
datagram and pong arms.

### `src/relay/frame_vectors.zig` — 9 — **test**

`hexdump` in full. It is a diagnostic dump on a failure path; no test reaches
it, and it is 10 lines of string building that a single assertion on the dump
format would cover.

### `src/node/node_relay_release.zig` — 8 — **test**

`reportDisconnection`'s `.duplicate`, `.promoted` and `.already_gone` arms and
its queue-full catch.

### `src/node/node_transport.zig` — 8 — **test**

`deliver`'s reply arm, `drain`'s egress send, `expire`'s `.reaped` record and
`.relay` route.

### `src/relay/server_handshake.zig` — 8 — **test**

`step`'s `.offered`, `.frame`, `.access` and `.stream_ended` refusal arms and
the `SignatureInvalid` denial; `admit`'s `.none` and `.malformed` credential
arms.

### `src/relay/server_registry.zig` — 8 — **test**

`find`/`place`/`rehash`'s probe-walk and tombstone arms. A registry collision
and a rehash both need enough entries; no test reaches the growth path.

### `src/transport/socket_addr.zig` — 8 — **test**

`writeSockaddr`/`readSockaddr` for both address families, including the
port byte-order conversions. No test binds or receives through this seam; the
loopback roots bind through `transport/socket.zig`'s own option path.

### `src/base/relay.zig` — 7 — **test**

`IpAddress.order`'s same-family comparisons, `SocketAddr.order`'s
`.eq` port arm, `SocketAddr.format`'s IPv6 tail and `RelayUrl.format`'s
path-separator write. `IpAddress.order` is part of the wire format — it is what
makes a ticket a stable identifier — and its two family arms are unproven in
both modes.

### `src/endpoint/accept_machine.zig` — 7 — **test**

`forget`'s compaction, `draining`'s `.arrived`/`.filtered` hold, `filtered`'s
`.negotiate_alpn` spawn, `owed`'s `.shutdown` action, and `init`'s
`incoming_filter` field.

### `src/gossip/hyparview/sim_simulator.zig` — 7 — **test**

`gossipRound`'s harvest/tick cycle and `harvest`'s `.swarm`/`.neighbors` arms.

### `src/gossip/hyparview/state_arms.zig` — 7 — **test**

`handleMessage`'s `.join`, `.forward_join`, `.shuffle`, `.shuffle_reply`,
`.neighbor` and `.disconnect` dispatch rows, and `onNeighbor`'s
disconnect-echo arm.

### `src/net/report_measure.zig` — 6 — **refactor**

The `.qad_ipv4` and `.qad_ipv6` arms of `relay`, `latency`, `list` and
`listConst`. The report holds three probe lists and only the direct one has a
producer; `TODO.md` §*Next* records that QAD has no producer behind it. Either
give QAD a producer or drop the two arms — an arm that no code path can select
is a second convention, not a feature.

### `src/transport/bridge_peer.zig` — 6 — **test**

`init`'s allocation rollback and both `toCoreAddress` calls, `exchange`'s
reply arm.

### `src/transport/dial_pair.zig` — 6 — **test**

`init`'s three `errdefer` rollbacks and `exchange`'s forward/move loop. This
is a test-only pair of bridges; the rollbacks need a failing allocator.

### `src/wire/quic_varint.zig` — 6 — **test**

The two-byte, four-byte and eight-byte length branches. `src/relay/` frames
are varint-prefixed, so these are on the relay's write path; the eight-byte
branch is never selected because no frame length reaches 2^30.

### `src/gossip/hyparview/state_views.zig` — 5 — **test**

`removeActiveByIndex`'s `.random`, `.disconnect_received`,
`.connection_closed` and passive-refill arms.

### `src/gossip/plumtree/state_control.zig` — 5 — **test**

`onIHave`'s graft-timer scheduling and `onNeighborDown`'s round compaction.

### `src/node/node_relay_table.zig` — 5 — **test**

`initRelay`'s five `errdefer` rollbacks for the per-client allocations. Same
fail-N debt class as `TODO.md`'s two named seams; the relay role is the only
caller.

### `src/gossip/plumtree/state_tree.zig` — 4 — **test**

`handleMessage`'s `.prune` and `.graft` control arms.

### `src/relay/frame_roundtrip.zig` — 4 — **test**

`datagramsOf`/`nodeOf`'s two batch-frame arms. The pinned invariant round trip
loops the four datagram frames, and the batch pair is not selected by any
fixture the loop uses.

### `src/endpoint/accept_fixture.zig` — 3 — **test**

The `shutdown` handler callback body. `accept_fixture.zig` is a test fixture
that is nevertheless wired into the endpoint's production types; its
`shutdown` callback is never invoked by the fixture that builds it.

### `src/node/cli_loop.zig` — 3 — **test**

`drive`'s retry send and the `node.wait` poll, and `shut`'s return row. The
one-shot CLI run has no peer that is gone by the time it sends.

### `src/transport/socket_cmsg.zig` — 3 — **test**

`putValue`'s `c_int` and `u16` word writes and `readCmsg`'s truncation break.
ECN marking is exercised; the short-value and truncated-control-message cases
are not.

### `src/gossip/plumtree/id_cache.zig` — 2 — **test**

`evictSlot`'s soonest-expiry scan. Needs a cache past capacity.

### `src/gossip/plumtree/message_cache.zig` — 2 — **test**

`evictSlot`'s soonest-expiry scan, same shape as `id_cache.zig`.

### `src/gossip/plumtree/state_missing.zig` — 2 — **test**

`takeOldestClaim`'s peer/round compaction.

### `src/net/report_fold.zig` — 2 — **test**

`format`'s `"none"` preferred-relay write and `choosePreferredRelay`'s
assignment. No observation ever prefers a relay, because no probe is taken
through one.

### `src/relay/frame_decode.zig` — 2 — **test**

`datagramsOf`'s two batch-frame arms, same gap as `frame_roundtrip.zig`.

### `src/transport/bridge_address.zig` — 2 — **test**

`toCoreAddress`'s `.v4` and `.v6` arms. `fromCoreAddress`'s two arms are
attributed, so the conversion runs on the receive side and not on the send
side — a real asymmetry between two mirrored functions.

### `src/transport/bridge_manager.zig` — 2 — **test**

`recv`'s non-socket classification arms (`.any_path`, `.relay`, `.custom`) and
the `send_response` reply.

### `src/gossip/hyparview/sim_harness.zig` — 1 — **test**

`draw`'s `.drawn` range branch; no scenario draws a latency range.

### `src/gossip/hyparview/sim_report.zig` — 1 — **test**

`neighbourEvents`' return row after the sort.

### `src/gossip/hyparview/sim_swarm.zig` — 1 — **test**

`eagerIndices`' counting row.

### `src/gossip/hyparview/state_departure.zig` — 1 — **test**

`onDisconnect`'s `alive_disconnect_peers.insert`.

### `src/gossip/plumtree/message.zig` — 1 — **test**

`deliveryScope`'s `.swarm` arm; only the gossip scope is delivered.

### `src/node/cli_values.zig` — 1 — **test**

`parseSocket`'s bracketed-host strip. No test passes `--bind [::1]:0`; the
whole tree's tests are IPv4 (`grep -rn '::1' test/` returns nothing), which is
the root of several IPv6 arms above.

### `src/node/node_close.zig` — 1 — **test**

`performShutdown`'s reaped-connection row.

### `src/node/node_loop.zig` — 1 — **test**

`windDown`'s error argument row; the loop is never stopped by an error.

### `src/relay/frame_types.zig` — 1 — **accept**

`const std = @import("std");` at line 83. An import declaration emits no code
of its own; there is no PC to attribute to it and no path through it. Accepted
as a DWARF row with no machine behind it.

### `src/transport/dial_route.zig` — 1 — **test**

`ownerOf`'s non-socket classification arms (`.any_path`, `.relay`, `.custom`).
`expire` in `node_transport.zig` calls `ownerOf` for exactly this and is itself
cold.

## 6. Ledger B — unwired added modules

All 60 rows: **refactor — wire it**. The reason is the class reason in §4:
nothing under `src/node/` imports the module, so no `ozai-node` execution
contains these lines and their counters come from test blocks alone. The
`README.md` register gives the per-directory count; the table gives the exact
cold declarations. These 439 lines are **not** counted as covered anywhere in
this ledger.

| module | both-mode uncovered production lines | declarations |
|---|---|---|
| `src/discovery/pkarr_live.zig` | 72 | `exchange`, `publish`, `readResponse`, `relayStatus`, `resolve`, `text`, `writeRequest` |
| `src/discovery/tls_client.zig` | 54 | `acceptOne`, `bindLoopback`, `close`, `open`, `plaintextReader`, `plaintextWriter`, `rescanTrust`, `streamIn`, `streamOut`, `writeAll` |
| `src/gossip/codec/membership.zig` | 30 | `decode`, `encode`, `encodedLen` |
| `src/transport/tcp_sys.zig` | 26 | `beginConnect`, `createStream`, `recvStream`, `sendStream` |
| `src/blobs/framing.zig` | 20 | `eql`, `write` |
| `src/ticket/body.zig` | 19 | `maxTransportAddrLength`, `readSocketAddr`, `readTransportAddr`, `writeSocketAddr`, `writeTransportAddr` |
| `src/discovery/dns_live.zig` | 18 | `receiveAnswer`, `sendQuery` |
| `src/transport/tcp.zig` | 14 | `acceptOne`, `awaitReady`, `bindLoopback`, `connect`, `create`, `open` |
| `src/discovery/item_encode.zig` | 13 | `encodeAddr` |
| `src/net/probe_run_turn.zig` | 12 | `cancel`, `drive`, `resultFor`, `sendIndex` |
| `src/discovery/txt.zig` | 10 | `maxTxtStringsLength`, `next`, `parseTxt`, `socketOf`, `writeSocketAddr` |
| `src/blobs/provider.zig` | 9 | `answer`, `readAll`, `runRange`, `selectedRange`, `writePlan` |
| `src/blobs/wire_test_support.zig` | 9 | `hexdump` |
| `src/gossip/codec/broadcast.zig` | 7 | `encodedLen`, `scopeLen`, `writeScope` |
| `src/net/holepunch_gate.zig` | 7 | `settle` |
| `src/discovery/pkarr_services.zig` | 6 | `pkarrNext` |
| `src/gossip/codec/frame.zig` | 6 | `encodeBody`, `encodedLen` |
| `src/net/interface.zig` | 6 | `ipFrom`, `moved` |
| `src/net/probe_turn.zig` | 6 | `new`, `step`, `wakeAt` |
| `src/transport/multipath.zig` | 6 | `init`, `mirror` |
| `src/blobs/getter.zig` | 5 | `expectedAnswer` |
| `src/net/holepunch_path.zig` | 5 | `laterThan`, `prune` |
| `src/net/observed_reporter.zig` | 5 | `get`, `observe`, `slotOf` |
| `src/discovery/dial_source_harness.zig` | 4 | `deinit`, `init` |
| `src/gossip/gossip_actions.zig` | 4 | `dialTarget` |
| `src/net/qad.zig` | 4 | `decode` |
| `src/blobs/observe.zig` | 3 | `boundariesOf` |
| `src/discovery/lookup_answer.zig` | 3 | `deinit`, `readAnswer` |
| `src/discovery/lookup_test_support.zig` | 3 | `expectHex` |
| `src/gossip/codec_test.zig` | 3 | `expectRefused` |
| `src/net/holepunch_failure_memory.zig` | 3 | `forget`, `remember` |
| `src/net/holepunch_trigger.zig` | 3 | `settle`, `start` |
| `src/relay/liveness.zig` | 3 | `check` |
| `src/relay/reconnect.zig` | 3 | `advance`, `const second = std.time.ns_per_s;` |
| `src/relay/relay_ingress.zig` | 3 | `presented`, `receive` |
| `src/blobs/bao_plan.zig` | 2 | `itemBytes`, `push` |
| `src/discovery/item_resolution.zig` | 2 | `isEmptyResult`, `itemCount` |
| `src/discovery/pkarr_body.zig` | 2 | `writeStrings` |
| `src/discovery/resolve_fanin.zig` | 2 | `itemCount`, `merge` |
| `src/net/holepunch_run_peer.zig` | 2 | `observePeer` |
| `src/net/qnt_state.zig` | 2 | `collectRates` |
| `src/net/resumption_acceptance.zig` | 2 | `inherit` |
| `src/net/statistics.zig` | 2 | `find`, `sortAscending` |
| `src/net/statistics_report.zig` | 2 | `format`, `mixedTable` |
| `src/node/ticket_cache.zig` | 2 | `relayHost`, `take` |
| `src/blobs/blob_claim.zig` | 1 | `claim` |
| `src/discovery/host_answer.zig` | 1 | `pub const Error = wire.WireError \|\| host` |
| `src/discovery/item_record.zig` | 1 | `name` |
| `src/discovery/lookup_retrieval.zig` | 1 | `begin` |
| `src/gossip/hyparview/peer_data_test.zig` | 1 | `const PeerDataMap = peers.PeerDataMap;` |
| `src/net/address_change.zig` | 1 | `overlaps` |
| `src/net/path_probe.zig` | 1 | `plan` |
| `src/net/path_select.zig` | 1 | `chosenPort` |
| `src/net/path_table.zig` | 1 | `ports` |
| `src/net/probe_plan.zig` | 1 | `delayFor` |
| `src/net/relay_selection.zig` | 1 | `homeRelay` |
| `src/node/ticket_lifecycle.zig` | 1 | `relayHost` |
| `src/relay/access_policy.zig` | 1 | `event` |
| `src/relay/relay_auth_policy.zig` | 1 | `plan` |
| `src/relay/relay_egress.zig` | 1 | `step` |

## 7. What this measurement cannot tell you

- **18 added modules produced no attributed row at all**, so nothing in them is
  dispositioned here and their absence is **not** a clean bill:
  `src/crypto/blake3_subtree_vectors.zig`,
  `src/discovery/lookup_datagram.zig`, `src/gossip/codec.zig`,
  `src/gossip/codec/tags.zig`, `src/gossip/hyparview/bounds.zig`,
  `src/gossip/hyparview/sim.zig`, `src/gossip/hyparview/sim_network.zig`,
  `src/gossip/hyparview/state.zig`, `src/gossip/plumtree/claim_table.zig`,
  `src/gossip/plumtree/config.zig`, `src/gossip/plumtree/limits.zig`,
  `src/gossip/plumtree/state.zig`, `src/gossip/topic_bounds.zig`,
  `src/node/node_config.zig`, `src/node/node_stats.zig`,
  `src/relay/http_upgrade_types.zig`, `src/transport/dial_config.zig`,
  `src/transport/socket_error.zig`.
  Several are facades, but `src/gossip/codec.zig` holds 28 declarations and the
  whole gossip wire codec is in that list. An absent row does not prove the
  compiler emitted no code, and here it very likely did emit code the reporter
  declined to attribute. Measuring the codec needs a build that keeps a PC per
  declaration.
- **These are lines, not paths.** A row is one attributed line. A path through
  `sendmsg` that returns `error.AGAIN` is one row here, not a statement about
  every way to reach it.
- **Zero attribution is not proof of an untested body.** The reporter's
  conditional filter, inlining and elision all produce zeros on bodies that ran.
  That is why §5 defaults to `test`: a disposition of `test` on a body that
  actually ran costs a redundant assertion, while an `accept` on a body that
  did not costs a hole. Only one row is accepted, and it is an import
  declaration with no code behind it.
- **The portable root, the vendored core and the fuzz targets are outside
  these runs** (§1). No coverage claim is made about them here.

## 8. Scoped RFC 7250 coverage follow-up

Date: 2026-10-07. Source base: `6dc7986a` plus the uncommitted issue #1 RFC
7250 patch and the SNI-capacity guard with its boundary regression. The helper
range remained unchanged after these reports.

Focused coverage ran six tests in each mode. Both modes reported 3/3 steps and
6/6 tests. For `vendor/quic/src/quic/tls13.zig:4414-4452`, inferred source-line
attribution was 27/27 in Debug and 25/25 in ReleaseSafe. The reports are
`/tmp/scratch/ozai-rpk-coverage/reviewed-debug.json` and
`/tmp/scratch/ozai-rpk-coverage/reviewed-release-safe.json`.

The helper range has no cold attributed lines in either report. The new
capacity guard at `vendor/quic/src/quic/tls13.zig:4027` has six Debug and four
ReleaseSafe attributed hits. Its boundary regression returns `InternalError`
for an oversized SNI and emits a 4096-byte ClientHello at the adjacent fit.
That behavior is independent of the line counts.

These are inferred attributions over instrumented blocks. They are not branch,
path or whole-TLS coverage.

**Accepted unmeasured negative guards.** The certificate send and receive
guards require successful certificate-type negotiation. A correctly ordered
handshake reaches those states only after both offers and selections pass.
The core suite exercises the valid transitions. This note does not claim that
invalid message ordering or all negative TLS paths were measured.

This scoped addendum does not refresh the broader whole-tree ledger above.