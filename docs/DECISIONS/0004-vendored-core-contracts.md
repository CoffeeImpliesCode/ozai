# 0004 — Vendored core contract cutover

- **Status**: accepted, recorded 2026-10-03.
- **Scope**: the working tree after the public contract cutover, based on
  `b7e2d4f2e43ec546f124f7bce27c2e06a453f83b`; Zig 0.16.0, native x86-64 Linux.
  Source inspection, exercised compilation and runtime observations are
  separate evidence. No result here extends to another target.
- Related: [`0001-transport-substrate.md`](0001-transport-substrate.md) (the
  vendored QUIC core),
  [`0003-api-contract-cutover.md`](0003-api-contract-cutover.md) (this package's
  own surface), [`0002-async-substrate.md`](0002-async-substrate.md).

## Context

0003 covered this package's own declarations. This pass covers the vendored QUIC
core, which a consumer reaches through `src/transport/quic_bridge.zig` and
through the registered `quic` module and `Connection`'s accessible fields.
Relative-import-only helpers and application-private declarations are not
additional supported package routes.

What that found was not one class of defect but four:

1. Wire lengths a peer chooses were trusted where a boundary had to be checked.
   A ClientHello session ID or cipher-suite list, a ServerHello extension block,
   a transport-parameter scalar, a preferred address and a truncated PKCS#8
   length all indexed past the message.
2. Values a caller supplied were borrowed where a later re-encode outlived the
   borrow. A server's transport parameters kept the caller's connection-id
   slices, and a connection's packer, flow control and TLS configuration
   described ownership the code did not keep.
3. Peer delay arithmetic trapped on shifts and multiplication. Separately, a
   locally configured RSA key with an empty exponent indexed an empty integer.
4. Contracts the code did not keep. A caller buffer could be written past by
   Initial padding, a refused allocation could consume a stream ID and leak the
   stream, a peer-reset bidirectional stream was never reclaimed, a certificate
   entry silently removed the connection's client-authentication policy, and
   two ends of a resumed handshake could derive different 0-RTT keys.

## What changed, and what it costs a consumer

### Wire boundaries are refused, not clamped

`TransportParams.decode` now requires every known parameter to consume exactly
its declared length, a preferred address to be `41 + cid_len` bytes with a
connection ID of 1..20, and a migration-disable flag to be empty; unknown ids
are still skipped by their declared length. A peer that violates any of these is
`error.TransportParameterError` instead of a silently reinterpreted value.

`Tls13Handshake` refuses a ClientHello cipher-suite or compression list that does
not fit the message, a ServerHello extension block or inner extension that runs
past it, and a PKCS#8 structure whose lengths the walk cannot honour. Those
three paths previously panicked, and the first two are reachable by anyone who
can send one CRYPTO frame.

`Connection.validatePeerTransportParams` requires client-sent Version Information
to include Chosen Version in Available Versions. That requirement does not apply
to a server's list ([RFC 9368 §3](https://www.rfc-editor.org/rfc/rfc9368.html#section-3)).

### Values a connection keeps are its own

`acceptInto` and `connectInto` copy the header, original-DCID and Retry-SCID
bytes into the connection's inline buffers before anything points at them, and
refuse a connection ID over 20 bytes before allocating. A caller no longer has to
keep the arrays it passed in alive for the connection's lifetime. The connection
still must not move after construction: its transport parameters and the
handshake's copy of them are views into its own storage.

### Peer numbers saturate instead of trapping

An encoded ACK delay is capped at the peer's `max_ack_delay` before it is
scaled, an ACK_FREQUENCY delay saturates at the signed duration limit, and an
ACK deadline beyond that limit saturates rather than overflowing the clock. A
zero-length RSA public exponent is `error.InvalidKey` instead of an index past
the end of the integer.

### Caller buffers bound what is packed

`max_packet_size` is a whole-UDP-payload number rather than a per-packet one,
because `Connection` writes it from the path MTU: `packCoalesced` spends it once,
as `min(max_packet_size, out_buf.len)`, and every encryption level is offered
what is left of that one budget (`PacketPacker.packCoalesced` in `packet_packer.zig`).
Initial padding cannot exceed it. A client needs at least 1200 bytes for its
Initial datagram; insufficient space must leave its flight pending, not emit an
invalid short Initial. Server output still respects its anti-amplification
budget. MTU probes clamp at 1500 and report the actual size
(`PacketPacker.packMtuProbe` in `packet_packer.zig`). `PacketPacker.init` no longer accepts an
unused allocator. Control frames that do not fit remain queued.
An Initial header must also fit the internal staging budget. An oversized Retry
token returns no packet without spending a packet number or consuming queued
frames, even when the caller supplies a larger output buffer.

### Allocations consume only committed state

A refused `openBidiStream`/`openUniStream` frees the stream it created and
consumes no stream ID. A peer-initiated stream that cannot be created leaves the
creation watermark at the last stream that exists, so a retry resumes instead of
replacing and leaking. A bidirectional stream the peer resets is reclaimed once
its send side has settled, and never while pinned.

Packet tracking reserves result storage before removing packets or changing
RTT and congestion accounting. An allocation refusal must leave tracked packets
available for retry; result cleanup must never free packets still in the map.

### The handshake agrees before it commits

A selected certificate with no local client-authentication override inherits the
connection policy. A resuming client offers its ticket's cipher suite, and a
ticket records negotiated ALPN, suite, and the QUIC version the connection that
issued it **ended on**. Both ends compare that field against the version the
**resuming connection starts on**, not the one it ends on
(`SessionTicket.quic_version`, `Tls13Handshake.resumableTicket` and `tryProcessPsk` in `tls13.zig`).
Under compatible version negotiation those are two different versions, and the
ticket belongs to the second one: a client whose first flight is version 1 may
negotiate version 2 and still resume a version-1 ticket, while a ticket issued
on a connection that ended on version 2 is usable only where the next one starts
on version 2. A mismatch is not a failure. The client resumes nothing, offers no
`early_data` and sends no 0-RTT, and the server falls back to a full handshake;
what it costs is a resumption, not an authentication.

During compatible version negotiation, 0-RTT keys and long headers retain the
first-flight version; handshake and application keys use the negotiated version
([RFC 9369 §4.1](https://www.rfc-editor.org/rfc/rfc9369.html#section-4.1)).
New tickets belong to the negotiated version
([§5](https://www.rfc-editor.org/rfc/rfc9369.html#section-5)).
This is a core contract, not a node-level 0-RTT feature claim.

The protocol a ticket records is agreed in both directions, and it is agreed as
a whole name. Both writers copy the connection's selection verbatim; a client
offers a ticket only while its own proposal still holds the protocol that ticket
records (`tls13.zig:1882-1887`), and a server that opens the ticket compares the
sealed name against the protocol it just selected and accepts no early data when
the two differ (`tls13.zig:3498-3567`). The record is
`negotiated_alpn_len_max` bytes — 32 (`tls13.zig:774`), the same width as the
handshake's own `selected_alpn` and not RFC 7301's 255 — so the sealed
plaintext is its 45-byte fixed head, those 32 and a 16-byte tag, and a sealed
ticket runs to 93 (`tls13.zig:938-962`). A proposal list that will not encode
whole fails the client's first `step` with the `error.InternalError` its
constructor already reports: the ClientHello is built into a bounded 4 KiB
staging buffer (`tls13.zig:2347`) and nothing is trimmed, because a peer cannot
tell a short ClientHello from a whole one. The RFC 9368 §3 membership question
costs one `bool` beside the decoded version fields rather than a second list:
every declared word is validated, the first eight are retained, and the answer
is decided over the whole list (`transport_params.zig:228-255`, `:584-607`).

TLS in-place constructors report `error.InternalError` on failed parameter
encoding instead of publishing a truncated prefix. Connection construction
releases the allocated handshake on that error. `transport_params.encode_len_max`
is a derived 324-byte bound for legal local values; invalid inline lengths are
programmer precondition violations, not guaranteed writer errors.

The client constructor transfers handshake ownership only after initialization
succeeds. A later allocation failure uses connection teardown once, rather than
both a local allocation guard and connection teardown freeing the same pointer.

## Decisions and consumer costs

Every entry below states a boundary judgment of this implementation audit: what
was chosen, what forced it, what a consumer pays and which counterchoice would
win under different constraints. They are decision criteria, not test results,
and none of them claims acceptance evidence for a repair.

### Inline connection identifiers

- **Priority**: retain valid transport-parameter views without caller pinning.
- **Constraint**: TLS re-encodes identifiers after construction; connection state
  already contains fixed-size CID storage.
- **Consumer cost**: construction copies at most 20 bytes per identifier. The
  connection must retain its final address because internal views borrow it.
- **Counterchoice**: borrowing external identifiers wins for a caller with
  independently pinned, immutable storage and a strict inline-state budget.
- **Grade and origin**: taste `analyst-inferred`, this implementation audit.

### Non-owning packet assembly

- **Priority**: bounded output and recoverable lack of room.
- **Constraint**: the caller owns datagram buffers and the connection owns queued
  frames, packet numbers and the send budget.
- **Consumer cost**: provide valid packet room and retry after a zero-length
  result. The packer retains no unused allocator.
- **Counterchoice**: a growing owned output wins when the caller needs one
  collected result and has no reusable buffer; it transfers allocation and
  cleanup obligations to that caller.
- **Grade and origin**: taste `analyst-inferred`, this implementation audit.

### Allocation failure transactions

- **Priority**: keep ownership and congestion accounting consistent.
- **Constraint**: returning packets through an allocating result cannot commit
  removals before the result can own them.
- **Consumer cost**: allocation can fail before progress; retry remains valid.
- **Counterchoice**: caller-provided bounded result storage wins when allocation
  is prohibited and the caller can repeatedly drain committed prefixes.
- **Grade and origin**: taste `analyst-inferred`, this implementation audit.

### The Initial floor decides whether there is a packet

- **Priority**: never put a datagram on the wire that a peer is entitled to
  drop, and never spend local state producing one.
- **Constraint**: RFC 9000 §14.1's 1200 bytes is a whole-datagram property, and
  which level spends it is not fixed at construction — a Handshake level with
  CRYPTO data and keys to seal it, or a queued CONNECTION_CLOSE, shares the
  floor with the Initial, and otherwise the Initial pads itself
  (`packet_packer.zig:392-428`, `:989-1006`). What later levels are held for is
  narrower than "an Initial still has data": a Handshake packet discards the
  Initial keys, so it must not overtake an Initial this datagram's budget
  refused, and that refusal is the whole of the hold (`:445-454`).
- **Consumer cost**: a caller whose `out_buf` cannot reach the floor gets
  `0`, not a short packet. Zero means nothing was packed and no packet was
  recorded — the packet number is given back and the frame queues are
  untouched — so the caller keeps its whole flight and retries with a larger
  buffer. A datagram with no Initial in it has no floor and goes out as short as
  its flight needs. Padding toward a target the budget cannot reach would be a
  datagram every peer may drop, carrying the ClientHello that then goes nowhere
  (`packet_packer.zig:548-555`, `:989-1006`). While the floor is shared, the
  room the later level needs is kept back from the Initial so the padding has
  somewhere to land whatever the Initial's own length turns out to be; that is
  what stops a queued CONNECTION_CLOSE from being deferred on every pass. At a
  budget that reaches the floor the Initial goes out and the Handshake level
  follows in the same datagram whether or not Initial data is still queued. One
  pass is not a promise that a level's whole flight drains: each level writes
  what fits the room it was offered and the rest stays queued.
- **Counterchoice**: emitting a best-effort padded Initial wins for a server
  under an anti-amplification budget, or a path with an MTU below the minimum,
  that can never reach 1200 and must keep moving. It is refused because the
  packer cannot tell that datagram from one the network lost.
- **Grade and origin**: the 1200-byte requirement is a safety-fixed protocol
  obligation; which level spends it, and what shares it, is taste
  `analyst-inferred`, this implementation audit.

### An assembly failure carries no usable prefix

- **Priority**: a caller must never be handed bytes it cannot interpret.
- **Constraint**: frames are consumed as they are packed, and recording a
  packet allocates — so a failure can land after the bytes are already in the
  caller's buffer and already out of the queues.
- **Consumer cost**: `packCoalesced` returns no count on `error.OutOfMemory` or
  `error.NoSpaceLeft`; the valid prefix of `out_buf` is unspecified and must be
  discarded, and the connection is finished. It is not a short read, and there
  is no prefix to retry from (`packet_packer.zig:304-313`).
- **Counterchoice**: returning a count and letting the caller continue on the
  frames that were packed wins when losing one flight is cheaper than losing
  the connection. The packer holds no allocator, so those frames have nowhere to
  be handed back to; a count reporting frames the queues will not offer again is
  worse than an error.
- **Grade and origin**: the discard-the-prefix rule is safety-fixed; closing
  rather than continuing is taste `analyst-inferred`, this implementation audit.

Current `Connection.sendAt` routes assembly errors through `failAssembly`, which closes with `INTERNAL_ERROR`.
`Bridge.Conn.drain` maps the refusal to `CoreRefused` and publishes no egress prefix.
This terminal assembly contract differs from path abandonment recovery.
First `PATH_ABANDON` calls `requeueAbandonedPath`.
It retains reliable STREAM bytes and FIN, control retransmission, CRYPTO and pending HANDSHAKE_DONE obligations.
It retires abandoned sent records and recovery deadlines but preserves packet-number history for ordinary ACKs.
Repeated abandonment does not repeat the recovery work.
The native sequence/last-local cancellation model remains standalone and does not drive Node cancellation.
Focused QUIC suite evidence does not establish new mixed-peer proof for these routes.

### A peer-sized header that does not fit costs nothing

- **Priority**: a length the peer chose must not spend local state.
- **Constraint**: the Retry token is the one long-header field whose length a
  peer controls, and the packer's staging budget is fixed — a larger caller
  buffer does not grow it.
- **Consumer cost**: an Initial header past the staging budget returns `0` with
  no packet number taken, no packet recorded and no frame dequeued; the caller
  retries when its buffers are larger (`packet_packer.zig:511-525`). The same
  guard refuses a packet too short to carry RFC 9001 §5.4.2's header-protection
  sample, which is a packet the peer cannot read at all.
- **Counterchoice**: truncating the token, or growing the staging buffer to the
  caller's buffer, wins when a client must answer a hostile token at any cost.
  Both spend a packet number and a queued frame to produce a packet the peer
  cannot use.
- **Grade and origin**: safety-fixed — a peer-chosen length is checked, never
  clamped; the zero-and-keep-the-flight shape is taste `analyst-inferred`, this
  implementation audit.

### Injected entropy that yields no key

- **Priority**: a caller's generator must never turn a construction into a trap.
- **Constraint**: `random` is a `std.Random` argument so one handshake can be
  driven with two generators, which means it is also a value a test may satisfy
  with fixed bytes. `P256.basePoint.mulPublic` rejects a scalar outside the
  group; X25519 clamps, so its draw cannot fail and its second attempt is
  already `unreachable` (`tls13.zig:1886-1900`).
- **Consumer cost**: an unusable P-256 scalar is redrawn once, and a second
  refusal is `error.InternalError` out of `initClientInto` — an error the caller
  already handles. No partially initialized handshake is ever returned, so an
  all-zero generator is a refusal rather than a weak key.
- **Counterchoice**: `unreachable` on the second draw wins when the generator is
  assumed cryptographic, and it costs one branch. It is not available here:
  `random` is a documented parameter, so assuming its output is valid is a
  precondition the core cannot impose on its own caller.
- **Grade and origin**: the refusal itself is safety-fixed; placing it on the
  second draw rather than the first is taste `analyst-inferred`, this
  implementation audit.

### CUBIC is exact while the quotient fits

- **Priority**: keep the window in range without making the curve wrong where
  it can still be right.
- **Constraint**: the curve's products are computed at `i128` and its inputs
  are `u64` and `i64`, so the exact quotient is sometimes wider than `u64` and
  sometimes representable. Clamping before dividing loses the exact value for
  every tick in between (`congestion.zig:630-675`).
- **Consumer cost**: `cubicCurveOffsetBytes` and `saturatingMulDiv` answer
  `maxInt(u64)` above the bound and the exact value below it, and the
  `MAX_WINDOW_PACKETS` cap applied on every acknowledgement is what a
  connection actually keeps (`congestion.zig:413`). An instant before the epoch
  origin, or a `w_max` wider than the window, stays in range but is not promised
  to mean anything: a backwards clock is a caller bug, not a supported mode.
- **Counterchoice**: clamping the numerator first wins when a shorter saturating
  path matters more than the intermediate value. It is not merely less precise
  — it is wrong for every tick whose quotient does fit, which biases the curve
  across its whole usable range.
- **Grade and origin**: the no-trap obligation is safety-fixed; taking the
  division before the clamp is taste `analyst-inferred`, this implementation
  audit.

### A ticket records the protocol whole, at a fixed width

- **Priority**: RFC 8446 §4.2.10 compares the protocol by name, so storage that
  can hold only a prefix cannot record what the next connection is checked
  against.
- **Constraint**: the handshake's selection, a ticket's record and a ticket's
  plaintext are three inline fixed buffers, and RFC 7301's own ceiling is 255.
- **Consumer cost**: 32 bytes of selection per handshake and 32 in every
  `SessionTicket`, 16 bytes more than the 16-byte record it replaced; a
  connection retains two tickets — the one the peer issued and the remembered
  transport parameters (`connection.zig:1339`, `:1343`) — so 32 added bytes per
  connection before the struct's padding decides the rest. A protocol longer
  than 32 bytes cannot be selected at all, and a proposal list that will not
  encode whole fails the first client `step` rather than being trimmed.
- **Counterchoice**: RFC 7301's 255 wins for a caller that must interoperate
  with a peer selecting a longer name. It costs 223 bytes in each of the three
  inline places and a sealed plaintext running to 316, for a protocol this
  project's peers have never selected.
- **Grade and origin**: whole-name comparison is safety-fixed (RFC 8446
  §4.2.10); the 32-byte width is taste `analyst-inferred`, this implementation
  audit.

### Safety-fixed and language-fixed obligations

Malformed peer lengths are refused, not reinterpreted. Client Initial size,
role-specific Version Information, the ticket version authenticated inside the
ticket's own AEAD tag and compared against the resuming connection's initial
version, and original-version 0-RTT follow the cited protocol requirements. A
ticket's protocol is a whole name on both sides of a resumption, and a
version-information list is validated in full rather than over the eight
entries this value retains.
Arithmetic must not trap on decoded peer values. Allocation refusal must not
leak or double-free.
These are safety-fixed choices, not preferences with unsafe counterchoices.

Zig exposes struct fields and shallow-copies owned handles. Comments therefore
state valid local fields, borrowed lifetimes, address stability and exactly-once
cleanup. Const storage cannot truthfully accept a discarded successful write;
the buffer adapter rejects that operation at compilation and preserves const
array views. These are language-fixed obligations.

## Verification

The earlier intermediate tree passed 510 vendored tests and 539 package tests.
Debug and ReleaseSafe builds and test runs exited 0. These are historical
observations, not acceptance counts for a later tree. Red failures were
observed for the wire, TLS, arithmetic, cancellation and constructor repairs;
the integrated stream slice did not supply a failing-before run, so no universal
red-green claim is made.

### Historical native record before RFC 7250

These direct native x86-64 Linux invocations used the pinned 0.16.0 compiler.
The same snapshot appears in the README under *Historical native gate record (before the RFC 7250 patch)*.
The counts describe that acceptance only. They do not describe the current issue #16 integration.
The [2026-10-08 integration snapshot](../../README.md#integration-snapshot-2026-10-08) records current consumer results, the default-gate pass and pending final review.

```text
Build:       Debug and ReleaseSafe each 5/5 build steps — exit 0
Tests:       Debug and ReleaseSafe each 22/22 steps; 1159/1159 tests passed
             package=599 (562 root + 37 integration/gates), vendored core=560
Format:      zig fmt --check . — exit 0
Syntax:      74 changed Zig files + 3 rechecks + 5 final-comment rechecks:
             82 source invocations, all exit 0; build.zig.zon parsed separately, exit 0
Lint:        0 errors; 24 vendored warnings
Static:      zwanzig, 42 non-vendored changed files, 21 rules — No issues found
Fuzz:        15/15 steps succeeded; 7/7 targets, at least 10,000 new runs each
```

No test step reported a leak under the test allocator. The lint warnings are
16 `avoid-as` style findings and 8 `suppressed-errors` findings on bounded or
deliberately best-effort core paths. They are not described as zero lint
findings, and no non-vendored finding was reported.

`-S` is a valid invocation and the file list went over stdin in the shape it
asks for: 74 changed Zig paths, one per line. The retained run that answered
`WriteFailed` handed the same list as one JSON array, so a single line of 2267
bytes overran the tool's fixed 1024-byte line reader; the same command with one
path from that list exits 0 and reports that file's own four findings. Those
runs are trace history for a caller that sent the wrong shape, and they are
lint evidence in neither direction.

The `Runs:` counters the fuzz reports print are cumulative across the retained
corpus and earlier runs. The per-target advance of at least 10 000 new runs is
what this invocation covers, and that is the bound claimed above.

The core's own resumption contract was also exercised in tree, directly, in
both modes: `zig test -lc vendor/quic/src/test_all.zig --test-filter "both ends
make the same 0-RTT keys when the suite is ChaCha"` exits 0 with 2/2 tests. That
test clears `cipher_suite_only` at both ends, so the suite the two ends would
otherwise settle on is AES while the ticket still records ChaCha, and it then
seals a real 0-RTT packet under the client's early keys and opens it with the
server's — header protection first, then the AEAD — so agreement is checked on
the wire instead of asserted on a field. It proves that two ends derive the
same 0-RTT keys; it is not a node feature, and no node here sends early data.

Six live CLI processes — a relay, a receiver and a sender in each of Debug and
ReleaseSafe — carried exactly the 21-byte payload `api-cutover-live-wire`
through the relay and exited 0 after SIGTERM in both modes, each reporting a
closed shutdown and a closed socket. Each receiver's inbox holds that one
datagram and the relay forwarded one. The seeds were 401, 402 and 403: the
CLI's fixed default is a replay aid, not independent entropy for several
processes.

The out-of-tree harness's six consumers passed against the registered package
modules in Debug and ReleaseSafe, 18/18 steps per mode. Contract, TLS, decoder
and cancellation scenarios are joined by decoded core-wire and package-state
checks. The README lists the exact stream, close, ownership, gossip, registry
and loss-result observations. These counts are separate from the native suite.
The original four scenarios observed identically in both modes: a const view
of 1122 bytes; an allocation refusal that retained 62 bytes and drained them
on one retry, the second drain empty; a copied `Join`; a real 1200-byte Initial
that parses as one; a pinned full handshake; ChaCha resumption with v1 early
keys after a v2 negotiation; an authenticated v2 ticket; a cross-version
ticket falling back to a full handshake; v2 early-payload decryption; eight
concurrent cancellation fires collapsing into one producer stop with the
pending timeout answered `Canceled`; a sweep of 50 000 bounded
transport-parameter, frame, DER, ClientHello and ServerHello cases per mode
from seed `0xdec0de` and one fixed clock; and the fixed decoder vectors — 127
DER refusals, each read through both of the routes a caller has, 27
`version_information` refusals, 2 `version_information` accepts, and a
zero-budget CRYPTO pop that returned no frame, moved no cursor and kept its
queued bytes. The refusal switches carry no `else` prong, so they are
exhaustive over these decoders' declared error sets at compile time.

The three attempts that blocked that run failed in the consumer's own source,
not here: an `else` prong left on an error switch this cutover had made
exhaustive, an array repeat written with a runtime length, and
`Connection.connectInto` written as a struct member where the registered
function is `quic.connection.connectInto`. The instrumented Debug run also
needed the fuzz runner's seven `runner_*` symbols, supplied by attaching the
package's own shipped `test/coverage_abi.zig` to each consumer root; that
bridge panics if anything reaches it, and it is not a claim that those symbols
are a production surface. Those receipts are trace history for the fixes above,
not a current blocker.

A declared-source archive passed through `zig fetch` and the native hash-cached
dependency route. All six programs passed again in Debug and ReleaseSafe,
18/18 steps per mode. At archive creation, the native extracted dependency
matched all 74 changed Zig files and 16 required shipped files byte for byte,
including the rules, lint config, both cross-test profiles and contract documents.
Fetching the working directory returned `error.IllegalFileTypeInPackage`.
The archive follows `build.zig.zon.paths` and excludes local environment and
cache artifacts. No user environment file was removed to make the fetch pass.

Coverage against this source is measured, and it is a PC measurement rather
than a branch or path one.

`zig build test quic-test -Doptimize=Debug -Dcoverage=true
-Dcoverage-rt=<zig-cov-rt.o>` exited 0 at 22/22 steps and 1159/1159 tests, and
the vendored core ran again through the out-of-tree consumer harness's
`coverage-core` step, exit 0 at 3/3 steps and 560/560. It is not a step of this
repository's `build.zig`. Forty-one fresh raw counter files from 15 binaries,
including all six instrumented consumers, merged into 15 normalized PC tables.
`zig-cov report --format=json` exited 0 and wrote the report. It spans 79 file
entries: 76 repository files and 3 libc startup assembly files. It reports
20 142 / 36 814 attributed source lines (54.71 %) and
30 502 / 75 108 instrumented blocks (40.61 %). The repository-only line figure
is 20 130 / 36 789 (54.72 %). Function counters are absent.

Line attribution expands executed block addresses through DWARF line tables,
then applies a conservative source-conditional filter. A line hit counts a
retained attribution, not a statement execution. Zero can mean withheld
attribution even when a separate runtime observation proves that the body ran.
This is not branch or path coverage.

Across added or replaced nonblank, non-comment lines in 74 changed Zig files,
1 946 have positive attribution, 2 338 have zero attribution, and 1 827 have
no report row. The pinned compiler's AST places 2 084 zero rows inside test
declarations. The other 254 contain 111 private test-helper rows and
143 production rows. An absent row does not prove that no code was emitted.
Every production zero row has a retained per-function disposition. The README
states the independently observed behaviors, accepted unforced combinations
and the change trigger that reopens them.

Two fixtures were removed rather than re-pinned to something a consumer cannot
reach. A whole fake-CID bookkeeping test that asserted through a private helper
index was deleted, and the old fake ticket's raw ClientHello list and pinned
ALPN defaults went with it; what replaced them are consumer-visible proofs,
including the CID tests that a refused registration stays pending for retry,
and that a refused reset generation preserves its old tokens, and the resumed
handshake above, which clears the forced cipher at both ends instead of pinning
one. A removal here is not a way to make a count: declaration sweeps and
executed test counts provide the evidence.

### Dated history

> **This block is an earlier snapshot, not integrated acceptance for the source
> as it now stands.** It is kept because it is reproducible history, not
> because it describes the current tree. The record above replaces it, and
> with it the consumer and process observations that used to sit under it.

```text
Debug:       Build Summary: 22/22 steps succeeded; 1102/1102 tests passed
ReleaseSafe: Build Summary: 22/22 steps succeeded; 1102/1102 tests passed
             package=577, vendored core=525
Format:      zig fmt --check . — exit 0
Syntax:      72 changed Zig files — exit 0 for each
Lint:        0 errors; 23 vendored advisories
Static:      zwanzig, 41 non-vendored changed files — No issues found
Fuzz:        15/15 steps succeeded; 7/7 targets, at least 10,000 iterations each
```

That run's lint advisories were 16 `avoid-as` style findings and seven
`suppressed-errors` findings on bounded or deliberately best-effort core paths.
They are not described as zero lint findings. No non-vendored finding remained
in that run.

Out-of-tree consumers built and ran in Debug and ReleaseSafe. They observed
retained stream bytes after allocation refusal and one successful retry, copied
Join storage, a real 1200-byte ClientHello flight, eight concurrent cancellation
requests producing one stop, and 50,000 bounded decoder cases per mode. A TLS
consumer completed a pinned full handshake, resumed with ChaCha early-data
decryption while negotiating v1 to v2, received a ticket the issuing connection
had ended on under v2, fell back to a full handshake for a ticket whose issuing
version did not match the resuming connection's initial version, then decrypted
v2 early data. Three live CLI processes delivered exactly
`api-cutover-live-wire` through a relay and exited 0 after SIGTERM in each mode.

That acceptance run removed a duplicate constructor-allocation fixture that
mistook cumulative allocated bytes for live bytes; the complete fail-N sweep
remains. It also removed a source-text test-root wiring check that rejected an
actually discovered test. Architectural I/O, clock and entropy checks remain.

## What is not claimed

No iroh interoperability, no cross-platform result, and no performance number is
claimed here. The coverage measurement above is a PC one; no branch or path
figure is derived from it.

The gate entry point (`devenv shell -- gate`) did not run during that historical acceptance.
Its `anyzig` shim re-downloaded the pinned toolchain and failed to extract it.
That acceptance used direct pinned-compiler invocations.
The [current default-gate pass](../../README.md#integration-snapshot-2026-10-08) is a later receipt, not part of this historical acceptance.
It does not extend that acceptance or erase its environment limitation.

The corrected rerun of the vendored 108-row ABI survey over the address and
fixture fixes was not executed in this native acceptance. The only survey result
recorded against this tree is the earlier failed run over the pre-fix tree, and
no cross-platform coverage is claimed from it.

### Historical final acceptance disposition

Independent re-review closed all 81 entries for that acceptance: 69 defect-bearing findings and 12 verification entries.
The captured native gates, six source/fetched consumers and bounded coverage record replaced the earlier premature completion claim.
This historical disposition does not close the current issue #15 default gate or snapshot cutover.

One standards judgment is accepted: `sendBatch` and `walkRuns` keep five
distinct-typed parameters so the injected socket seam stays explicit and
monomorphises to the direct production call. An options struct would add one
pack/unpack without removing same-typed ambiguity. Ceiling: these two private
helpers; reopen if a new argument introduces role ambiguity or coupled state.

The listed unforced coverage combinations remain limits, not claims of path
coverage. Cross-platform behavior, iroh interoperability, performance and
node-level authenticated 0-RTT remain outside this acceptance record.

## 2026-10-08 static-tool constraints

The current strict gate is not the dated native acceptance record above.
Its checks cover the current source and fail on incomplete analysis.

`ZWANZIG_ARGS=--max-states-per-point 200` raises the per-point state budget from 50.
The CLI option preserves the analyzer's default rule selection.
A config file with only this setting would select all rules instead.
The gate does not suppress `analysis-limit-exceeded`.
A remaining limit diagnostic means that the analyzer did not finish that path.

Four callback declarations retain the required context-first vtable signatures:

- `dns_live.TruncatedDatagram.send` and `receive`: `Datagram.VTable`.
- `node_discovery_wire.VerifiedRecords.start`: `AddressLookup.VTable.resolve`.
- `node_discovery_wire.SignedStream.destroy`: `Stream.VTable.destroy`.

Each declaration has a local `Z023` annotation with its ABI constraint.
No file-wide or rule-wide exception applies.
These annotations correct a parameter-order rule that does not recognize fixed callback signatures.
They do not bypass runtime validation or suppress ownership analysis.

Three `store-violations-engine` annotations cover proved directory-borrow limits.
`gate_measure.rawFiles` immediately defers closing its opened directory.
The pinned `std.Io.Dir.Iterator` borrows that handle and has no owning destructor.
`vendored_file_list` closes each newly opened subdirectory in its own scope.
Its recursive walk borrows the input directory and never closes that input.
The root caller closes its root handle once.
These exceptions do not cover allocation failures or suppress other resource findings.

ZBC exceptions use its native, single-rule, line-scoped directives.
The gate binds every annotated file to a reviewed source hash and the tool hash.
It rejects wildcard controls, file-wide controls and active directives hidden in string literals.
A source or tool change invalidates the record in `.zbc-source-exceptions.json`.
The untouched ZBC executable must finish its full inventory with zero active findings.

At this earlier stage, the residual source registry contained 55 file bindings.
It pins the untouched ZBC tool SHA-256:
`6baad8f048f4cf8150d6691e5b79d78b2d7bf4a804d9ec4f3b8399dcab38e08a`.
These are reviewed native line exceptions, not a tool patch, new exclusion or analyzer-budget change.

- `gate_zbc_policy_schema.parse` has five `slice-loop-reentrant-grow` annotations.
  `exactObject` only reads object count and membership.
  `field` uses read-only `ArrayHashMap.get`.
  `validPath` reads immutable bytes and changes only a local cursor.
  The loop writes a separate allocated `SourceFile` output array.
  None of these operations grows the parsed input array.
- `qnt.decode` has `use-undefined` annotations at the returned aggregate and its `Challenge` field.
  The eight-byte guard and `memcpy` initialize the complete challenge before either use.
- The launch `argv[1..]` exception records the imported helper's exact argument bound.
  It always supplies ten arguments plus the executor, for eleven entries under the same configuration.
  The native annotation covers that missed helper fact, not an unchecked variable-size argument list.

The new `vendored_file_list` Zwanzig prefix annotation covers a borrowed recursive `sub_prefix`.
Recursion neither frees, stores nor transfers the incoming prefix.
Each child frees only its separately allocated `allocPrint` result.
This is separate from the directory-handle borrow annotations above.

`NatTopology.deinit` has a local `ziglint-ignore: Z030` annotation with its ownership reason.
Fallible cleanup preserves keeper PID and network ownership for retry.
The function poisons the owner only after all cleanup succeeds.
It is not an infallible destructor disguised by an ignored error.

The redundant same-name counter-wiring reflection test was removed, not kept to preserve a test quota.
The parent reports format and 100-column checks passed over 374 Zig files.
The first actual default gate used full `GATE_MAX_LINES=100000` and exited 1 after 2199.07 seconds.
Its evidence directory is `/tmp/scratch/ozai-gate-6f4fabec18153fae5af10d5a69c9cb96`.
Format, build, tests, syntax, zlint and Zwanzig passed.
Zwanzig reported no findings or analysis limits at the 200-state budget.
ZBC selected and analyzed all 374 files, with zero failed files and zero findings under 55 source bindings.
The sole failure was ziglint `Z006` on the local `TransportTag` alias in `src/base/ula.zig`.
Explicit typing did not resolve the linters' conflicting naming interpretation.
The unnecessary alias was removed without suppression.
The test iterates the three transports directly and keeps the union-field-count exhaustiveness check.
This changes test structure, not production behavior.
At that stage, focused lint proof and the full gate rerun were pending. Coverage did not run after the lint failure.
Cross-target status was partial: two executed passes, fourteen build-only targets, zero failures.
All sixteen compiled. Fourteen lacked a runner and are not runtime passes.

The subsequent coverage measurement failed with `PartialMapping` after 1135.58 seconds.
Its retained root is `/tmp/scratch/ozai-gate-aaaef134f07f37e08e587a0a1fb9dd2d`.
Debug completed. ReleaseSafe failed at row 97, `ReleaseSafe/map-1-286.stdout`.
The unresolved location was `ozai-coverage-policy-test:?` at adjusted PC `0x10bc05b`, not `??:0`.
Parent DWARF lookup found no matching range or line entry.
Bounded disassembly identified NOP padding after `std.Io.Writer.alignBuffer`'s integer-overflow call and before the next function at `0x10bc060`.
This does not establish project-source ownership for the PC.
The Debug report remains partial, not final both-mode coverage acceptance.

`gate_raw` and `gate_raw_mapping` now validate the current binary before recognizing its exact basename plus `:?` as source-unowned.
Generic relative paths, wrong basenames, source paths and numeric line rows still fail.
Both modes retain source-unowned counts and reasons.
No stdout rewrite, PC subtraction, invented source file or tool patch substitutes for that evidence.
The eleven fixture call sites use explicit typed options for the binary context.
Fresh focused gate-policy tests passed 5/5 steps and 82/82 tests in Debug and ReleaseSafe.
The split was 17 coverage-policy tests and 65 project-gate tests.
The next measurement completed both raw symbolization maps, then exited 1 with `PartialMapping` after 1569.22 seconds.
Its retained root is `/tmp/scratch/ozai-gate-035bc5969bda35a93fe4a425f4530060`.
`gate_report.zig` rejected report block totals/hits that differed from audited raw counts.
Both reports and raw maps remain retained. No validated measurement manifest exists for that run.
Independent full-PC comparison and unchanged raw-count probes proved the resolver mismatch.
They compared 286,503 unique PCs.
ReleaseSafe raw source-owned block counts were 96,666 total and 47,315 hit.
The old reporter returned 96,654 total and 47,315 hit.
Its `std.debug.Info` resolver falsely assigned numeric locations to all 10,270 project source-line-zero PCs, including 3,776 hits.
Of those, 10,258 stayed falsely project-attributed and twelve became falsely external.
All twelve external PCs were unhit. Exact-address DWARF checks proved the ownership errors.
The old reporter's inferred numeric-line hits and cold classification cannot be the current accepted ledger.
These diagnostic counts do not establish final coverage.
Probe evidence is retained at:
- `/tmp/scratch/ozai-resolver-probe-V8YNDlZl/analysis.json`
- `/tmp/scratch/ozai-resolver-probe-V8YNDlZl/ownership-proof.json`
- `/tmp/scratch/ozai-raw-count-probe-20261008-r1/result.json`

The next full default gate exited 1 after 2856.51 seconds.
ZBC analyzed all 374 files with zero findings.
`gate_measure.emitReport` then failed to spawn external `zig-cov` with `FileNotFound`.
The implemented clean cutover makes audited GNU `addr2line` source/line projection authoritative.
Runtime ZCOV instrumentation remains unchanged.
Consumers emit version-1 `ozai-zcov-raw` report JSON and replay full ordered source rows.
Canonical source paths are interned.
Unique binary PCs merge their hit states before source-line grouping.
Exact-row replay rejects same-total forgeries.
Pure projection APIs have explicit error sets and allocation-failure tests.
All project `:?` blocks remain unmapped.
The external reporter invocation and CLI dependency are removed.
No neighbor-line inference, PC subtraction or tool patch is part of the implementation.
Fresh focused Debug and ReleaseSafe policy suites passed 5/5 steps and 94/94 tests.
The split was 17 coverage-policy and 77 project-gate tests.
The source registry retains 55 refreshed bindings.
At that stage, the frozen-source default gate selected 375 non-vendored files.
The retained-earlier-raw-input smoke exited 0 after 579.70 seconds.
Its evidence root is `/tmp/scratch/ozai-raw-projection-smoke-20261008-r1`.
Each mode replayed all 26 raw files and 13 artifacts with hashes, PCs and mappings.
Debug source-owned blocks were 109823/48567 total/hit.
Its project-unmapped blocks were 41625/10349, source-unowned blocks 0/0 and actual numbered lines 17634/13320.
ReleaseSafe source-owned blocks were 96666/47315, preserving the twelve formerly lost PCs.
Its project-unmapped blocks were 10270/3776, source-unowned blocks 20/17 and actual numbered lines 21569/14776.
Both reports contained zero numbered-line-zero entries.
The smoke used only positive GNU source-line rows observed for instrumented PCs.
That subset is not the full required line universe and cannot be accepted as ledger scope.
Independent enumeration proved the complete generated DWARF numeric-row universe: 61,297 Debug and 53,050 ReleaseSafe rows.
These denominators are not physical source lines, comments or source-row expansion.
Direct-PC-only reports omitted 43,663 Debug and 31,481 ReleaseSafe rows.
Positive GNU-PC hits remain 13,320 and 14,776.
With all other numeric rows cold, retained-input cold counts are 47,977 and 38,274.
The block, project-unmapped and source-unowned counts remain unchanged.
`gate_dwarf_universe`, `gate_dwarf_rows`, `Builder.declare` and the raw collector implement full-universe enumeration.
They load DWARF through explicit `Io` and enumerate `Dwarf.populateSrcLocCache`.
They do not use `resolveAddresses` or range inference for hit attribution.
The earlier focused Debug run passed 106/107 tests, including 17 coverage-policy and 89/90 project-gate tests.
One fixture used `:0` where strict GNU unknown-line syntax requires `:?`.
ReleaseSafe did not run after that Debug failure.
The corrected fresh Debug and ReleaseSafe runs each passed 5/5 steps and 107/107 tests.
The split was 17 coverage-policy and 90 project-gate tests.
The earlier native host invocation could not load the executable and exited 127.
The earlier full sandbox ZBC run analyzed all 377 selected files with zero failed files and two borrowed-metadata-helper findings.
Two exact next-line controls now state the helpers' borrowed metadata and pure scalar behavior.
Fresh focused native ZBC selected and analyzed four files with zero failed files and zero findings.
It used the unchanged original tool SHA. No helper-file exemption applies.
The source registry now contains 56 file bindings.
This focused check does not establish green full-377-file native analysis.

`GateFiles` raises the coverage-document bound to 64 MiB to retain the complete line universe.
The retained inputs contain 47,977 Debug and 38,274 ReleaseSafe cold rows, or 86,251 total.
Shortest pretty-serialized identities with actual mode names already require 16,876,111 bytes.
That exceeds the former 16,777,216-byte bound before real paths and headers.
The larger bound is not a reason to omit rows or weaken validation.
Native compiled-binary hashing remains streaming.

The current full-universe constructor passed the retained-earlier-input smoke with exit 0 after 598.08 seconds.
Its root is `/tmp/scratch/ozai-full-universe-smoke-20261008-r1`.
Both modes replayed all 26 raw files and 13 binary hashes.
Debug retained the full 61,297 numeric rows with 13,320 GNU-PC hits.
Its source-owned blocks were 109823/48567, project-unmapped 41625/10349 and source-unowned 0/0.
ReleaseSafe retained the full 53,050 numeric rows with 14,776 GNU-PC hits.
Its source-owned blocks were 96666/47315, project-unmapped 10270/3776 and source-unowned 20/17.
Both reports emitted zero numbered-line-zero entries.
The twelve formerly lost ReleaseSafe PCs remain counted.
All other numeric rows remain cold: 47,977 Debug and 38,274 ReleaseSafe.
This proves full-universe restoration on retained inputs, not fresh current-tree coverage.

At that retained-input smoke stage, fresh measurement, full default-gate validation and final review were still pending.

The preceding default gate ended with exit 143 after 1302.73 seconds, logging one native ZBC failed file.
No measurement or pass result came from that run.
The parent's `pidfd_open` attempt returned `EINVAL` before any signal.
Parent cancellation is therefore not claimed.
The final orphan audit found all original job PIDs absent and zero exact owned job markers.
It sent no signals and left an unrelated reused PID untouched.
Evidence is `/tmp/scratch/bg253-reap-summary-1791435495498173729.json`.
The next full default gate exited 1 after 2390.64 seconds, before coverage measurement.
Its root is `/tmp/scratch/ozai-gate-17e24e9ca1953a994f17015198f0999f`.
Native ZBC selected and analyzed all 377 files with zero failed files and zero findings under 56 bindings.
Format, build, tests, syntax and zlint passed, but configured external checks exited 1.
Ziglint reported only two `Z030` findings:
- `gate_projection.Paths.deinit`, recorded line 80.
- `gate_projection.Builder.deinit`, recorded line 190.
The analyzer did not recognize their aliased `.empty` resets.
The repair clarifies terminal-state and explicit-reset contracts without suppression.
Zwanzig reported six asserted optional unwraps in `gate_raw` fixtures at recorded lines 528, 532, 534, 561, 585 and 589.
The fixture repair makes missing expected keys return `TestUnexpectedResult` explicitly.
The source repairs now make both deinits terminal (`undefined`), with LSP caller contracts checked.
A regression verifies the deep-owned report remains valid after both temporary containers deinitialize.
Fresh Debug and ReleaseSafe policy suites each passed 5/5 steps and 107/107 tests.
Native ZBC analyzed both changed files with zero failures and zero findings.
Ziglint passed both changed files.
Full-scope Zwanzig analyzed all 377 files under 21 rules and reported no issues, with exit 0.
A smaller two-file Zwanzig run omitted real callers and emitted unused-function audit noise, not a product finding.
No suppression, tool flags, rules or tool patch changed to bypass the original findings.
The captured-source `measure` run exited 0 after 1303.14 seconds.
Its root is `/tmp/scratch/ozai-gate-8d817e339b72296a468bff22f0a58847`.
Source digest is `f871adbdc33d7b21a75bcafc22a498ab40030cfd5bdb33503428b10fab1e31ae`.
Zig 0.16.0 executable SHA-256 is `2317bbb91798556d9d0f38aabdac23db83f0979b25f767259ae474546724087c`.
The complete manifest is 19,755,810 bytes, with 549 sources, 80 artifacts and 87,120 cold tuples across 389 paths.
Exact measured scope is `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy`.
Opt-in Rust interop is outside this scope. Its earlier 48/48-step, 3068-test receipt remains separate history.
Both modes built with exit 0 over 6/6 steps.
Uninstrumented scope tests passed 31/31 steps and 3052/3052 tests in each mode.
Instrumented coverage tests passed 41/41 steps and 3052/3052 tests in each mode.
Debug numeric DWARF rows were 61893/13470 total/hit, project blocks 110282/48825, project-unmapped 41851/10438 and source-unowned 0/0.
ReleaseSafe numeric rows were 53593/14958, project blocks 97085/47541, project-unmapped 10350/3797 and source-unowned 20/17.
All 389 captured paths and all 87,120 exact unique cold tuples have source-grounded dispositions.
The tuple split is 87,058 numeric rows and 62 absence rows.
Actions are `accept` 1,930, `test` 69,491 and `refactor` 15,699.
Test rows identify regressions or coverage obligations, not executed hit credit.
Refactor rows state required execution work, not completed work.
Accepted rows carry guard, metadata or attribution reasons.
The parent embedded the captured machine fence and section 9 in `docs/COVERAGE-LEDGER.md`.
The captured ledger was 26,821,766 bytes, with a 26,788,210-byte fence.
Actual CLI validation against the captured `8d817e339b72296a468bff22f0a58847` measurement exited 0 with no output after 729.33 seconds.
It replayed every source, compiled-binary, raw and report SHA identity, exact-PC projection and all 87,120 cold-tuple dispositions.
This completed issue #11's measurement and record acceptance for the captured `f871adbd…` source.
Cross status was two executed passes, fourteen build-only targets and zero failures.
All sixteen compiled. Fourteen lacked runtime runners, so the accepted status is partial.
The complete native-ZBC stage and captured measurement are proved, but no full-gate pass is claimed.
The actual bg267 default `devenv shell -- gate` run exited 1 after 3681.64 seconds with `UnmatchedDisposition`.
Its root is `/tmp/scratch/ozai-gate-015e738ce1e1ba35ff91b4ff6a669f90`.
Native ZBC analyzed all 377 files with zero findings under 56 bindings.
All configured format, build, test, syntax, ziglint, zlint and Zwanzig checks passed.
Cross status remained two executed passes, fourteen build-only and zero failures.
Source digest remained `f871adbdc33d7b21a75bcafc22a498ab40030cfd5bdb33503428b10fab1e31ae`.
Numeric universes/hits stayed 61893/13470 Debug and 53593/14958 ReleaseSafe.
The cold-tuple count stayed 87,120, but two ReleaseSafe identities swapped.
`test/two_process_child.zig:228` changed cold to hit. `test/two_process_roster.zig:144` changed hit to cold.
Debug project hits changed 48825 to 48815 and project-unmapped hits 10438 to 10435.
ReleaseSafe project hits changed 47541 to 47554 while project-unmapped hits remained 3797.
The mismatch is fresh live-I/O coverage variation, not stale source or artifacts.
The tests use real pipes, polling and child-process I/O with fixed node seeds.
[INFERENCE] Process scheduling explains the variation. The retained evidence does not identify the exact trigger.
The first measured snapshot and its exact replay remain valid for their recorded inputs.
Issue #15 permits a dated, source-bound ledger with on-demand regeneration.
The chosen default uses full strict retained replay after current checks, not a new instrumented capture.
No retry-to-green or relaxed validation is accepted.
The earlier schema-2 capture, machine fence, replay and default-gate receipts are historical after the current source repairs.
They remain evidence for their captured source, not current acceptance.
Fresh schema-3 capture, exact all-cold dispositions, strict replay, the full default gate and independent review remain pending.
No new all-source counts or wire-interoperability proof are claimed.
The [integration snapshot](../../README.md#integration-snapshot-2026-10-08) records Main's observed current normal-root and focused results.
Vendored QUIC passed 671/671 and gate policy passed 116/116 in each mode.
The pinned Rust peer passed 30/30 tests and its release build.
Current normal-root `bg317` passed 28/28 steps and 2538/2538 tests in Debug and ReleaseSafe.
Each mode includes library 1317/1317, portable 1041/1041 and child helpers 35/35.
The public regressions cover current ownership, refusal, gossip and reusable Resolver cancellation contracts.
Fresh schema-3 capture, full default gate and live smokes have not run.

## Schema-3 retained snapshot contract

Default always runs configured full checks before it validates retained coverage.
It runs current uninstrumented builds/tests in both Debug and ReleaseSafe.
Its exact test scope is `test`, `test-portable`, `quic-test`, `invariants` and `test-gate-policy`.
Configured format, syntax, ziglint, zlint, native ZBC, Zwanzig and cross-target checks remain required.
Missing cross-target runners retain build-only status, not runtime acceptance.
Then default fully replays the required current-source retained measurement.
It does not start a fresh instrumented capture.

The legacy `refdecls` and `compile-all` names describe declaration checks, not separate driver sections.
`test` runs the `src/root.zig` sweep. `test-portable` runs the socket-free `src/portable_test.zig` sweeps.
`quic-test` runs `vendor/quic/src/test_all.zig`, including core sweeps and explicit internal/test-only imports.
`test-gate-policy` runs the `scripts/project_gate.zig` gate-module sweeps.
These executed roots meet the Compile-all convention without a new gate abstraction.
`invariants` adds vendored source-contract checks. It does not replace core runtime tests or prove production execution.
The [named issue #2 admissions](../../TODO.md#issue-2-named-standalone-admissions) state every remaining module-only subsystem boundary.
They cover blob variants, ticket use/lifecycle/loss logging, interface discovery, topic tables, statistics, ECN policy, budgets and broader relay authorization.
They are explicitly permitted scope admissions, not completed production features or coverage credit.

`measure.runSafetyModes(runner, zig)` shares the actual first two `buildMode` stages.
`record.validateRetained(gpa, io, env)` reads the exact required machine reference and calls the common full validator.
Allocators and `Io` remain explicit. Temporary owners release their data.
`measure` also captures fresh instrumented coverage in both modes.
The machine ledger and Measurement use schema 3.
The ledger requires one `ozai-coverage-v2` fence and `measurement: {path, sha256}`.
The path must be nonempty. The captured file SHA-256 must have 64 hexadecimal characters.
Replay checks the file hash before it trusts the manifest.
`validate <path>` requires the exact referenced path and SHA-256 and performs the same full replay.

Replay binds current source, compiler, scope and both modes.
It checks all source/artifact/raw/report hashes, raw completeness, ordered report rows, exact-PC projection and exact counters.
It preserves the full positive DWARF numeric-row universe and direct-PC hit attribution.
Capture binds the original absolute runtime object path and SHA-256.
Replay rehashes that object independently of fresh `OZAI_COVERAGE_RT`.
The source inventory represents absent roots and test sources.
Cold DWARF rows can outnumber mapped PCs without report corruption.
Stored `Measurement.cold_items` must match replay-generated tuples by field content.
Those identity fields are `mode`, `path`, `source_sha256`, `line` and `unit`.
Missing, duplicate, stale or extra tuples fail. Changed metadata also fails.
Ledger decisions must match the exact cold tuples, without covered or stale extra decisions.
Project-unmapped and source-unowned totals and hits must match exactly.
Coverage documents remain bounded to 64 MiB.

Missing or changed references, manifests, artifacts, raw inputs, reports or decisions fail closed.
Source, compiler or scope drift fails until a fresh capture and exact fence replace the snapshot.
There is no advisory mode, opt-out, skipped check, old-schema fallback, tolerance or retry-to-green.
Rust interop, relay roles and controlled-NAT evidence retain their separate scopes and admissions.
They do not replace coverage replay.
Direct capture/replay commands use both explicit Zig cache flags and the README's approved host-scratch exports.
`measure` requires `OZAI_COVERAGE_RT`. Default retained replay does not require a fresh instrumentation runtime.
The [README workflow](../../README.md#strict-coverage-snapshot-workflow) gives the concrete default, capture and replay commands.
